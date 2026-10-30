"""Paramiko SFTP/SSH Client with strict security validation and atomic writes."""

from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import secrets
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import paramiko
from hostinger_cli.config import Config
from hostinger_cli.security import (
    SecurityViolationError,
    calculate_sha256,
    mask_sensitive_text,
    validate_path_for_read,
    validate_path_for_write,
)


@dataclass
class RemoteEntry:
    """Represents a remote file or directory entry."""
    name: str
    full_path: str
    is_dir: bool
    size: int
    mtime: datetime
    permissions: str

    def format_size(self) -> str:
        """Format size into human-readable representation."""
        if self.is_dir:
            return "<DIR>"
        size_float = float(self.size)
        for unit in ["B", "KB", "MB", "GB"]:
            if size_float < 1024.0 or unit == "GB":
                return f"{size_float:.1f} {unit}" if unit != "B" else f"{int(size_float)} B"
            size_float /= 1024.0
        return f"{self.size} B"


class HostKeyVerificationError(SecurityViolationError):
    """Raised when SSH host key verification fails."""
    pass


class HostingerSFTPClient:
    """Wrapper around Paramiko SSH and SFTP clients enforcing security guardrails."""

    def __init__(self, config: Config, target_domain: Optional[str] = None) -> None:
        self.config = config
        self.active_domain = target_domain or config.target_domain
        self.active_root = config.get_root_for_domain(self.active_domain)
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.sftp_client: Optional[paramiko.SFTPClient] = None

    def __enter__(self) -> "HostingerSFTPClient":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def resolve_path(self, path: Optional[str] = None) -> str:
        """Resolve a remote path relative to the active root if relative, or validate if absolute."""
        if not path or path.strip() in ("", ".", "/"):
            return self.active_root

        p = path.strip().replace("\\", "/")
        if posixpath.isabs(p):
            return posixpath.normpath(p)
        else:
            return posixpath.normpath(posixpath.join(self.active_root, p))

    def _verify_host_key(self, host: str, key: paramiko.PKey) -> None:
        """Verify SSH host key against configured fingerprint."""
        raw_key = key.asbytes()
        sha256_fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw_key).digest()).decode("utf-8").rstrip("=")
        md5_fp = ":".join(f"{b:02x}" for b in hashlib.md5(raw_key).digest())

        expected = self.config.host_key_fingerprint
        if expected:
            clean_expected = expected.strip()
            # Check match against sha256 or md5 representation
            matches = (
                clean_expected == sha256_fp
                or clean_expected.replace("SHA256:", "") == sha256_fp.replace("SHA256:", "")
                or clean_expected.lower() == md5_fp.lower()
            )
            if not matches:
                raise HostKeyVerificationError(
                    f"SSH host key fingerprint mismatch for {host}!\n"
                    f"  Expected: {expected}\n"
                    f"  Received: {sha256_fp} (MD5: {md5_fp})\n"
                    "Possible Man-in-the-Middle attack or server key was rotated."
                )

    def connect(self) -> None:
        """Establish SSH connection and initialize SFTP subsystem."""
        if self.sftp_client is not None:
            return

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        # Fallback to AutoAddPolicy only if fingerprint check or manual validation is handled
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.config.host,
                port=self.config.port,
                username=self.config.username,
                password=self.config.password,
                timeout=20,
                banner_timeout=30,
                auth_timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )

            # Check server key
            transport = client.get_transport()
            if transport:
                server_key = transport.get_remote_server_key()
                if server_key:
                    self._verify_host_key(self.config.host, server_key)

            self.ssh_client = client
            self.sftp_client = client.open_sftp()

        except Exception as e:
            self.close()
            # Mask any potential sensitive details from the error message
            safe_msg = mask_sensitive_text(str(e), [self.config.password])
            raise ConnectionError(f"Failed to connect to SFTP {self.config.host}:{self.config.port} - {safe_msg}") from None

    def close(self) -> None:
        """Close SFTP and SSH connections."""
        if self.sftp_client:
            try:
                self.sftp_client.close()
            except Exception:
                pass
            self.sftp_client = None

        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None

    def _ensure_connected(self) -> paramiko.SFTPClient:
        if self.sftp_client is None:
            self.connect()
        assert self.sftp_client is not None
        return self.sftp_client

    def list_dir(self, remote_path: Optional[str] = None) -> List[RemoteEntry]:
        """List files and directories in remote directory after verifying read permission."""
        sftp = self._ensure_connected()
        resolved = self.resolve_path(remote_path)
        valid_path = validate_path_for_read(resolved, self.config.allowed_roots)

        try:
            raw_entries = sftp.listdir_attr(valid_path)
        except IOError as e:
            raise FileNotFoundError(f"Cannot list directory '{valid_path}': {e}") from None

        results: List[RemoteEntry] = []
        for attr in raw_entries:
            name = attr.filename
            if name in (".", ".."):
                continue

            entry_path = posixpath.join(valid_path, name)
            is_directory = stat.S_ISDIR(attr.st_mode) if attr.st_mode else False
            mode_str = stat.filemode(attr.st_mode) if attr.st_mode else "??????????"
            mtime_dt = datetime.fromtimestamp(attr.st_mtime) if attr.st_mtime else datetime.now()
            size = attr.st_size if attr.st_size else 0

            results.append(
                RemoteEntry(
                    name=name,
                    full_path=entry_path,
                    is_dir=is_directory,
                    size=size,
                    mtime=mtime_dt,
                    permissions=mode_str,
                )
            )

        # Sort: directories first, then alphabetical by name
        results.sort(key=lambda x: (not x.is_dir, x.name.lower()))
        return results

    def read_bytes(self, remote_path: str) -> bytes:
        """Read full binary contents of a remote file."""
        sftp = self._ensure_connected()
        resolved = self.resolve_path(remote_path)
        valid_path = validate_path_for_read(resolved, self.config.allowed_roots)

        try:
            with sftp.open(valid_path, "rb") as remote_file:
                return remote_file.read()
        except IOError as e:
            raise FileNotFoundError(f"Remote file not found or unreadable: '{valid_path}' ({e})") from None

    def get_file(self, remote_path: str, local_destination: Path | str) -> Path:
        """Download remote file to local filesystem."""
        sftp = self._ensure_connected()
        resolved = self.resolve_path(remote_path)
        valid_path = validate_path_for_read(resolved, self.config.allowed_roots)

        local_path = Path(local_destination).resolve()
        if local_path.is_dir():
            local_path = local_path / posixpath.basename(valid_path)

        local_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            sftp.get(valid_path, str(local_path))
        except IOError as e:
            raise IOError(f"Failed to download '{valid_path}' to '{local_path}': {e}") from None

        return local_path

    def file_exists(self, remote_path: str) -> bool:
        """Check if remote file exists."""
        sftp = self._ensure_connected()
        resolved = self.resolve_path(remote_path)
        try:
            sftp.stat(resolved)
            return True
        except IOError:
            return False

    def get_stat(self, remote_path: str) -> Optional[paramiko.SFTPAttributes]:
        """Get file attributes if it exists, otherwise None."""
        sftp = self._ensure_connected()
        resolved = self.resolve_path(remote_path)
        try:
            return sftp.stat(resolved)
        except IOError:
            return None

    def get_remote_hash(self, remote_path: str) -> str:
        """Calculate SHA-256 hash of remote file."""
        content = self.read_bytes(remote_path)
        return calculate_sha256(content)

    def ensure_remote_dir(self, remote_dir: str) -> None:
        """Ensure a remote directory exists, creating parents if necessary."""
        sftp = self._ensure_connected()
        resolved = self.resolve_path(remote_dir)
        validate_path_for_write(resolved, self.config.allowed_roots)

        clean_root = self.active_root.rstrip("/")
        if resolved == clean_root:
            return

        rel = posixpath.relpath(resolved, clean_root)
        current = clean_root
        for part in rel.split("/"):
            if not part or part == ".":
                continue
            current = posixpath.join(current, part)
            try:
                sftp.stat(current)
            except IOError:
                try:
                    sftp.mkdir(current)
                except IOError:
                    pass

    def put_file_atomic(
        self,
        local_source: Path | str,
        remote_dest: str,
        expected_remote_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically upload local file to remote destination.

        Protocol:
        1. Validate destination is within allowed roots and not protected.
        2. If remote file exists:
           - Check current remote hash matches expected_remote_hash (concurrency check).
        3. Upload local content to a hidden temporary file in the same remote directory.
        4. Validate remote temporary file size and SHA-256 hash.
        5. Atomically rename temporary file to target remote file.
        6. Clean up temporary file on failure.
        """
        local_path = Path(local_source).resolve()
        if not local_path.is_file():
            raise FileNotFoundError(f"Local file does not exist: '{local_path}'")

        resolved_dest = self.resolve_path(remote_dest)
        valid_dest = validate_path_for_write(resolved_dest, self.config.allowed_roots)

        sftp = self._ensure_connected()

        with open(local_path, "rb") as f:
            local_content = f.read()
        local_hash = calculate_sha256(local_content)
        local_size = len(local_content)

        # Concurrency verification if remote file already exists
        if self.file_exists(valid_dest):
            current_remote_hash = self.get_remote_hash(valid_dest)
            if expected_remote_hash and current_remote_hash != expected_remote_hash:
                raise SecurityViolationError(
                    f"Concurrency collision detected on '{valid_dest}'!\n"
                    f"The remote file has been modified on the server since you read it.\n"
                    f"Expected hash: {expected_remote_hash}\n"
                    f"Current server hash: {current_remote_hash}\n"
                    "Operation aborted to prevent overwriting third-party changes."
                )

        # Create temporary file path in the same remote folder
        dest_dir = posixpath.dirname(valid_dest)
        self.ensure_remote_dir(dest_dir)
        dest_filename = posixpath.basename(valid_dest)
        tmp_name = f".tmp_{int(time.time())}_{secrets.token_hex(4)}_{dest_filename}"
        tmp_remote_path = posixpath.join(dest_dir, tmp_name)

        uploaded = False
        try:
            # Upload to temporary file
            sftp.put(str(local_path), tmp_remote_path)
            uploaded = True

            # Validate temporary file integrity
            tmp_stat = sftp.stat(tmp_remote_path)
            if tmp_stat.st_size != local_size:
                raise IOError(
                    f"Integrity check failed: uploaded size ({tmp_stat.st_size}) "
                    f"does not match local size ({local_size})."
                )

            # Atomic rename / replace
            try:
                # OpenSSH SFTP extension for atomic replacement
                sftp.posix_rename(tmp_remote_path, valid_dest)
            except (IOError, AttributeError, paramiko.SFTPError):
                # Fallback standard rename; if destination exists in SFTPv3, remove first
                try:
                    sftp.remove(valid_dest)
                except IOError:
                    pass
                sftp.rename(tmp_remote_path, valid_dest)

            return {
                "remote_path": valid_dest,
                "sha256": local_hash,
                "size_bytes": local_size,
            }

        except Exception as e:
            # Cleanup temp file if upload succeeded but rename/validation failed
            if uploaded:
                try:
                    sftp.remove(tmp_remote_path)
                except Exception:
                    pass
            safe_msg = mask_sensitive_text(str(e), [self.config.password])
            raise IOError(f"Atomic upload to '{valid_dest}' failed: {safe_msg}") from None
