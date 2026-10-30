"""Local backup management for remote files before write operations.

Creates dated backups, tracks SHA-256 hashes, and maintains a manifest log.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from hostinger_cli.security import calculate_sha256


class BackupManager:
    """Manages local timestamped backups and integrity manifest."""

    def __init__(self, base_backup_dir: Path) -> None:
        self.base_dir = base_backup_dir.resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file = self.base_dir / "backups_manifest.jsonl"

    def _sanitize_path_for_filename(self, remote_path: str) -> str:
        """Convert a remote path into a safe filename representation."""
        clean = remote_path.strip().lstrip("/").replace("/", "_").replace("\\", "_")
        return clean or "root"

    def create_backup(
        self,
        remote_path: str,
        content: bytes,
        domain: str,
        remote_mtime: Optional[int] = None,
    ) -> Path:
        """Save a dated backup of the remote file content.

        Args:
            remote_path: Canonical remote path on the server.
            content: Raw file content bytes.
            domain: Target domain name.
            remote_mtime: Optional remote modification timestamp.

        Returns:
            Path to the newly saved backup file.
        """
        now = datetime.now()
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        safe_name = self._sanitize_path_for_filename(remote_path)

        domain_dir = self.base_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)

        backup_filename = f"{timestamp_str}_{safe_name}.bak"
        backup_path = domain_dir / backup_filename

        # Write backup file
        with open(backup_path, "wb") as f:
            f.write(content)

        file_hash = calculate_sha256(content)

        # Log into manifest
        record: Dict[str, Any] = {
            "timestamp": now.isoformat(),
            "domain": domain,
            "remote_path": remote_path,
            "backup_file": str(backup_path.relative_to(self.base_dir)),
            "sha256": file_hash,
            "size_bytes": len(content),
            "remote_mtime": remote_mtime,
        }

        with open(self.manifest_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        return backup_path

    def list_backups(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all backups recorded in manifest, optionally filtered by domain."""
        if not self.manifest_file.is_file():
            return []

        backups: List[Dict[str, Any]] = []
        with open(self.manifest_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if domain is None or data.get("domain") == domain:
                        backups.append(data)
                except json.JSONDecodeError:
                    continue

        return backups
