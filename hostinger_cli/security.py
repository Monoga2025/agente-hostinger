"""Security validations, path guardrails, and cryptographic hashing.

Enforces:
1. Strict boundary containment within HOSTINGER_ALLOWED_ROOTS.
2. Immutable protected files (.env, wp-config.php, certificates, keys, backups).
3. SHA-256 integrity verification.
4. Safe logging without credential leakage.
"""

from __future__ import annotations

import fnmatch
import hashlib
import posixpath
import re
from pathlib import Path
from typing import List, Optional, Tuple


class SecurityViolationError(Exception):
    """Raised when an operation violates security boundaries or protected file rules."""
    pass


# Strict list of file patterns that CANNOT be modified, overwritten, or created
PROTECTED_WRITE_PATTERNS = [
    # Environment & configuration secrets
    ".env",
    ".env.*",
    "*.env",
    "wp-config.php",
    "wp-config-sample.php",
    "configuration.php",  # Joomla
    "settings.php",       # Drupal

    # Private keys & certificates
    "*.pem",
    "*.key",
    "*.crt",
    "*.cer",
    "*.pfx",
    "*.p12",
    "*.der",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "authorized_keys",
    "known_hosts",

    # Backups & archives
    "*.bak",
    "*.backup",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.zip",
    "*.gz",
    "*.sql",
    "*.sql.gz",
    "*.7z",
    "*.rar",
]

# Path components that indicate a backup or system directory that should not be overwritten
PROTECTED_DIRECTORY_NAMES = {
    "backups",
    "backup",
    ".ssh",
    ".git",
}


def normalize_remote_path(path: str, base_root: Optional[str] = None) -> str:
    """Normalize a remote path to a canonical POSIX path.

    If path is relative and base_root is given, it is resolved relative to base_root.
    Protects against path traversal (../ tricks).
    """
    clean = path.strip().replace("\\", "/")
    if not clean:
        clean = "."

    if posixpath.isabs(clean):
        resolved = posixpath.normpath(clean)
    elif base_root:
        base_clean = base_root.strip().replace("\\", "/")
        if not base_clean.startswith("/"):
            base_clean = "/" + base_clean
        resolved = posixpath.normpath(posixpath.join(base_clean, clean))
    else:
        resolved = posixpath.normpath(clean)
        if not resolved.startswith("/"):
            resolved = "/" + resolved

    return resolved


def is_path_allowed(remote_path: str, allowed_roots: List[str]) -> bool:
    """Check if the normalized remote path is strictly inside one of the allowed roots."""
    if not allowed_roots:
        return False

    norm = normalize_remote_path(remote_path)
    for root in allowed_roots:
        norm_root = normalize_remote_path(root)
        if norm == norm_root or norm.startswith(norm_root + "/"):
            return True

    return False


def is_protected_file(remote_path: str) -> Tuple[bool, Optional[str]]:
    """Check if a remote file matches protected patterns (e.g. wp-config, .env, keys, backups).

    Returns:
        Tuple[bool, Optional[str]]: (is_protected, reason)
    """
    filename = posixpath.basename(remote_path).lower()
    path_lower = remote_path.lower()
    parts = [p.lower() for p in remote_path.split("/") if p]

    # Check protected directory names
    for part in parts:
        if part in PROTECTED_DIRECTORY_NAMES:
            return True, f"Modifying files in directory '{part}' is strictly forbidden for security."

    # Check exact match and glob patterns
    for pattern in PROTECTED_WRITE_PATTERNS:
        if fnmatch.fnmatch(filename, pattern.lower()):
            return True, f"File matches protected pattern '{pattern}'."

    # Additional regex checks for hidden secrets
    if re.search(r"(\.env|\.key|\.pem|\.pfx)$", filename, re.IGNORECASE):
        return True, "File appears to contain cryptographic keys or environment secrets."

    return False, None


def validate_path_for_read(remote_path: str, allowed_roots: List[str]) -> str:
    """Validate that path is permitted for read operations (list, get, diff).

    Returns:
        The normalized canonical path.

    Raises:
        SecurityViolationError: If path is outside allowed roots.
    """
    norm = normalize_remote_path(remote_path)
    if not is_path_allowed(norm, allowed_roots):
        raise SecurityViolationError(
            f"Access denied: Path '{norm}' is outside the allowed roots:\n"
            + "\n".join(f"  - {r}" for r in allowed_roots)
        )
    return norm


def validate_path_for_write(remote_path: str, allowed_roots: List[str]) -> str:
    """Validate that path is permitted for write operations (put, edit, rename, delete).

    Returns:
        The normalized canonical path.

    Raises:
        SecurityViolationError: If path is outside allowed roots or is a protected file.
    """
    norm = validate_path_for_read(remote_path, allowed_roots)

    is_prot, reason = is_protected_file(norm)
    if is_prot:
        raise SecurityViolationError(
            f"Operation forbidden: Target file '{norm}' is protected.\nReason: {reason}"
        )

    return norm


def calculate_sha256(data: bytes | str | Path) -> str:
    """Calculate SHA-256 hash of bytes, string, or local file."""
    hasher = hashlib.sha256()
    if isinstance(data, bytes):
        hasher.update(data)
    elif isinstance(data, str):
        hasher.update(data.encode("utf-8"))
    elif isinstance(data, Path):
        with open(data, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
    else:
        raise TypeError(f"Unsupported data type for hashing: {type(data)}")
    return hasher.hexdigest()


def mask_sensitive_text(text: str, secrets: Optional[List[str]] = None) -> str:
    """Mask any known secret or credential from being printed in logs or console."""
    if not text:
        return ""
    result = text
    if secrets:
        for secret in secrets:
            if secret and len(secret) >= 4:
                result = result.replace(secret, "********")

    # Mask potential passwords or tokens in URLs (e.g. sftp://user:pass@host)
    result = re.sub(r"://([^:@\s]+):([^@\s]+)@", r"://\1:********@", result)
    return result
