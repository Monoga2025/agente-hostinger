"""Configuration management for Hostinger SFTP Agent.

Loads environment variables from local .env and provides validation,
multi-domain routing, and secret masking.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv


class ConfigError(Exception):
    """Raised when configuration is invalid or missing required values."""
    pass


@dataclass
class DomainConfig:
    """Configuration for a specific domain root."""
    name: str
    root_path: str

    def __post_init__(self) -> None:
        # Standardize as POSIX path without trailing slash
        clean = self.root_path.replace("\\", "/").rstrip("/")
        if not clean.startswith("/"):
            clean = "/" + clean
        self.root_path = clean


@dataclass
class Config:
    """Agent configuration loaded from .env."""
    host: str
    port: int
    username: str
    password: str
    target_domain: str
    allowed_roots: List[str] = field(default_factory=list)
    domain_map: Dict[str, str] = field(default_factory=dict)
    backup_dir: Path = field(default_factory=lambda: Path("./backups"))
    host_key_fingerprint: Optional[str] = None
    env_file_path: Optional[Path] = None

    def get_root_for_domain(self, domain: Optional[str] = None) -> str:
        """Resolve the root path for a given domain or the active target domain."""
        dom = domain or self.target_domain
        if dom in self.domain_map:
            return self.domain_map[dom]
        if self.allowed_roots:
            return self.allowed_roots[0]
        raise ConfigError(f"No root path found for domain '{dom}'.")

    def to_safe_dict(self) -> dict:
        """Return a representation safe for display, without secret leakage."""
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": "********" if self.password else "<NOT SET>",
            "target_domain": self.target_domain,
            "allowed_roots": self.allowed_roots,
            "domain_map": self.domain_map,
            "backup_dir": str(self.backup_dir),
            "host_key_fingerprint": self.host_key_fingerprint or "<Not Configured>",
            "env_file": str(self.env_file_path) if self.env_file_path else "<Default>",
        }

    def __repr__(self) -> str:
        safe = self.to_safe_dict()
        return f"Config({safe})"


def _clean_path(path: str) -> str:
    """Normalize remote path as clean POSIX path."""
    p = path.strip().replace("\\", "/")
    p = posixpath.normpath(p)
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") if p != "/" else "/"


def _is_placeholder(val: str) -> bool:
    """Check if value is a placeholder like '<contraseña>' or empty."""
    v = val.strip()
    return not v or (v.startswith("<") and v.endswith(">"))


def load_config(env_path: Optional[str | Path] = None) -> Config:
    """Load and validate configuration from .env file.

    Args:
        env_path: Optional path to .env file. If not provided, searches current working directory.

    Raises:
        ConfigError: If required configuration is missing or invalid.
    """
    if env_path:
        env_file = Path(env_path).resolve()
        if not env_file.is_file():
            raise ConfigError(f"Specified env file does not exist: {env_file}")
        load_dotenv(dotenv_path=env_file, override=True, encoding="utf-8")
    else:
        # Look in current directory or parent directory
        env_file = Path(".env").resolve()
        if env_file.is_file():
            load_dotenv(dotenv_path=env_file, override=True, encoding="utf-8")
        else:
            load_dotenv(override=True, encoding="utf-8")

    host = os.getenv("HOSTINGER_SFTP_HOST", "").strip()
    port_str = os.getenv("HOSTINGER_SFTP_PORT", "65002").strip()
    username = os.getenv("HOSTINGER_SFTP_USERNAME", "").strip()
    password = os.getenv("HOSTINGER_SFTP_PASSWORD", "").strip()
    target_domain = os.getenv("HOSTINGER_TARGET_DOMAIN", "").strip()
    allowed_roots_raw = os.getenv("HOSTINGER_ALLOWED_ROOTS", "").strip()
    backup_dir_str = os.getenv("HOSTINGER_BACKUP_DIR", "./backups").strip()
    host_key_fp = os.getenv("HOSTINGER_SSH_HOST_KEY_FINGERPRINT", "").strip()
    domains_raw = os.getenv("HOSTINGER_DOMAINS", "").strip()

    # Validation checks
    missing: List[str] = []
    if _is_placeholder(host):
        missing.append("HOSTINGER_SFTP_HOST")
    if _is_placeholder(username):
        missing.append("HOSTINGER_SFTP_USERNAME")
    if _is_placeholder(password):
        missing.append("HOSTINGER_SFTP_PASSWORD (set your agent password in .env)")
    if _is_placeholder(target_domain):
        missing.append("HOSTINGER_TARGET_DOMAIN")
    if _is_placeholder(allowed_roots_raw):
        missing.append("HOSTINGER_ALLOWED_ROOTS")

    if missing:
        raise ConfigError(
            f"Missing or placeholder configuration values in .env:\n- "
            + "\n- ".join(missing)
            + "\nPlease update your local .env file before running."
        )

    try:
        port = int(port_str)
    except ValueError:
        raise ConfigError(f"Invalid HOSTINGER_SFTP_PORT: '{port_str}'. Must be an integer.")

    # Parse allowed roots (comma or semicolon separated)
    roots_list: List[str] = []
    for r in allowed_roots_raw.replace(";", ",").split(","):
        clean_r = _clean_path(r)
        if clean_r and clean_r not in roots_list:
            roots_list.append(clean_r)

    # Parse domain map (format: domain1:/path/to/root,domain2:/path/to/root)
    domain_map: Dict[str, str] = {}
    if domains_raw and not _is_placeholder(domains_raw):
        for item in domains_raw.replace(";", ",").split(","):
            item = item.strip()
            if ":" in item:
                dom, path = item.split(":", 1)
                dom = dom.strip()
                clean_p = _clean_path(path)
                domain_map[dom] = clean_p
                if clean_p not in roots_list:
                    roots_list.append(clean_p)

    # If target_domain is not yet in domain_map, bind it to the first allowed root
    if target_domain and target_domain not in domain_map and roots_list:
        domain_map[target_domain] = roots_list[0]

    backup_dir = Path(backup_dir_str).resolve()
    fp = None if _is_placeholder(host_key_fp) else host_key_fp

    return Config(
        host=host,
        port=port,
        username=username,
        password=password,
        target_domain=target_domain,
        allowed_roots=roots_list,
        domain_map=domain_map,
        backup_dir=backup_dir,
        host_key_fingerprint=fp,
        env_file_path=env_file if env_file.is_file() else None,
    )
