"""Unit tests for security rules, path validation, and protected files."""

import pytest
from hostinger_cli.security import (
    SecurityViolationError,
    calculate_sha256,
    is_path_allowed,
    is_protected_file,
    mask_sensitive_text,
    normalize_remote_path,
    validate_path_for_read,
    validate_path_for_write,
)

ALLOWED_ROOTS = [
    "/home/u000000000/domains/grupomonoga.com/public_html",
    "/home/u000000000/domains/staging.grupomonoga.com/public_html",
]


def test_normalize_remote_path():
    assert normalize_remote_path("foo/bar", base_root="/home/user/public_html") == "/home/user/public_html/foo/bar"
    assert normalize_remote_path("../bar", base_root="/home/user/public_html") == "/home/user/bar"
    assert normalize_remote_path("/absolute/path") == "/absolute/path"
    assert normalize_remote_path("/a/b/../c") == "/a/c"


def test_is_path_allowed():
    valid = "/home/u000000000/domains/grupomonoga.com/public_html/index.php"
    assert is_path_allowed(valid, ALLOWED_ROOTS) is True

    valid_sub = "/home/u000000000/domains/grupomonoga.com/public_html/wp-content/themes/style.css"
    assert is_path_allowed(valid_sub, ALLOWED_ROOTS) is True

    # Path traversal outside allowed roots
    traversal = "/home/u000000000/domains/grupomonoga.com/public_html/../../etc/passwd"
    assert is_path_allowed(traversal, ALLOWED_ROOTS) is False

    # Root of server or other user
    assert is_path_allowed("/etc/shadow", ALLOWED_ROOTS) is False
    assert is_path_allowed("/home/u000000000/other_dir/secret.txt", ALLOWED_ROOTS) is False


def test_validate_path_for_read_denies_unauthorized_paths():
    with pytest.raises(SecurityViolationError):
        validate_path_for_read("/etc/passwd", ALLOWED_ROOTS)


def test_protected_files():
    # Sensitive config & env files
    assert is_protected_file("/var/www/.env")[0] is True
    assert is_protected_file("/var/www/.env.production")[0] is True
    assert is_protected_file("/var/www/secret.env")[0] is True
    assert is_protected_file("/var/www/wp-config.php")[0] is True
    assert is_protected_file("/var/www/wp-config-sample.php")[0] is True

    # Keys & Certificates
    assert is_protected_file("/var/www/ssl/server.key")[0] is True
    assert is_protected_file("/var/www/certs/domain.pem")[0] is True
    assert is_protected_file("/var/www/cert.crt")[0] is True
    assert is_protected_file("/var/www/auth.pfx")[0] is True
    assert is_protected_file("/var/www/id_rsa")[0] is True

    # Backups & Archives
    assert is_protected_file("/var/www/db_dump.sql")[0] is True
    assert is_protected_file("/var/www/database.sql.gz")[0] is True
    assert is_protected_file("/var/www/site_backup.tar.gz")[0] is True
    assert is_protected_file("/var/www/site.zip")[0] is True
    assert is_protected_file("/var/www/backups/index.php")[0] is True
    assert is_protected_file("/var/www/index.php.bak")[0] is True

    # Regular files that should NOT be protected
    assert is_protected_file("/var/www/index.php")[0] is False
    assert is_protected_file("/var/www/style.css")[0] is False
    assert is_protected_file("/var/www/main.js")[0] is False
    assert is_protected_file("/var/www/image.png")[0] is False


def test_validate_path_for_write_blocks_protected_files():
    root = ALLOWED_ROOTS[0]
    # Allowed file
    assert validate_path_for_write(f"{root}/index.php", ALLOWED_ROOTS) == f"{root}/index.php"

    # Protected file in allowed root
    with pytest.raises(SecurityViolationError, match="protected"):
        validate_path_for_write(f"{root}/wp-config.php", ALLOWED_ROOTS)

    with pytest.raises(SecurityViolationError, match="protected"):
        validate_path_for_write(f"{root}/.env", ALLOWED_ROOTS)

    with pytest.raises(SecurityViolationError, match="protected"):
        validate_path_for_write(f"{root}/ssl.key", ALLOWED_ROOTS)


def test_calculate_sha256(tmp_path):
    import hashlib
    data = b"Hello Hostinger Security Test"
    expected = hashlib.sha256(data).hexdigest()
    assert calculate_sha256(data) == expected

    tmp_file = tmp_path / "test.txt"
    tmp_file.write_bytes(data)
    assert calculate_sha256(tmp_file) == expected


def test_mask_sensitive_text():
    secret_pass = "UltraSecretPass123!"
    log_msg = f"Connecting with password {secret_pass} to server"
    masked = mask_sensitive_text(log_msg, secrets=[secret_pass])
    assert secret_pass not in masked
    assert "********" in masked

    url = "sftp://u000000000:MySecretPassword@203.0.113.10:65002"
    masked_url = mask_sensitive_text(url)
    assert "MySecretPassword" not in masked_url
    assert "********" in masked_url
