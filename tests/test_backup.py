"""Unit tests for BackupManager and DiffEngine."""

from pathlib import Path
from hostinger_cli.backup_manager import BackupManager
from hostinger_cli.diff_engine import generate_diff, is_binary_content
from hostinger_cli.security import calculate_sha256


def test_backup_manager_creation(tmp_path):
    bm = BackupManager(tmp_path)
    remote_path = "/home/u000000000/domains/grupomonoga.com/public_html/index.php"
    content = b"<?php echo 'Version 1'; ?>"

    backup_file = bm.create_backup(remote_path, content, domain="grupomonoga.com")
    assert backup_file.is_file()
    assert backup_file.read_bytes() == content

    records = bm.list_backups("grupomonoga.com")
    assert len(records) == 1
    assert records[0]["remote_path"] == remote_path
    assert records[0]["sha256"] == calculate_sha256(content)


def test_diff_engine_identical():
    data = b"line 1\nline 2\n"
    has_diff, msg = generate_diff(data, data)
    assert has_diff is False
    assert "identical" in msg.lower()


def test_diff_engine_text_differences():
    remote = b"hello world\nold line\n"
    local = b"hello world\nnew line\n"
    has_diff, diff = generate_diff(remote, local, color=False)
    assert has_diff is True
    assert "-old line" in diff
    assert "+new line" in diff


def test_diff_engine_binary_files():
    bin1 = b"\x00\x01\x02\x03\xff"
    bin2 = b"\x00\x01\x02\x03\xfe"
    assert is_binary_content(bin1) is True
    has_diff, msg = generate_diff(bin1, bin2)
    assert has_diff is True
    assert "Binary files differ" in msg
