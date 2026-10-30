"""Tests for CLI interface and SFTP atomic workflows with mocking."""

from unittest.mock import MagicMock, patch
from click.testing import CliRunner

from hostinger_cli.cli import main
from hostinger_cli.config import Config
from hostinger_cli.security import SecurityViolationError, calculate_sha256
from hostinger_cli.sftp_client import HostingerSFTPClient


def make_mock_config(tmp_path) -> Config:
    return Config(
        host="203.0.113.10",
        port=65002,
        username="u000000000",
        password="ValidPassword123",
        target_domain="grupomonoga.com",
        allowed_roots=["/home/u000000000/domains/grupomonoga.com/public_html"],
        domain_map={"grupomonoga.com": "/home/u000000000/domains/grupomonoga.com/public_html"},
        backup_dir=tmp_path / "backups",
    )


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "get" in result.output
    assert "diff" in result.output
    assert "backup" in result.output
    assert "put" in result.output
    assert "edit" in result.output
    assert "status" in result.output
    assert "backups" in result.output


def test_sftp_atomic_upload_workflow(tmp_path):
    cfg = make_mock_config(tmp_path)
    client = HostingerSFTPClient(cfg)

    # Setup local file
    local_file = tmp_path / "test.html"
    local_content = b"<h1>Hello World</h1>"
    local_file.write_bytes(local_content)
    local_hash = calculate_sha256(local_content)

    mock_sftp = MagicMock()
    # Mock stat for the temp file check
    mock_stat = MagicMock()
    mock_stat.st_size = len(local_content)
    mock_sftp.stat.return_value = mock_stat
    client.sftp_client = mock_sftp

    # Target path inside allowed root
    target_remote = "/home/u000000000/domains/grupomonoga.com/public_html/test.html"

    # Mock that remote file does not exist initially
    client.file_exists = MagicMock(return_value=False)

    res = client.put_file_atomic(local_file, target_remote)

    # Verify upload was called with temporary file
    assert mock_sftp.put.called
    tmp_arg = mock_sftp.put.call_args[0][1]
    assert ".tmp_" in tmp_arg

    # Verify rename was called to atomic target
    assert mock_sftp.posix_rename.called or mock_sftp.rename.called
    assert res["sha256"] == local_hash
    assert res["size_bytes"] == len(local_content)


def test_sftp_atomic_upload_detects_concurrency_change(tmp_path):
    cfg = make_mock_config(tmp_path)
    client = HostingerSFTPClient(cfg)
    client.sftp_client = MagicMock()

    local_file = tmp_path / "update.html"
    local_file.write_bytes(b"updated")

    target_remote = "/home/u000000000/domains/grupomonoga.com/public_html/update.html"

    # Simulate that server file was modified by someone else in the meantime
    client.file_exists = MagicMock(return_value=True)
    client.get_remote_hash = MagicMock(return_value="server_hash_different")

    # We expect original hash "initial_hash", but server has "server_hash_different"
    try:
        client.put_file_atomic(local_file, target_remote, expected_remote_hash="initial_hash")
        assert False, "Expected SecurityViolationError due to concurrency mismatch"
    except SecurityViolationError as e:
        assert "Concurrency collision detected" in str(e)


def test_sftp_blocks_protected_files(tmp_path):
    cfg = make_mock_config(tmp_path)
    client = HostingerSFTPClient(cfg)
    client.sftp_client = MagicMock()

    local_file = tmp_path / "wp-config.php"
    local_file.write_bytes(b"forbidden")

    target_remote = "/home/u000000000/domains/grupomonoga.com/public_html/wp-config.php"

    try:
        client.put_file_atomic(local_file, target_remote)
        assert False, "Expected SecurityViolationError for wp-config.php"
    except SecurityViolationError as e:
        assert "protected" in str(e)


@patch("hostinger_cli.cli.load_config")
@patch("hostinger_cli.cli.HostingerSFTPClient")
def test_cli_put_requires_confirmation_unless_yes(mock_client_cls, mock_load_cfg, tmp_path):
    cfg = make_mock_config(tmp_path)
    mock_load_cfg.return_value = cfg

    mock_client = MagicMock()
    mock_client.active_domain = cfg.target_domain
    mock_client.active_root = cfg.allowed_roots[0]
    mock_client.resolve_path.side_effect = lambda p: f"{cfg.allowed_roots[0]}/{p}"
    mock_client.file_exists.return_value = True
    mock_client.read_bytes.return_value = b"old remote content"
    mock_client.get_stat.return_value = MagicMock(st_mtime=123456)
    mock_client.put_file_atomic.return_value = {
        "remote_path": f"{cfg.allowed_roots[0]}/index.html",
        "sha256": "abc123",
        "size_bytes": 10,
    }
    mock_client_cls.return_value = mock_client

    local_file = tmp_path / "index.html"
    local_file.write_bytes(b"new local content")

    runner = CliRunner()

    # Case 1: User declines confirmation -> put_file_atomic should NOT be called
    result_decline = runner.invoke(main, ["put", str(local_file), "index.html"], input="n\n")
    assert result_decline.exit_code == 0
    assert "Operation cancelled" in result_decline.output
    assert not mock_client.put_file_atomic.called

    # Case 2: User passes --yes -> put_file_atomic SHOULD be called
    result_yes = runner.invoke(main, ["put", str(local_file), "index.html", "--yes"])
    assert result_yes.exit_code == 0
    assert mock_client.put_file_atomic.called
