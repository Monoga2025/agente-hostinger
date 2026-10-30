# tests

pytest suite for the Hostinger SFTP agent (20 tests in the last run, SFTP calls mocked).

- `test_security.py`: path traversal, protected files and hashing.
- `test_config.py`: configuration loading and multi-domain handling.
- `test_backup.py`: backups and diffs.
- `test_cli.py`: CLI commands and atomic write workflows.
- Run with `python -m pytest -v` from the repo root.
