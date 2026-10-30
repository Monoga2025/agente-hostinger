# hostinger_cli

The Python package behind `python -m hostinger_cli`.

- `cli.py`: commands (`status`, `list`, `get`, `diff`, `backup`, `put`, `edit`, `backups`).
- `sftp_client.py`: Paramiko SFTP client with atomic writes and concurrency checks.
- `security.py`: root confinement, protected-file rules and SHA-256 hashing.
- `config.py`: loads `.env` and handles multi-domain settings.
- `backup_manager.py` and `diff_engine.py`: dated local backups with a JSONL manifest, and colored unified diffs.
- `__main__.py`: module entry point.
