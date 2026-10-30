"""Command-Line Interface for Hostinger SFTP Agent.

Implements:
- list / ls: browse remote directories safely
- get: download remote file
- diff: inspect differences between local and remote
- backup: generate local timestamped backup
- put: atomic upload with pre-write safety flow, diff, and confirmation
- edit: interactive edit with diff and confirmation
- status: verify connectivity and display configuration
- backups: view local backup history
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

import click
from tabulate import tabulate

from hostinger_cli.backup_manager import BackupManager
from hostinger_cli.config import Config, ConfigError, load_config
from hostinger_cli.diff_engine import generate_diff
from hostinger_cli.security import (
    SecurityViolationError,
    calculate_sha256,
    mask_sensitive_text,
)
from hostinger_cli.sftp_client import HostingerSFTPClient


def print_error(msg: str) -> None:
    click.secho(f"[-] ERROR: {msg}", fg="red", err=True)


def print_success(msg: str) -> None:
    click.secho(f"[+] {msg}", fg="green")


def print_warning(msg: str) -> None:
    click.secho(f"[!] WARNING: {msg}", fg="yellow")


def print_info(msg: str) -> None:
    click.secho(f"[*] {msg}", fg="cyan")


def get_configured_client(
    env_file: Optional[str],
    domain: Optional[str],
) -> tuple[Config, HostingerSFTPClient]:
    """Helper to initialize config and client with clean error reporting."""
    try:
        cfg = load_config(env_file)
        client = HostingerSFTPClient(cfg, target_domain=domain)
        return cfg, client
    except ConfigError as ce:
        print_error(str(ce))
        sys.exit(1)
    except Exception as e:
        print_error(f"Initialization error: {e}")
        sys.exit(1)


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--env-file", "-e", type=click.Path(), help="Path to custom .env file.")
@click.option("--domain", "-d", type=str, help="Target domain (defaults to HOSTINGER_TARGET_DOMAIN).")
@click.pass_context
def main(ctx: click.Context, env_file: Optional[str], domain: Optional[str]) -> None:
    """Hostinger SFTP CLI Agent - Secure remote file management."""
    ctx.ensure_object(dict)
    ctx.obj["env_file"] = env_file
    ctx.obj["domain"] = domain


@main.command(name="status")
@click.pass_context
def status_cmd(ctx: click.Context) -> None:
    """Test SFTP connection and view configuration (safe, no secrets printed)."""
    cfg, client = get_configured_client(ctx.obj["env_file"], ctx.obj["domain"])
    print_info("Testing connection to Hostinger SFTP...")
    safe_info = cfg.to_safe_dict()

    click.echo("\n--- Configuration ---")
    click.echo(f"Host:           {safe_info['host']}:{safe_info['port']}")
    click.echo(f"Username:       {safe_info['username']}")
    click.echo(f"Password:       {safe_info['password']}")
    click.echo(f"Active Domain:  {client.active_domain}")
    click.echo(f"Active Root:    {client.active_root}")
    click.echo(f"Allowed Roots:  {', '.join(safe_info['allowed_roots'])}")
    click.echo(f"Backup Dir:     {safe_info['backup_dir']}")
    click.echo(f"Host Key Check: {safe_info['host_key_fingerprint']}")
    click.echo("---------------------\n")

    try:
        with client:
            print_success(f"Connection successful to {cfg.host}:{cfg.port}!")
            # Check if active root exists
            exists = client.file_exists(client.active_root)
            if exists:
                print_success(f"Active root directory verified: {client.active_root}")
            else:
                print_warning(f"Active root directory not found on server: {client.active_root}")
    except Exception as e:
        safe_err = mask_sensitive_text(str(e), [cfg.password])
        print_error(f"Connection failed: {safe_err}")
        sys.exit(1)


@main.command(name="list")
@click.argument("remote_path", required=False, default="")
@click.pass_context
def list_cmd(ctx: click.Context, remote_path: str) -> None:
    """List contents of remote directory (default: active domain root)."""
    _, client = get_configured_client(ctx.obj["env_file"], ctx.obj["domain"])

    try:
        with client:
            resolved = client.resolve_path(remote_path)
            print_info(f"Listing: {resolved}")
            entries = client.list_dir(remote_path)

            if not entries:
                print_info("Directory is empty.")
                return

            rows = []
            for entry in entries:
                kind = "DIR" if entry.is_dir else "FILE"
                rows.append([
                    kind,
                    entry.permissions,
                    entry.format_size(),
                    entry.mtime.strftime("%Y-%m-%d %H:%M:%S"),
                    entry.name,
                ])

            table = tabulate(
                rows,
                headers=["Type", "Perms", "Size", "Modified", "Name"],
                tablefmt="simple",
            )
            click.echo(table)
            click.echo(f"\nTotal: {len(entries)} items")

    except (SecurityViolationError, FileNotFoundError) as se:
        print_error(str(se))
        sys.exit(1)
    except Exception as e:
        print_error(f"Failed to list directory: {e}")
        sys.exit(1)


@main.command(name="get")
@click.argument("remote_path")
@click.argument("local_path", required=False)
@click.pass_context
def get_cmd(ctx: click.Context, remote_path: str, local_path: Optional[str]) -> None:
    """Download a remote file safely to local disk."""
    _, client = get_configured_client(ctx.obj["env_file"], ctx.obj["domain"])

    try:
        with client:
            resolved = client.resolve_path(remote_path)
            if not client.file_exists(resolved):
                print_error(f"Remote file does not exist: {resolved}")
                sys.exit(1)

            target_local = local_path or Path("./downloads") / Path(resolved).name
            print_info(f"Downloading '{resolved}' to '{target_local}'...")
            downloaded = client.get_file(resolved, target_local)
            file_hash = calculate_sha256(downloaded)
            print_success(f"Downloaded: {downloaded} ({downloaded.stat().st_size} bytes)")
            print_info(f"SHA-256: {file_hash}")

    except SecurityViolationError as se:
        print_error(str(se))
        sys.exit(1)
    except Exception as e:
        print_error(f"Download failed: {e}")
        sys.exit(1)


@main.command(name="diff")
@click.argument("remote_path")
@click.argument("local_path")
@click.pass_context
def diff_cmd(ctx: click.Context, remote_path: str, local_path: str) -> None:
    """Display differences between remote file and local file."""
    _, client = get_configured_client(ctx.obj["env_file"], ctx.obj["domain"])

    local_file = Path(local_path).resolve()
    if not local_file.is_file():
        print_error(f"Local file does not exist: {local_file}")
        sys.exit(1)

    try:
        with client:
            resolved = client.resolve_path(remote_path)
            if not client.file_exists(resolved):
                print_error(f"Remote file does not exist: {resolved}")
                sys.exit(1)

            remote_bytes = client.read_bytes(resolved)
            with open(local_file, "rb") as lf:
                local_bytes = lf.read()

            has_diff, diff_text = generate_diff(
                remote_bytes=remote_bytes,
                local_bytes=local_bytes,
                remote_name=f"remote:{resolved}",
                local_name=f"local:{local_path}",
                color=True,
            )

            if not has_diff:
                print_success("Files are identical (hashes match).")
            else:
                click.echo("\n" + diff_text + "\n")

    except SecurityViolationError as se:
        print_error(str(se))
        sys.exit(1)
    except Exception as e:
        print_error(f"Diff inspection failed: {e}")
        sys.exit(1)


@main.command(name="backup")
@click.argument("remote_path")
@click.pass_context
def backup_cmd(ctx: click.Context, remote_path: str) -> None:
    """Create an explicit local timestamped backup of a remote file."""
    cfg, client = get_configured_client(ctx.obj["env_file"], ctx.obj["domain"])
    bm = BackupManager(cfg.backup_dir)

    try:
        with client:
            resolved = client.resolve_path(remote_path)
            if not client.file_exists(resolved):
                print_error(f"Remote file does not exist: {resolved}")
                sys.exit(1)

            remote_bytes = client.read_bytes(resolved)
            stat_obj = client.get_stat(resolved)
            mtime = int(stat_obj.st_mtime) if stat_obj else None

            backup_path = bm.create_backup(
                remote_path=resolved,
                content=remote_bytes,
                domain=client.active_domain,
                remote_mtime=mtime,
            )
            file_hash = calculate_sha256(remote_bytes)
            print_success(f"Backup created: {backup_path}")
            print_info(f"SHA-256: {file_hash} ({len(remote_bytes)} bytes)")

    except SecurityViolationError as se:
        print_error(str(se))
        sys.exit(1)
    except Exception as e:
        print_error(f"Backup failed: {e}")
        sys.exit(1)


@main.command(name="put")
@click.argument("local_path")
@click.argument("remote_path")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts.")
@click.pass_context
def put_cmd(ctx: click.Context, local_path: str, remote_path: str, yes: bool) -> None:
    """Upload local file to remote server with pre-write safety checks and backup."""
    cfg, client = get_configured_client(ctx.obj["env_file"], ctx.obj["domain"])
    bm = BackupManager(cfg.backup_dir)

    local_file = Path(local_path).resolve()
    if not local_file.is_file():
        print_error(f"Local file does not exist: {local_file}")
        sys.exit(1)

    with open(local_file, "rb") as f:
        local_bytes = f.read()
    local_hash = calculate_sha256(local_bytes)

    try:
        with client:
            resolved = client.resolve_path(remote_path)
            remote_exists = client.file_exists(resolved)

            expected_remote_hash: Optional[str] = None

            if remote_exists:
                # Step 1: Read remote bytes and calculate initial hash
                remote_bytes = client.read_bytes(resolved)
                expected_remote_hash = calculate_sha256(remote_bytes)

                # Step 2: Show diff
                has_diff, diff_text = generate_diff(
                    remote_bytes=remote_bytes,
                    local_bytes=local_bytes,
                    remote_name=f"remote:{resolved}",
                    local_name=f"local:{local_path}",
                    color=True,
                )

                if not has_diff:
                    print_info("Remote file is already identical to local file. No changes needed.")
                    return

                click.echo("\n--- Proposed Changes (Diff) ---")
                click.echo(diff_text)
                click.echo("---------------------------------\n")

                # Step 3: Prompt confirmation
                if not yes:
                    confirm = click.confirm(
                        f"Overwrite remote file '{resolved}' with '{local_path}'?",
                        default=False,
                    )
                    if not confirm:
                        print_warning("Operation cancelled by user.")
                        return

                # Step 4: Create local dated backup
                stat_obj = client.get_stat(resolved)
                mtime = int(stat_obj.st_mtime) if stat_obj else None
                backup_path = bm.create_backup(
                    remote_path=resolved,
                    content=remote_bytes,
                    domain=client.active_domain,
                    remote_mtime=mtime,
                )
                print_success(f"Automatic pre-write backup saved: {backup_path}")

            else:
                # New remote file
                if not yes:
                    confirm = click.confirm(
                        f"Create NEW remote file '{resolved}' from '{local_path}'?",
                        default=False,
                    )
                    if not confirm:
                        print_warning("Operation cancelled by user.")
                        return

            # Step 5: Atomic upload with concurrency check
            print_info(f"Uploading atomically to '{resolved}'...")
            res = client.put_file_atomic(
                local_source=local_file,
                remote_dest=resolved,
                expected_remote_hash=expected_remote_hash,
            )

            print_success(f"File uploaded successfully to: {res['remote_path']}")
            print_info(f"Verified SHA-256: {res['sha256']} ({res['size_bytes']} bytes)")

    except SecurityViolationError as se:
        print_error(str(se))
        sys.exit(1)
    except Exception as e:
        print_error(f"Put operation failed: {e}")
        sys.exit(1)


@main.command(name="edit")
@click.argument("remote_path")
@click.pass_context
def edit_cmd(ctx: click.Context, remote_path: str) -> None:
    """Interactively edit a remote file with diff, backup, and atomic upload."""
    cfg, client = get_configured_client(ctx.obj["env_file"], ctx.obj["domain"])
    bm = BackupManager(cfg.backup_dir)

    try:
        with client:
            resolved = client.resolve_path(remote_path)
            if not client.file_exists(resolved):
                print_error(f"Remote file does not exist: {resolved}")
                sys.exit(1)

            # Step 1: Read remote file
            original_bytes = client.read_bytes(resolved)
            original_hash = calculate_sha256(original_bytes)

            # Step 2: Write to local temp file for editing
            suffix = Path(resolved).suffix or ".txt"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp_file:
                tmp_file.write(original_bytes)
                tmp_path = Path(tmp_file.name)

            try:
                # Determine editor
                editor = os.getenv("EDITOR")
                if not editor:
                    if sys.platform == "win32":
                        # Check if 'code' (VS Code) is available
                        if shutil.which("code"):
                            editor = "code --wait"
                        else:
                            editor = "notepad"
                    else:
                        editor = "nano" if shutil.which("nano") else "vi"

                print_info(f"Opening editor ({editor}) for '{resolved}'...")
                exit_code = subprocess.call(f"{editor} \"{tmp_path}\"", shell=True)
                if exit_code != 0:
                    print_error(f"Editor exited with code {exit_code}.")
                    return

                with open(tmp_path, "rb") as f:
                    new_bytes = f.read()

                # Step 3: Check if changes were made
                has_diff, diff_text = generate_diff(
                    remote_bytes=original_bytes,
                    local_bytes=new_bytes,
                    remote_name=f"remote:{resolved}",
                    local_name="edited_copy",
                    color=True,
                )

                if not has_diff:
                    print_info("No changes were made. Aborting.")
                    return

                click.echo("\n--- Proposed Changes (Diff) ---")
                click.echo(diff_text)
                click.echo("---------------------------------\n")

                # Step 4: Ask confirmation
                if not click.confirm("Apply these changes to the remote server?", default=False):
                    print_warning("Edit cancelled. No changes were applied.")
                    return

                # Step 5: Create pre-write backup
                stat_obj = client.get_stat(resolved)
                mtime = int(stat_obj.st_mtime) if stat_obj else None
                backup_path = bm.create_backup(
                    remote_path=resolved,
                    content=original_bytes,
                    domain=client.active_domain,
                    remote_mtime=mtime,
                )
                print_success(f"Automatic pre-write backup saved: {backup_path}")

                # Step 6: Atomic upload with concurrency check
                print_info(f"Uploading changes atomically to '{resolved}'...")
                res = client.put_file_atomic(
                    local_source=tmp_path,
                    remote_dest=resolved,
                    expected_remote_hash=original_hash,
                )
                print_success(f"Remote file '{res['remote_path']}' updated successfully!")
                print_info(f"Verified SHA-256: {res['sha256']}")

            finally:
                if tmp_path.is_file():
                    try:
                        tmp_path.unlink()
                    except Exception:
                        pass

    except SecurityViolationError as se:
        print_error(str(se))
        sys.exit(1)
    except Exception as e:
        print_error(f"Edit operation failed: {e}")
        sys.exit(1)


@main.command(name="backups")
@click.pass_context
def list_backups_cmd(ctx: click.Context) -> None:
    """View local backup history and integrity hashes."""
    cfg = load_config(ctx.obj["env_file"])
    bm = BackupManager(cfg.backup_dir)
    records = bm.list_backups(domain=ctx.obj.get("domain"))

    if not records:
        print_info("No backups recorded yet in manifest.")
        return

    rows = []
    for r in records:
        rows.append([
            r.get("timestamp", "")[:19],
            r.get("domain", ""),
            r.get("remote_path", ""),
            f"{r.get('size_bytes', 0)} B",
            r.get("sha256", "")[:12] + "...",
            r.get("backup_file", ""),
        ])

    table = tabulate(
        rows,
        headers=["Timestamp", "Domain", "Remote Path", "Size", "SHA-256", "Backup File"],
        tablefmt="simple",
    )
    click.echo(table)
    click.echo(f"\nTotal: {len(records)} backups logged.")


if __name__ == "__main__":
    main()
