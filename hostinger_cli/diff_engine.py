"""Diff calculation and formatting between remote and local contents."""

from __future__ import annotations

import difflib
from typing import Tuple


def is_binary_content(content: bytes) -> bool:
    """Heuristic check for binary content (null bytes or high proportion of non-text)."""
    if b"\x00" in content:
        return True
    # Try decoding as utf-8 or latin-1
    try:
        content.decode("utf-8")
        return False
    except UnicodeDecodeError:
        try:
            content.decode("latin-1")
            return False
        except UnicodeDecodeError:
            return True


def generate_diff(
    remote_bytes: bytes,
    local_bytes: bytes,
    remote_name: str = "remote",
    local_name: str = "local",
    color: bool = True,
) -> Tuple[bool, str]:
    """Generate a readable unified diff between remote content and local content.

    Returns:
        Tuple[bool, str]: (has_differences, formatted_diff_string)
    """
    if remote_bytes == local_bytes:
        return False, "Files are identical (no differences found)."

    is_remote_bin = is_binary_content(remote_bytes)
    is_local_bin = is_binary_content(local_bytes)

    if is_remote_bin or is_local_bin:
        msg = (
            f"Binary files differ.\n"
            f"  {remote_name}: {len(remote_bytes)} bytes\n"
            f"  {local_name}: {len(local_bytes)} bytes"
        )
        return True, msg

    try:
        remote_lines = remote_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
        local_lines = local_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
    except Exception as e:
        return True, f"Error decoding file contents for diff: {e}"

    diff_lines = list(
        difflib.unified_diff(
            remote_lines,
            local_lines,
            fromfile=remote_name,
            tofile=local_name,
            lineterm="",
        )
    )

    if not diff_lines:
        return False, "Files are identical."

    if not color:
        return True, "\n".join(diff_lines)

    # Apply ANSI colors
    color_diff = []
    for line in diff_lines:
        if line.startswith("---") or line.startswith("+++"):
            color_diff.append(f"\033[1;37m{line}\033[0m")  # Bold white
        elif line.startswith("@@"):
            color_diff.append(f"\033[36m{line}\033[0m")     # Cyan
        elif line.startswith("+"):
            color_diff.append(f"\033[32m{line}\033[0m")     # Green
        elif line.startswith("-"):
            color_diff.append(f"\033[31m{line}\033[0m")     # Red
        else:
            color_diff.append(line)

    return True, "\n".join(color_diff)
