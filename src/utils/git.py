"""Git operation helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path


def get_repo_root(path: str | None = None) -> Path:
    """Find the root of the Git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True,
            cwd=path, timeout=10,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return Path(path) if path else Path.cwd()


def get_current_branch(path: str | None = None) -> str:
    """Get the current Git branch name."""
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True, text=True,
            cwd=path, timeout=10,
        )
        return result.stdout.strip() or "detached"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def get_staged_files(path: str | None = None) -> list[str]:
    """List files staged for commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True,
            cwd=path, timeout=10,
        )
        return [f for f in result.stdout.strip().splitlines() if f]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def is_git_repo(path: str | None = None) -> bool:
    """Check if the current directory is inside a Git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True,
            cwd=path, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
