"""
Git diff parser for extracting changed files and line ranges.

Supports unified diff format, staged changes, branch comparisons,
and commit ranges. Produces structured DiffResult objects for
downstream analyzers.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ChangeType(str, Enum):
    ADDED = "added"
    DELETED = "deleted"
    MODIFIED = "modified"
    RENAMED = "renamed"


@dataclass
class HunkRange:
    """A contiguous range of changed lines within a file."""

    start_line: int
    line_count: int
    content_lines: list[str] = field(default_factory=list)

    @property
    def end_line(self) -> int:
        return self.start_line + max(self.line_count - 1, 0)


@dataclass
class FileDiff:
    """Parsed diff for a single file."""

    file_path: str
    change_type: ChangeType
    old_path: str | None = None
    added_lines: list[int] = field(default_factory=list)
    deleted_lines: list[int] = field(default_factory=list)
    hunks: list[HunkRange] = field(default_factory=list)
    raw_diff: str = ""

    @property
    def changed_lines(self) -> set[int]:
        return set(self.added_lines)

    @property
    def total_changes(self) -> int:
        return len(self.added_lines) + len(self.deleted_lines)


@dataclass
class DiffResult:
    """Complete diff result across all changed files."""

    files: list[FileDiff] = field(default_factory=list)
    base_ref: str | None = None
    head_ref: str | None = None
    raw_output: str = ""

    @property
    def total_files_changed(self) -> int:
        return len(self.files)

    @property
    def total_additions(self) -> int:
        return sum(len(f.added_lines) for f in self.files)

    @property
    def total_deletions(self) -> int:
        return sum(len(f.deleted_lines) for f in self.files)

    def get_python_files(self) -> list[FileDiff]:
        return [f for f in self.files if f.file_path.endswith(".py")]


class DiffParser:
    """Parses Git diffs into structured FileDiff objects."""

    HUNK_HEADER_RE = re.compile(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
    )
    DIFF_FILE_RE = re.compile(r"^diff --git a/(.*) b/(.*)")
    RENAME_RE = re.compile(r"^rename from (.+)")

    def __init__(self, repo_path: str | Path | None = None):
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()

    def parse_diff_string(self, diff_text: str) -> DiffResult:
        """Parse a unified diff string into structured format."""
        result = DiffResult(raw_output=diff_text)
        current_file: FileDiff | None = None
        current_new_line = 0

        for line in diff_text.splitlines():
            # New file header
            file_match = self.DIFF_FILE_RE.match(line)
            if file_match:
                if current_file:
                    result.files.append(current_file)
                old_path, new_path = file_match.group(1), file_match.group(2)
                change_type = ChangeType.MODIFIED
                current_file = FileDiff(
                    file_path=new_path,
                    change_type=change_type,
                    old_path=old_path if old_path != new_path else None,
                )
                continue

            if current_file is None:
                continue

            # Detect new/deleted files
            if line.startswith("new file"):
                current_file.change_type = ChangeType.ADDED
            elif line.startswith("deleted file"):
                current_file.change_type = ChangeType.DELETED
            elif line.startswith("rename from"):
                current_file.change_type = ChangeType.RENAMED

            # Hunk header
            hunk_match = self.HUNK_HEADER_RE.match(line)
            if hunk_match:
                new_start = int(hunk_match.group(3))
                new_count = int(hunk_match.group(4) or "1")
                current_file.hunks.append(
                    HunkRange(start_line=new_start, line_count=new_count)
                )
                current_new_line = new_start
                continue

            # Diff content lines
            if line.startswith("+") and not line.startswith("+++"):
                current_file.added_lines.append(current_new_line)
                if current_file.hunks:
                    current_file.hunks[-1].content_lines.append(line[1:])
                current_new_line += 1
            elif line.startswith("-") and not line.startswith("---"):
                current_file.deleted_lines.append(current_new_line)
            else:
                if not line.startswith("\\"):
                    current_new_line += 1

        if current_file:
            result.files.append(current_file)

        return result

    def diff_from_ref(self, ref: str = "HEAD~1", staged: bool = False) -> DiffResult:
        """Get diff from a Git reference."""
        cmd = ["git", "diff"]
        if staged:
            cmd.append("--cached")
        else:
            cmd.append(ref)
        cmd.extend(["--unified=3", "--no-color"])

        try:
            output = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=30,
            )
            if output.returncode != 0:
                raise RuntimeError(f"Git diff failed: {output.stderr}")
            result = self.parse_diff_string(output.stdout)
            result.base_ref = ref
            result.head_ref = "HEAD" if not staged else "staged"
            return result
        except FileNotFoundError:
            raise RuntimeError("Git is not installed or not in PATH")

    def diff_between(self, base: str, head: str) -> DiffResult:
        """Get diff between two refs (branches, commits, tags)."""
        cmd = ["git", "diff", f"{base}...{head}", "--unified=3", "--no-color"]
        try:
            output = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=30,
            )
            if output.returncode != 0:
                raise RuntimeError(f"Git diff failed: {output.stderr}")
            result = self.parse_diff_string(output.stdout)
            result.base_ref = base
            result.head_ref = head
            return result
        except FileNotFoundError:
            raise RuntimeError("Git is not installed or not in PATH")
