"""
Source file reader with encoding detection and language identification.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class SourceFile:
    """A source file ready for analysis."""

    path: str
    content: str
    language: str
    encoding: str = "utf-8"
    line_count: int = 0

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()


LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".cpp": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
}


def detect_language(path: str) -> str:
    """Detect programming language from file extension."""
    suffix = Path(path).suffix.lower()
    return LANGUAGE_MAP.get(suffix, "unknown")


def read_source_file(path: str | Path, encoding: str = "utf-8") -> SourceFile:
    """Read a source file and return structured representation."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")

    try:
        content = p.read_text(encoding=encoding)
    except UnicodeDecodeError:
        content = p.read_text(encoding="latin-1")
        encoding = "latin-1"

    return SourceFile(
        path=str(p),
        content=content,
        language=detect_language(str(p)),
        encoding=encoding,
        line_count=content.count("\n") + (1 if content and not content.endswith("\n") else 0),
    )


def collect_files(
    root: str | Path,
    extensions: Optional[list[str]] = None,
    ignore_patterns: Optional[list[str]] = None,
) -> list[SourceFile]:
    """Recursively collect source files from a directory."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")

    extensions = extensions or [".py"]
    ignore = ignore_patterns or ["__pycache__", ".git", "node_modules", "venv", ".venv"]

    files = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in extensions:
            continue
        # Check ignore patterns against relative path
        rel = str(p.relative_to(root))
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(p.name, pat) for pat in ignore):
            continue
        # Skip hidden directories
        if any(part.startswith(".") for part in p.parts):
            continue

        try:
            files.append(read_source_file(p))
        except (UnicodeDecodeError, PermissionError):
            continue

    return sorted(files, key=lambda f: f.path)
