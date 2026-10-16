"""Content hashing utilities for deduplication and caching."""

from __future__ import annotations

import hashlib


def hash_content(content: str) -> str:
    """Produce a short SHA-256 hash of content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def hash_file(path: str) -> str:
    """Hash the contents of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:16]
