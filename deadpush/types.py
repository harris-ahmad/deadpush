"""Shared types for the deadpush guardian."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FileInfo:
    """Lightweight descriptor for a file evaluated by the guardian."""
    path: Path
    rel_path: Path
    size: int
    is_text: bool
    mtime: float

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


@dataclass
class DebrisFile:
    """A debris finding from real-time guardian evaluation."""
    path: str
    category: str
    confidence: float
    reasons: list[str]
    block_push: bool
    suggestion: str = ""

    @property
    def reason(self) -> str:
        return self.reasons[0] if self.reasons else self.category


def content_hash(path: Path | str) -> str | None:
    """SHA256 of file contents (first 16 hex chars), or None on failure."""
    try:
        data = Path(path).read_bytes()
        if not data:
            return None
        return hashlib.sha256(data).hexdigest()[:16]
    except Exception:
        return None
