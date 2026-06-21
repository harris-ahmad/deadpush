"""
Source file crawler for deadpush.

Discovers text source files while respecting:
- .gitignore + built-in ignores
- Config ignore patterns + language filters (indirectly via caller)
- Size limits and binary detection
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import Config


@dataclass(frozen=True, slots=True)
class FileInfo:
    """Lightweight descriptor for a discovered file passed to analyzers."""
    path: Path
    rel_path: Path
    size: int
    is_text: bool
    mtime: float

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


def _is_text_file(path: Path, max_bytes: int = 4096) -> bool:
    """Heuristic: read prefix and look for null bytes or control chars typical of binary."""
    try:
        with path.open("rb") as f:
            chunk = f.read(max_bytes)
        if b"\0" in chunk:
            return False
        # Allow common text
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
        return all(b in text_chars for b in chunk)
    except Exception:
        return False


def _iter_candidate_files(root: Path, ignore_spec) -> Iterator[Path]:
    """Yield candidate paths, skipping ignored and non-regular files."""
    for dirpath, dirnames, filenames in os.walk(root):
        dir_p = Path(dirpath)

        # Prune ignored dirs early (mutate dirnames)
        kept = []
        for d in dirnames:
            dp = dir_p / d
            rel = dp.relative_to(root)
            if not ignore_spec.match_file(str(rel)) and not ignore_spec.match_file(str(rel) + "/"):
                kept.append(d)
        dirnames[:] = kept

        for fn in filenames:
            fp = dir_p / fn
            try:
                rel = fp.relative_to(root)
            except ValueError:
                continue
            if ignore_spec.match_file(str(rel)):
                continue
            # Skip symlinks, sockets etc for safety
            try:
                mode = fp.lstat().st_mode
                if not stat.S_ISREG(mode):
                    continue
            except OSError:
                continue
            yield fp


def iter_source_files(repo_root: Path, config: Config) -> list[FileInfo]:
    """
    Return discovered files under repo_root.

    Always returns more files than just code (debris detector wants md, env, etc).
    Language plugins later filter by their extensions for graph analysis.
    """
    ignore_spec = config.get_effective_ignore_spec()
    max_bytes = config.max_file_size_mb * 1024 * 1024

    files: list[FileInfo] = []
    for p in _iter_candidate_files(repo_root, ignore_spec):
        try:
            st = p.stat()
            size = st.st_size
            if size > max_bytes:
                is_text = False
            else:
                is_text = _is_text_file(p)
            rel = p.relative_to(repo_root)
            files.append(FileInfo(
                path=p,
                rel_path=rel,
                size=size,
                is_text=is_text,
                mtime=st.st_mtime,
            ))
        except OSError:
            continue

    # Stable sort by path for determinism
    files.sort(key=lambda f: str(f.rel_path))
    return files


def get_supported_extensions(config: Config | None = None) -> set[str]:
    """Return a union of extensions from known plugins (used by watch etc)."""
    # Avoid circular import at module load: import lazily inside function
    exts: set[str] = set()
    try:
        from .languages import get_all_extensions
        exts.update(get_all_extensions())
    except Exception:
        # Fallback defaults covering the common ones
        exts.update({
            ".py", ".pyi",
            ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
            ".go",
            ".rs",
            ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".h", ".c",
            ".java",
        })
    return exts
