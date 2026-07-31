"""Write-ahead-style file journal for recoverability (thesis Phase 1).

Stores *preimages* of files (content-addressed blobs + append-only entries)
so staged recovery / save points can restore useful work after a destructive
agent action — without requiring an LLM.

Design notes (from docs/thesis.md + docs/openai-features.md):

- Journal only changed files, not whole worktrees.
- First unrepaired preimage for a relative path wins within an epoch
  (classic WAL: the original before the mutation chain).
- Blobs are keyed by sha256 so repeated captures of the same bytes are cheap.
- This module is the store. Save points and staged git intercept are later slices.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

logger = logging.getLogger("deadpush.journal")

JOURNAL_DIRNAME = "journal"
BLOBS_DIRNAME = "blobs"
ENTRIES_FILENAME = "entries.jsonl"
EPOCH_FILENAME = "epoch.json"


@dataclass(frozen=True)
class JournalEntry:
    """One recorded preimage (or 'did not exist') for a repo-relative path."""

    id: str
    ts: str
    rel: str
    kind: str  # "modify" | "create"
    sha256: str | None
    size: int
    mtime_ns: int | None
    epoch: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JournalEntry:
        return cls(
            id=str(data["id"]),
            ts=str(data["ts"]),
            rel=str(data["rel"]),
            kind=str(data.get("kind", "modify")),
            sha256=data.get("sha256"),
            size=int(data.get("size", 0)),
            mtime_ns=data.get("mtime_ns"),
            epoch=str(data.get("epoch", "")),
        )


class JournalStore:
    """Per-repo durable journal under ``<repo>/.deadpush/journal/``."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self.root = self.repo_root / ".deadpush" / JOURNAL_DIRNAME
        self.blobs_dir = self.root / BLOBS_DIRNAME
        self.entries_path = self.root / ENTRIES_FILENAME
        self.epoch_path = self.root / EPOCH_FILENAME
        self._lock = threading.Lock()
        self._ensure_layout()
        self._epoch = self._load_or_create_epoch()
        # id -> entry (O(1) lookups; rebuilt from JSONL on init)
        self._entries_by_id: dict[str, JournalEntry] = {}
        # rel -> entry id of first unrepaired preimage in this epoch
        self._first_wins: dict[str, str] = {}
        self._load_index_from_log()

    def _ensure_layout(self) -> None:
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        if not self.entries_path.exists():
            self.entries_path.write_text("", encoding="utf-8")

    def _load_or_create_epoch(self) -> str:
        if self.epoch_path.exists():
            try:
                data = json.loads(self.epoch_path.read_text(encoding="utf-8"))
                epoch = str(data.get("epoch") or "").strip()
                if epoch:
                    return epoch
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        epoch = uuid.uuid4().hex[:12]
        self.epoch_path.write_text(
            json.dumps({"epoch": epoch, "started_at": _utc_now()}, indent=2) + "\n",
            encoding="utf-8",
        )
        return epoch

    def _load_index_from_log(self) -> None:
        self._entries_by_id.clear()
        self._first_wins.clear()
        for entry in self._read_entries_from_disk():
            self._entries_by_id[entry.id] = entry
            if entry.epoch != self._epoch:
                continue
            if entry.rel not in self._first_wins:
                self._first_wins[entry.rel] = entry.id

    @property
    def epoch(self) -> str:
        return self._epoch

    def begin_epoch(self) -> str:
        """Start a new journaling epoch (clears first-wins; keeps blobs)."""
        with self._lock:
            self._epoch = uuid.uuid4().hex[:12]
            self.epoch_path.write_text(
                json.dumps({"epoch": self._epoch, "started_at": _utc_now()}, indent=2) + "\n",
                encoding="utf-8",
            )
            self._first_wins.clear()
            return self._epoch

    def rel_of(self, path: Path) -> str | None:
        try:
            return path.resolve().relative_to(self.repo_root).as_posix()
        except ValueError:
            return None

    def safe_repo_path(self, rel: str) -> Path:
        """Resolve *rel* under the repo, rejecting absolute paths and ``..`` escapes."""
        if not rel or rel.startswith("/") or rel.startswith("\\"):
            raise ValueError(f"unsafe journal rel (absolute): {rel!r}")
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"unsafe journal rel: {rel!r}")
        target = (self.repo_root / candidate).resolve()
        try:
            target.relative_to(self.repo_root)
        except ValueError as e:
            raise ValueError(f"journal path escapes repo: {rel!r}") from e
        return target

    def capture(self, path: Path) -> JournalEntry | None:
        """Record preimage for *path* if none exists yet in this epoch.

        - Existing file → ``kind=modify`` with content blob.
        - Missing file → ``kind=create`` (restore deletes the path).
        - Already captured for this rel in epoch → return existing entry (idempotent).
        - Paths outside repo or under ``.deadpush/`` → skipped (``None``).
        """
        with self._lock:
            rel = self.rel_of(path)
            if rel is None:
                return None
            if _is_journal_internal(rel):
                return None
            existing_id = self._first_wins.get(rel)
            if existing_id is not None:
                entry = self._entries_by_id.get(existing_id)
                if entry is not None:
                    return entry
                # Stale index: entry id remembered but missing from log/index.
                # Drop the mapping so we can re-capture rather than return None forever.
                logger.warning(
                    "stale first-wins id %s for %s; re-capturing preimage",
                    existing_id,
                    rel,
                )
                del self._first_wins[rel]

            try:
                resolved = self.safe_repo_path(rel)
            except ValueError:
                return None
            if resolved.exists() and resolved.is_file():
                try:
                    data = resolved.read_bytes()
                    st = resolved.stat()
                except OSError as e:
                    logger.debug("journal capture failed for %s: %s", rel, e)
                    return None
                digest = hashlib.sha256(data).hexdigest()
                self._write_blob(digest, data)
                entry = JournalEntry(
                    id=_new_entry_id(),
                    ts=_utc_now(),
                    rel=rel,
                    kind="modify",
                    sha256=digest,
                    size=len(data),
                    mtime_ns=getattr(st, "st_mtime_ns", None),
                    epoch=self._epoch,
                )
            elif resolved.exists():
                # Directories / special files are out of scope for Phase 1.
                return None
            else:
                entry = JournalEntry(
                    id=_new_entry_id(),
                    ts=_utc_now(),
                    rel=rel,
                    kind="create",
                    sha256=None,
                    size=0,
                    mtime_ns=None,
                    epoch=self._epoch,
                )

            self._append_entry(entry)
            self._first_wins[rel] = entry.id
            return entry

    def capture_many(self, paths: Iterable[Path]) -> list[JournalEntry]:
        out: list[JournalEntry] = []
        for path in paths:
            entry = self.capture(path)
            if entry is not None:
                out.append(entry)
        return out

    def get_entry(self, entry_id: str) -> JournalEntry | None:
        with self._lock:
            return self._entries_by_id.get(entry_id)

    def iter_entries(self) -> Iterator[JournalEntry]:
        """Iterate a snapshot of entries (safe under concurrent capture)."""
        with self._lock:
            if self._entries_by_id:
                snapshot = list(self._entries_by_id.values())
            else:
                snapshot = self._read_entries_from_disk()
        return iter(snapshot)

    def _read_entries_from_disk(self) -> list[JournalEntry]:
        if not self.entries_path.exists():
            return []
        try:
            lines = self.entries_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: list[JournalEntry] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(JournalEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
        return out

    def list_entries(self, *, epoch: str | None = None) -> list[JournalEntry]:
        with self._lock:
            want = epoch if epoch is not None else self._epoch
            if self._entries_by_id:
                entries = list(self._entries_by_id.values())
            else:
                entries = self._read_entries_from_disk()
        return [e for e in entries if e.epoch == want]

    def restore(self, rel: str, *, entry_id: str | None = None) -> Path:
        """Restore *rel* from its first-wins (or specified) journal entry.

        ``kind=modify`` writes the blob back; ``kind=create`` removes the path
        if present (undo an agent-created file).

        First-wins is strict: a missing indexed entry raises rather than falling
        back to a later (possibly mutated) preimage.
        """
        with self._lock:
            entry = self._lookup_restore_entry(rel, entry_id=entry_id)
            return self._restore_entry_unlocked(entry)

    def restore_all(self, *, epoch: str | None = None) -> list[Path]:
        """Restore every first-wins path in the epoch (create entries last).

        Two-phase: validate every entry (safe path + blob present) before writing
        any file, so a failure does not leave a partially-restored tree.
        """
        with self._lock:
            entries = [e for e in self._entries_by_id.values() if e.epoch == (epoch or self._epoch)]
            by_rel: dict[str, JournalEntry] = {}
            for e in entries:
                by_rel.setdefault(e.rel, e)
            ordered = sorted(
                by_rel.values(),
                key=lambda e: (0 if e.kind == "modify" else 1, e.rel),
            )

            prepared: list[tuple[JournalEntry, Path, bytes | None]] = []
            errors: list[str] = []
            for e in ordered:
                try:
                    target = self.safe_repo_path(e.rel)
                    if e.kind == "create":
                        prepared.append((e, target, None))
                        continue
                    if not e.sha256:
                        raise ValueError(f"modify entry {e.id} missing sha256")
                    blob = self.blobs_dir / e.sha256
                    if not blob.is_file():
                        raise FileNotFoundError(f"missing journal blob {e.sha256}")
                    prepared.append((e, target, blob.read_bytes()))
                except (ValueError, FileNotFoundError, OSError) as err:
                    errors.append(f"{e.rel}: {err}")

            if errors:
                raise FileNotFoundError(
                    "restore_all preflight failed; no files written:\n"
                    + "\n".join(errors)
                )

            restored: list[Path] = []
            for e, target, data in prepared:
                if e.kind == "create":
                    if target.exists() and target.is_file():
                        target.unlink()
                    restored.append(target)
                    continue
                assert data is not None
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_name(target.name + f".deadpush-journal-tmp-{os.getpid()}")
                try:
                    tmp.write_bytes(data)
                    tmp.replace(target)
                finally:
                    if tmp.exists():
                        try:
                            tmp.unlink()
                        except OSError:
                            pass
                restored.append(target)
            return restored

    def _lookup_restore_entry(self, rel: str, *, entry_id: str | None) -> JournalEntry:
        if entry_id is not None:
            entry = self._entries_by_id.get(entry_id)
            if entry is None:
                raise FileNotFoundError(f"no journal entry id {entry_id!r}")
            return entry

        eid = self._first_wins.get(rel)
        if eid is None:
            raise FileNotFoundError(f"no journal entry for {rel!r}")
        entry = self._entries_by_id.get(eid)
        if entry is None:
            # Do not fall back to "latest" — that would violate first-wins WAL semantics.
            raise FileNotFoundError(
                f"first-wins entry missing for {rel!r} (id={eid}); "
                "journal may be truncated — refusing to restore a later preimage"
            )
        return entry

    def _restore_entry_unlocked(self, entry: JournalEntry) -> Path:
        target = self.safe_repo_path(entry.rel)
        if entry.kind == "create":
            if target.exists() and target.is_file():
                target.unlink()
            return target

        if not entry.sha256:
            raise ValueError(f"modify entry {entry.id} missing sha256")
        blob = self.blobs_dir / entry.sha256
        if not blob.is_file():
            raise FileNotFoundError(f"missing journal blob {entry.sha256}")
        target.parent.mkdir(parents=True, exist_ok=True)
        data = blob.read_bytes()
        tmp = target.with_name(target.name + f".deadpush-journal-tmp-{os.getpid()}")
        try:
            tmp.write_bytes(data)
            tmp.replace(target)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
        return target

    def _write_blob(self, digest: str, data: bytes) -> Path:
        dest = self.blobs_dir / digest
        if dest.exists():
            return dest
        tmp = self.blobs_dir / f".tmp-{digest}-{os.getpid()}"
        try:
            tmp.write_bytes(data)
            tmp.replace(dest)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
        return dest

    def _append_entry(self, entry: JournalEntry) -> None:
        line = json.dumps(entry.to_dict(), separators=(",", ":")) + "\n"
        with self.entries_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
        self._entries_by_id[entry.id] = entry


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _new_entry_id() -> str:
    # time-sortable-ish id for debugging
    return f"{int(time.time() * 1000):x}-{uuid.uuid4().hex[:8]}"


def _is_journal_internal(rel: str) -> bool:
    parts = rel.split("/")
    if not parts:
        return True
    if parts[0] in {
        ".deadpush",
        ".deadpush-quarantine",
        ".deadpush-archive",
        ".deadpush-config-backups",
        ".git",
    }:
        return True
    return False
