"""Validated save points for recoverability (thesis Phase 2).

A save point is a milestone snapshot of repo file contents (content-addressed
blobs shared with ``JournalStore``). Restore rolls the live tree back to that
snapshot — answering \"how far do I need to go\" (docs/openai-features.md).

After creating a save point we also begin a fresh journal epoch and seed
preimages from the snapshot so subsequent mutations have a WAL baseline.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .journal import JournalStore, is_journal_internal

logger = logging.getLogger("deadpush.savepoints")

SAVEPOINTS_DIRNAME = "savepoints"

_SKIP_DIR_NAMES = {
    "__pycache__",
    ".git",
    "node_modules",
    ".deadpush",
    ".deadpush-quarantine",
    ".deadpush-archive",
    ".deadpush-config-backups",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}

# Thesis validation stub: reject trees that clearly embed secret material.
_SECRET_NAME_RE = re.compile(r"(^\.env($|\.)|credentials\.json$|secrets?\.(json|ya?ml|toml)$)", re.I)
_SECRET_BODY_RE = re.compile(
    r"(API[_-]?KEY|SECRET[_-]?KEY|BEGIN (RSA |OPENSSH )?PRIVATE KEY|sk-[A-Za-z0-9]{20,})",
    re.I,
)


@dataclass(frozen=True)
class SavePoint:
    id: str
    ts: str
    label: str
    validated: bool
    validation_errors: tuple[str, ...] = ()
    files: dict[str, str] = field(default_factory=dict)  # rel -> sha256
    epoch: str = ""

    @property
    def file_count(self) -> int:
        return len(self.files)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["validation_errors"] = list(self.validation_errors)
        d["file_count"] = self.file_count
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SavePoint:
        files = {str(k): str(v) for k, v in (data.get("files") or {}).items()}
        errs = tuple(str(e) for e in (data.get("validation_errors") or ()))
        return cls(
            id=str(data["id"]),
            ts=str(data["ts"]),
            label=str(data.get("label") or ""),
            validated=bool(data.get("validated", False)),
            validation_errors=errs,
            files=files,
            epoch=str(data.get("epoch") or ""),
        )


@dataclass(frozen=True)
class RestoreResult:
    savepoint_id: str
    restored: tuple[str, ...]
    removed: tuple[str, ...] = ()
    missing_blobs: tuple[str, ...] = ()


class SavePointStore:
    """Milestone snapshots under ``<repo>/.deadpush/journal/savepoints/``."""

    def __init__(self, repo_root: Path, journal: JournalStore | None = None):
        self.repo_root = repo_root.resolve()
        self.journal = journal or JournalStore(self.repo_root)
        self.root = self.journal.root / SAVEPOINTS_DIRNAME
        self.root.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        label: str = "",
        *,
        validate: bool = True,
        seed_journal: bool = True,
        paths: Iterable[Path] | None = None,
    ) -> SavePoint:
        """Snapshot current files; optionally validate and seed the journal epoch."""
        file_map: dict[str, str] = {}
        for path in paths if paths is not None else iter_snapshot_files(self.repo_root):
            rel = self.journal.rel_of(path)
            if rel is None or is_journal_internal(rel):
                continue
            if not path.is_file():
                continue
            try:
                data = path.read_bytes()
            except OSError as e:
                logger.debug("savepoint skip %s: %s", rel, e)
                continue
            digest = self.journal.store_bytes(data)
            file_map[rel] = digest

        errors: list[str] = []
        if validate:
            errors = validate_working_tree(self.repo_root)

        sp_id = uuid.uuid4().hex[:12]
        epoch = ""
        if seed_journal:
            # Atomic with seeding: snapshot digests become first-wins, not a
            # racy re-read of live disk between begin_epoch and capture.
            epoch = self.journal.begin_epoch_seeded(file_map)

        sp = SavePoint(
            id=sp_id,
            ts=_utc_now(),
            label=label,
            validated=not errors,
            validation_errors=tuple(errors),
            files=file_map,
            epoch=epoch,
        )
        self._write(sp)
        logger.info(
            "savepoint %s created (%s files, validated=%s)",
            sp.id,
            sp.file_count,
            sp.validated,
        )
        return sp

    def list(self) -> list[SavePoint]:
        points = [self._read(p) for p in sorted(self.root.glob("sp_*.json"))]
        return [p for p in points if p is not None]

    def get(self, savepoint_id: str) -> SavePoint | None:
        path = self.root / f"sp_{savepoint_id}.json"
        if path.is_file():
            return self._read(path)
        # Allow prefix match for short ids typed by humans.
        matches = [p for p in self.list() if p.id.startswith(savepoint_id)]
        if len(matches) == 1:
            return matches[0]
        return None

    def latest_validated(self) -> SavePoint | None:
        validated = [p for p in self.list() if p.validated]
        if not validated:
            return None
        return max(validated, key=lambda p: _parse_ts(p.ts))

    def restore(self, savepoint_id: str) -> RestoreResult:
        """Roll the live tree back to *savepoint_id*.

        Two-phase like ``JournalStore.restore_all``: resolve paths and load every
        available blob before writing anything, so a preflight I/O failure leaves
        the tree untouched. Missing blobs are soft-reported; other load errors
        propagate before mutation.
        """
        sp = self.get(savepoint_id)
        if sp is None:
            raise FileNotFoundError(f"savepoint not found: {savepoint_id}")

        # Phase 1: validate paths + load blobs (no tree mutation yet).
        missing: list[str] = []
        prepared: list[tuple[str, Path, str, bytes]] = []
        for rel, digest in sorted(sp.files.items()):
            try:
                target = self.journal.safe_repo_path(rel)
            except ValueError as e:
                raise ValueError(f"unsafe savepoint path {rel!r}: {e}") from e
            try:
                data = self.journal.load_bytes(digest)
            except FileNotFoundError:
                missing.append(rel)
                continue
            prepared.append((rel, target, digest, data))

        # Snapshot had files but every blob failed to load: leave the live tree
        # and journal epoch alone (do not prune extras or wipe first-wins).
        # An empty snapshot (sp.files == {}) is intentional and still cleans up.
        if sp.files and not prepared:
            return RestoreResult(
                savepoint_id=sp.id,
                restored=(),
                removed=(),
                missing_blobs=tuple(missing),
            )

        # Phase 2: write prepared files, then prune extras and reseed the journal.
        restored: list[str] = []
        restored_preimages: dict[str, str] = {}
        for rel, target, digest, data in prepared:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + f".deadpush-sp-tmp-{sp.id}")
            try:
                tmp.write_bytes(data)
                tmp.replace(target)
            finally:
                if tmp.exists():
                    try:
                        tmp.unlink()
                    except OSError:
                        pass
            restored.append(rel)
            restored_preimages[rel] = digest

        removed = self._remove_files_absent_from(sp.files)

        # Prefer a clean journal epoch after restore so new mutations start fresh.
        self.journal.begin_epoch_seeded(restored_preimages)

        return RestoreResult(
            savepoint_id=sp.id,
            restored=tuple(restored),
            removed=tuple(removed),
            missing_blobs=tuple(missing),
        )

    def _remove_files_absent_from(self, wanted: dict[str, str]) -> list[str]:
        """Delete snapshot-eligible live files that are not in the save point."""
        removed: list[str] = []
        for path in iter_snapshot_files(self.repo_root):
            rel = self.journal.rel_of(path)
            if rel is None or is_journal_internal(rel):
                continue
            if rel in wanted:
                continue
            try:
                path.unlink()
            except OSError as e:
                logger.debug("savepoint restore could not remove %s: %s", rel, e)
                continue
            removed.append(rel)
        return sorted(removed)

    def _write(self, sp: SavePoint) -> Path:
        path = self.root / f"sp_{sp.id}.json"
        path.write_text(json.dumps(sp.to_dict(), indent=2) + "\n", encoding="utf-8")
        return path

    def _read(self, path: Path) -> SavePoint | None:
        try:
            return SavePoint.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.debug("bad savepoint file %s: %s", path, e)
            return None


def iter_snapshot_files(repo_root: Path) -> Iterable[Path]:
    """Yield regular files under *repo_root* suitable for a save-point snapshot."""
    root = repo_root.resolve()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(part in _SKIP_DIR_NAMES for part in rel_parts):
            continue
        yield path


def validate_working_tree(repo_root: Path) -> list[str]:
    """Thesis validation stub: flag secret-like live files.

    A save point is ``validated`` only when this returns an empty list.
    """
    errors: list[str] = []
    root = repo_root.resolve()
    for path in iter_snapshot_files(root):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        name_hit = bool(_SECRET_NAME_RE.search(path.name))
        try:
            # Bound read — enough for stub heuristics.
            sample = path.read_bytes()[:64_000]
        except OSError:
            continue
        try:
            text = sample.decode("utf-8", errors="replace")
        except Exception:
            continue
        body_hit = bool(_SECRET_BODY_RE.search(text))
        if name_hit and body_hit:
            errors.append(f"secret-like content in {rel}")
        elif name_hit and len(text.strip()) > 0:
            # Named like a secrets file with any content — conservative stub.
            errors.append(f"secret-named file present: {rel}")
        elif body_hit and path.suffix in {".env", ".pem", ".key"}:
            errors.append(f"secret-like content in {rel}")
    return errors


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_ts(ts: str) -> datetime:
    """Parse save-point timestamps (ISO-8601, typically ``...Z``)."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)
