"""Quarantine storage for dangerous files blocked by the guardian."""

from __future__ import annotations

import errno
import logging
import os
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path

class QuarantineManager:
    """Moves dangerous files to a quarantine folder instead of deleting them."""

    def __init__(self, base_dir: Path):
        self.quarantine_dir = base_dir / ".deadpush-quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("deadpush.guardian")
        self._lock = threading.Lock()

    def _unique_dest(self, basename: str, timestamp: str) -> Path:
        dest = self.quarantine_dir / f"{timestamp}_{basename}"
        if not dest.exists():
            return dest
        return self.quarantine_dir / f"{timestamp}_{os.getpid()}_{basename}"

    def _write_reason(self, dest: Path, reason: str, original: Path) -> None:
        reason_path = dest.with_suffix(dest.suffix + ".reason")
        reason_path.write_text(
            f"Quarantined at {datetime.now()}\nReason: {reason}\nOriginal path: {original}\n",
            encoding="utf-8",
        )

    def quarantine(self, path: Path, reason: str) -> Path:
        """Move a dangerous file out of the live tree as quickly as possible.

        Prefer same-filesystem ``rename`` so the live path disappears immediately
        (shrinks the H-04 post-decision window). Fall back to copy+unlink when
        rename is unavailable (cross-device, busy handles, etc.).
        """
        with self._lock:
            if not path.exists():
                return path

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = self._unique_dest(path.name, timestamp)
            retry_errnos = {errno.EBUSY, errno.EACCES, errno.EPERM}

            # Fast path: atomic rename removes bad content from the live path
            # in one syscall (no copy-then-unlink race).
            try:
                path.rename(dest)
            except OSError:
                pass
            else:
                # Live path is already gone — never fall through to copy+unlink.
                try:
                    self._write_reason(dest, reason, path)
                except OSError as e:
                    self.logger.warning(
                        "Quarantined %s to %s but failed to write reason file: %s",
                        path,
                        dest,
                        e,
                    )
                return dest

            for attempt in range(4):
                try:
                    shutil.copy2(path, dest)
                except OSError as e:
                    if e.errno in retry_errnos and attempt < 3:
                        time.sleep(0.05 * (attempt + 1))
                        continue
                    break

                try:
                    self._write_reason(dest, reason, path)
                except OSError as e:
                    self.logger.warning(
                        "Copied %s to %s but failed to write reason file: %s",
                        path,
                        dest,
                        e,
                    )

                try:
                    path.unlink()
                except OSError as unlink_err:
                    if unlink_err.errno in retry_errnos:
                        time.sleep(0.05 * (attempt + 1))
                        if not path.exists():
                            return dest
                        continue
                    try:
                        path.write_text("", encoding="utf-8")
                    except OSError:
                        pass
                return dest

            self.logger.error(f"Failed to quarantine {path}")
            if dest.exists() and not path.exists():
                return dest
            return path

    def list_quarantined(self):
        """Return list of dicts with info about quarantined files (newest first)."""
        with self._lock:
            entries = []
            if not self.quarantine_dir.exists():
                return entries
            for f in sorted(self.quarantine_dir.iterdir(), reverse=True):
                if f.name.endswith(".reason"):
                    continue
                reason_path = self.quarantine_dir / (f.name + ".reason")
                info = {
                    "quarantined_file": f,
                    "name": f.name,
                    "size": f.stat().st_size if f.exists() else 0,
                    "mtime": datetime.fromtimestamp(f.stat().st_mtime) if f.exists() else None,
                }
                if reason_path.exists():
                    try:
                        text = reason_path.read_text(errors="ignore")
                        for line in text.splitlines():
                            if line.startswith("Quarantined at "):
                                info["quarantined_at"] = line.split("Quarantined at ", 1)[1]
                            elif line.startswith("Reason: "):
                                info["reason"] = line.split("Reason: ", 1)[1]
                            elif line.startswith("Original path: "):
                                info["original_path"] = line.split("Original path: ", 1)[1]
                    except Exception:
                        pass
                entries.append(info)
            return entries

    def restore(self, quarantined_name_or_path: str) -> Path | None:
        """Restore a quarantined file back to its original location if possible.
        Returns the restored path or None on failure.
        """
        with self._lock:
            qpath = Path(quarantined_name_or_path)
            if not qpath.is_absolute():
                qpath = self.quarantine_dir / qpath.name
            if not qpath.exists() or qpath.name.endswith(".reason"):
                # try finding by name
                candidates = list(self.quarantine_dir.glob(f"*{Path(quarantined_name_or_path).name}*"))
                qpath = next((c for c in candidates if not c.name.endswith(".reason")), None)
                if not qpath:
                    return None
            reason_path = self.quarantine_dir / (qpath.name + ".reason")
            original = None
            if reason_path.exists():
                try:
                    for line in reason_path.read_text(errors="ignore").splitlines():
                        if line.startswith("Original path: "):
                            original = Path(line.split("Original path: ", 1)[1].strip())
                            break
                except Exception:
                    pass

            if not original:
                # fallback: strip timestamp_ prefix
                name = qpath.name
                if "_" in name and name.split("_", 1)[0].isdigit():
                    original = self.quarantine_dir.parent / name.split("_", 1)[1]
                else:
                    original = self.quarantine_dir.parent / name
            # Confine the restore destination to the repo tree. The "Original path"
            # is read from an agent-writable .reason file, so without this a crafted
            # .reason could make the guardian (running as _deadpush in hardened mode)
            # move a file to an arbitrary absolute path — a confused-deputy write.
            repo_root = self.quarantine_dir.parent
            try:
                resolved = original.resolve()
                resolved.relative_to(repo_root.resolve())
            except (ValueError, OSError, RuntimeError):
                logging.getLogger("deadpush.guardian").warning(
                    f"Refusing to restore outside the repo: {original}")
                return None
            original = resolved
            if original.exists():
                logging.getLogger("deadpush.guardian").warning(f"Refusing to restore: original already exists at {original}")
                return None
            try:
                original.parent.mkdir(parents=True, exist_ok=True)
                qpath.rename(original)
                if reason_path.exists():
                    reason_path.unlink()
                logging.getLogger("deadpush.guardian").info(f"Restored {qpath.name} -> {original}")
                return original
            except Exception as e:
                logging.getLogger("deadpush.guardian").error(f"Restore failed for {qpath}: {e}")
                return None

    def clear(self, older_than_days: int | None = None) -> int:
        """Delete quarantined files (and their .reason). Returns count deleted.
        If older_than_days, only those older than N days.
        """
        with self._lock:
            count = 0
            if not self.quarantine_dir.exists():
                return 0
            now = datetime.now()
            for f in list(self.quarantine_dir.iterdir()):
                if f.name.endswith(".reason"):
                    # will be handled with main file or orphaned cleanup
                    try:
                        if older_than_days is None:
                            f.unlink()
                        else:
                            mtime = datetime.fromtimestamp(f.stat().st_mtime)
                            if (now - mtime).days >= older_than_days:
                                f.unlink()
                                count += 1
                        continue
                    except Exception:
                        continue
                # main file
                try:
                    if older_than_days is not None:
                        mtime = datetime.fromtimestamp(f.stat().st_mtime)
                        if (now - mtime).days < older_than_days:
                            continue
                    f.unlink()
                    count += 1
                    rp = self.quarantine_dir / (f.name + ".reason")
                    if rp.exists():
                        rp.unlink()
                except Exception as e:
                    logging.getLogger("deadpush.guardian").error(f"Failed clearing {f}: {e}")
            return count
