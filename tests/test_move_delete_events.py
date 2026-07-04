"""Tests for real-time mv/rm handling in the guardian (D3).

The watchdog handler previously implemented only on_created/on_modified, so an
agent could evade the real-time layer by moving un-scanned content into place
(`mv node_modules/x ./evil.py`) or renaming onto a dangerous path. on_moved now
evaluates the destination like a fresh write; on_deleted records forensic
telemetry without punishing the safety score (which never recovers).

These exercise the handler methods directly with lightweight fakes so they stay
deterministic (no real observer/daemon timing).
"""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.guard import GuardianHandler  # noqa: E402


# ---------------------------------------------------------------------------
# on_moved — the destination is evaluated like a fresh write
# ---------------------------------------------------------------------------
class TestOnMoved:
    def test_move_evaluates_destination(self):
        fake = types.SimpleNamespace(_evaluate=Mock())
        ev = types.SimpleNamespace(is_directory=False, src_path="/repo/a.txt",
                                   dest_path="/repo/evil.py")
        GuardianHandler.on_moved(fake, ev)
        fake._evaluate.assert_called_once()
        (path_arg,), kwargs = fake._evaluate.call_args
        assert path_arg == Path("/repo/evil.py")
        assert kwargs.get("event_type") == "moved"

    def test_directory_move_ignored(self):
        fake = types.SimpleNamespace(_evaluate=Mock())
        ev = types.SimpleNamespace(is_directory=True, src_path="/repo/a",
                                   dest_path="/repo/b")
        GuardianHandler.on_moved(fake, ev)
        fake._evaluate.assert_not_called()

    def test_missing_dest_ignored(self):
        fake = types.SimpleNamespace(_evaluate=Mock())
        ev = types.SimpleNamespace(is_directory=False, src_path="/repo/a", dest_path=None)
        GuardianHandler.on_moved(fake, ev)
        fake._evaluate.assert_not_called()


# ---------------------------------------------------------------------------
# on_deleted — forensic telemetry only, no safety-score change
# ---------------------------------------------------------------------------
class TestOnDeleted:
    def test_delete_routes_to_handler(self):
        fake = types.SimpleNamespace(_handle_deletion=Mock())
        ev = types.SimpleNamespace(is_directory=False, src_path="/repo/gone.py")
        GuardianHandler.on_deleted(fake, ev)
        fake._handle_deletion.assert_called_once_with(Path("/repo/gone.py"))

    def test_directory_delete_ignored(self):
        fake = types.SimpleNamespace(_handle_deletion=Mock())
        ev = types.SimpleNamespace(is_directory=True, src_path="/repo/dir")
        GuardianHandler.on_deleted(fake, ev)
        fake._handle_deletion.assert_not_called()


class TestHandleDeletion:
    def _fake(self, repo_root: Path):
        recorded: list[dict] = []
        fake = types.SimpleNamespace(
            config=types.SimpleNamespace(repo_root=repo_root),
            logger=logging.getLogger("deadpush.test"),
            session_mgr=types.SimpleNamespace(record_incident=recorded.append),
            _looks_transient=GuardianHandler._looks_transient,
        )
        return fake, recorded

    def test_real_deletion_records_incident(self, tmp_path):
        fake, recorded = self._fake(tmp_path)
        GuardianHandler._handle_deletion(fake, tmp_path / "src" / "app.py")
        assert recorded == [{"type": "file_deleted", "file": "src/app.py"}]

    def test_transient_deletion_ignored(self, tmp_path):
        fake, recorded = self._fake(tmp_path)
        for name in ("app.py.tmp", "notes~", ".app.py.swp", "4913", ".DS_Store"):
            GuardianHandler._handle_deletion(fake, tmp_path / name)
        assert recorded == []

    def test_skipped_dir_deletion_ignored(self, tmp_path):
        fake, recorded = self._fake(tmp_path)
        for p in (tmp_path / ".git" / "HEAD",
                  tmp_path / "node_modules" / "x.js",
                  tmp_path / ".deadpush" / "rules.json"):
            GuardianHandler._handle_deletion(fake, p)
        assert recorded == []

    def test_outside_repo_deletion_ignored(self, tmp_path):
        fake, recorded = self._fake(tmp_path)
        GuardianHandler._handle_deletion(fake, Path("/etc/hosts"))
        assert recorded == []


class TestLooksTransient:
    def test_transient_names(self):
        for n in ("x.tmp", "X.TEMP", "a.swp", "b.swo", "c.swx",
                  "foo~", "bar.bak", "baz.orig", "4913", ".DS_Store",
                  ".#lockfile", "~$doc.docx"):
            assert GuardianHandler._looks_transient(n) is True, n

    def test_real_names(self):
        for n in ("app.py", "Dockerfile", ".env", "config.yaml", "README.md"):
            assert GuardianHandler._looks_transient(n) is False, n
