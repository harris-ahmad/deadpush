"""H-04 race-window shrink: stability budget, rename-first quarantine, autostart flags."""

from __future__ import annotations

import errno
import logging
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from deadpush import guard as guard_mod
from deadpush import state
from deadpush.config import Config
from deadpush.guard import GuardianHandler, QuarantineManager, setup_autostart


@pytest.fixture
def autostart_env(tmp_path, monkeypatch):
    """Redirect autostart unit paths into tmp so tests do not litter ~/Library."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    monkeypatch.setattr(state, "HARDENED_STATE_DIR", state_dir)
    monkeypatch.setattr(
        state, "state_dir", lambda hardened=False: state_dir if hardened else Path.home() / ".deadpush"
    )
    state.reset_migration_flags()
    monkeypatch.setattr(guard_mod, "_state_dir", lambda hardened=False: state.state_dir(hardened))
    rid_fn = guard_mod._repo_id
    if sys.platform == "darwin":
        monkeypatch.setattr(
            guard_mod,
            "_scoped_plist_path",
            lambda r, hardened=False: state_dir / f"com.deadpush.guardian.{rid_fn(str(r))}.plist",
        )
    elif sys.platform.startswith("linux"):
        monkeypatch.setattr(
            guard_mod,
            "_scoped_systemd_unit_path",
            lambda r, hardened=False: state_dir / f"deadpush-guardian.{rid_fn(str(r))}.service",
        )
    return state_dir


def test_stability_budget_is_sub_quarter_second():
    assert GuardianHandler.STABILITY_SECONDS <= 0.10
    assert GuardianHandler.STABILITY_POLL <= 0.02


def test_is_stable_returns_within_budget_for_finished_file(temp_repo: Path):
    handler = GuardianHandler(Config(repo_root=temp_repo), intervention=False, daemon=False)
    target = temp_repo / "done.txt"
    target.write_text("stable\n", encoding="utf-8")

    t0 = time.perf_counter()
    assert handler._is_stable(target, required=handler.STABILITY_SECONDS) is True
    elapsed = time.perf_counter() - t0

    # Allow a little scheduling slack above the configured wait.
    assert elapsed < handler.STABILITY_SECONDS + 0.25


def test_moved_events_skip_stability_wait(temp_repo: Path):
    handler = GuardianHandler(Config(repo_root=temp_repo), intervention=False, daemon=False)
    target = temp_repo / "renamed.txt"
    target.write_text("x\n", encoding="utf-8")
    assert handler._stability_required(target, "moved") == 0.0
    assert handler._is_stable(target, required=0.0) is True


def test_quarantine_rename_first_clears_live_path_immediately(temp_repo: Path):
    target = temp_repo / "live_evil.py"
    payload = "eval('x')\n"
    target.write_text(payload, encoding="utf-8")
    qm = QuarantineManager(temp_repo)

    dest = qm.quarantine(target, "h04")
    assert not target.exists()
    assert dest.read_text(encoding="utf-8") == payload


def test_quarantine_reason_write_failure_does_not_claim_failed(temp_repo: Path, caplog):
    target = temp_repo / "evil2.py"
    target.write_text("eval('x')\n", encoding="utf-8")
    qm = QuarantineManager(temp_repo)

    def boom(_dest, _reason, _original):
        raise OSError(errno.ENOSPC, "No space left on device")

    with caplog.at_level(logging.WARNING):
        with patch.object(qm, "_write_reason", side_effect=boom):
            dest = qm.quarantine(target, "disk full reason")

    assert not target.exists()
    assert dest.exists()
    assert not any("Failed to quarantine" in r.message for r in caplog.records)
    assert any("failed to write reason file" in r.message.lower() for r in caplog.records)


def test_is_stable_false_when_file_keeps_changing(temp_repo: Path, monkeypatch):
    handler = GuardianHandler(Config(repo_root=temp_repo), intervention=False, daemon=False)
    target = temp_repo / "growing.bin"
    target.write_bytes(b"x")

    original_sleep = time.sleep

    def bump_then_sleep(dt):
        target.write_bytes(target.read_bytes() + b"y")
        original_sleep(min(dt, 0.005))

    monkeypatch.setattr(time, "sleep", bump_then_sleep)
    assert handler._is_stable(target, timeout=0.08, required=0.05) is False


@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="autostart units only on darwin/linux",
)
def test_setup_autostart_embeds_no_fanotify(tmp_path: Path, autostart_env):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    setup_autostart(repo, hardened=False, enable_fanotify=False)
    if sys.platform == "darwin":
        text = guard_mod._scoped_plist_path(repo, False).read_text(encoding="utf-8")
    else:
        text = guard_mod._scoped_systemd_unit_path(repo, False).read_text(encoding="utf-8")
    assert "--no-fanotify" in text
