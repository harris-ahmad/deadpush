"""Tests for daemon-kill detection and 'installed but not running' visibility.

Soft mode cannot prevent a same-UID `pkill`, but it must make a kill loud instead of
silent: a clean stop removes the PID file, so a stale PID file with no live process
means the guardian was killed/crashed, and `status`/`doctor` say so distinctly.
"""

from __future__ import annotations

import sys
from pathlib import Path

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import deadpush.guard as guard  # noqa: E402
from deadpush import config as dp_config  # noqa: E402
from deadpush.cli import main  # noqa: E402


class TestKilledUncleanly:
    def test_stale_pidfile_with_dead_process_is_flagged(self, temp_repo: Path, monkeypatch):
        pidfile = temp_repo / "guardian.pid"
        monkeypatch.setattr(guard, "_scoped_pidfile", lambda r, h=False: pidfile)

        # No pidfile yet -> not "killed", just not running.
        assert guard.guardian_killed_uncleanly(temp_repo) is False

        # A leftover pidfile pointing at a dead PID = an unclean kill/crash.
        pidfile.write_text("999999")
        assert guard.guardian_is_running(temp_repo) is False
        assert guard.guardian_killed_uncleanly(temp_repo) is True

    def test_clean_state_is_not_flagged(self, temp_repo: Path, monkeypatch):
        pidfile = temp_repo / "guardian.pid"
        monkeypatch.setattr(guard, "_scoped_pidfile", lambda r, h=False: pidfile)
        # No pidfile (clean stop removes it) -> not flagged as killed.
        assert guard.guardian_killed_uncleanly(temp_repo) is False


class TestPersistenceInstalled:
    def test_marker_makes_it_installed(self, temp_repo: Path):
        assert guard.guardian_persistence_installed(temp_repo) is False
        dp_config.write_install_marker(temp_repo)
        assert guard.guardian_persistence_installed(temp_repo) is True


class TestStatusReporting:
    def test_status_reports_killed_guardian(self, temp_repo: Path, monkeypatch):
        monkeypatch.setattr(guard, "guardian_is_running", lambda r, hardened=False: False)
        monkeypatch.setattr(guard, "guardian_killed_uncleanly", lambda r, hardened=False: True)
        monkeypatch.setattr(guard, "guardian_persistence_installed", lambda r, hardened=False: True)

        result = CliRunner().invoke(main, ["status", "--repo", str(temp_repo)])
        assert "KILLED" in result.output or "stale PID" in result.output

    def test_status_reports_installed_but_not_running(self, temp_repo: Path, monkeypatch):
        monkeypatch.setattr(guard, "guardian_is_running", lambda r, hardened=False: False)
        monkeypatch.setattr(guard, "guardian_killed_uncleanly", lambda r, hardened=False: False)
        monkeypatch.setattr(guard, "guardian_persistence_installed", lambda r, hardened=False: True)

        result = CliRunner().invoke(main, ["status", "--repo", str(temp_repo)])
        assert "INSTALLED but NOT running" in result.output
