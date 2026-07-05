"""Tests for fanotify integration in the always-on guardian daemon (Slice C)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deadpush.config import Config
from deadpush.guard import GuardianHandler


@pytest.fixture
def guardian(temp_repo: Path) -> GuardianHandler:
    config = Config(repo_root=temp_repo)
    return GuardianHandler(config, intervention=True, daemon=False, enable_fanotify=True)


class TestFanotifyDenyHandler:
    def test_handle_fanotify_deny_records_incident_and_feedback(
        self, guardian: GuardianHandler, temp_repo: Path,
    ):
        guardian._handle_fanotify_deny("evil.py", "eval() blocked", "fanotify")

        assert guardian.safety_score.score < 100
        feedback_dir = temp_repo / ".deadpush" / "feedback"
        assert feedback_dir.exists()
        assert any(f.name.endswith(".json") for f in feedback_dir.glob("*.json"))

    def test_handle_fanotify_deny_emits_gpc(self, guardian: GuardianHandler):
        gpc = MagicMock()
        guardian.gpc = gpc

        guardian._handle_fanotify_deny("bad.py", "secret detected", "fanotify")

        gpc.emit_incident.assert_called_once()
        assert gpc.emit_incident.call_args.kwargs["category"] == "fanotify"


class TestFanotifyLifecycle:
    def test_start_fanotify_noop_off_linux(self, guardian: GuardianHandler):
        if sys.platform.startswith("linux"):
            pytest.skip("non-Linux only")
        guardian._start_fanotify()
        assert guardian._fanotify_backend is None

    def test_start_fanotify_skipped_when_disabled(self, guardian: GuardianHandler):
        guardian.enable_fanotify = False
        guardian._start_fanotify()
        assert guardian._fanotify_backend is None

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
    def test_start_fanotify_attaches_backend_when_available(self, guardian: GuardianHandler):
        mock_backend = MagicMock()
        mock_backend.available.return_value = True
        with patch("deadpush.backends.linux.LinuxEnforcementBackend", return_value=mock_backend):
            guardian._start_fanotify()
        mock_backend.start.assert_called_once()
        assert guardian._fanotify_backend is mock_backend

    def test_stop_fanotify_clears_backend(self, guardian: GuardianHandler):
        mock_backend = MagicMock()
        guardian._fanotify_backend = mock_backend
        guardian._stop_fanotify()
        mock_backend.stop.assert_called_once()
        assert guardian._fanotify_backend is None

    def test_fanotify_status_none_when_inactive(self, guardian: GuardianHandler):
        assert guardian.fanotify_status() is None

    def test_fanotify_status_describes_backend(self, guardian: GuardianHandler):
        mock_backend = MagicMock()
        mock_backend.describe.return_value = {"name": "linux-fanotify", "started": True}
        guardian._fanotify_backend = mock_backend
        assert guardian.fanotify_status()["name"] == "linux-fanotify"
