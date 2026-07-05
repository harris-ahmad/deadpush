"""Tests for bootstrap allowlist and quarantine hardening (Slice B)."""

from __future__ import annotations

import errno
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.bootstrap import (
    BOOTSTRAP_MANIFEST,
    default_protect_bootstrap_paths,
    is_bootstrap_path,
    record_bootstrap_paths,
)
from deadpush.config import Config
from deadpush.debris import DebrisDetector
from deadpush.guard import GuardianHandler, QuarantineManager
from deadpush.types import FileInfo


class TestBootstrapPaths:
    def test_exact_paths_are_bootstrap(self):
        assert is_bootstrap_path(".github/workflows/deadpush-guard.yml")
        assert is_bootstrap_path(".cursor/rules/deadpush-gpc.mdc")

    def test_protect_ignore_files_are_bootstrap(self):
        assert is_bootstrap_path(".cursorignore")
        assert is_bootstrap_path(".claudeignore")

    def test_deadpush_prefixes_are_bootstrap(self):
        assert is_bootstrap_path(".deadpush/bootstrap_paths.json")
        assert is_bootstrap_path(".deadpush-quarantine/evil.py")

    def test_manifest_paths_are_bootstrap(self, temp_repo: Path):
        record_bootstrap_paths(temp_repo, ["custom/artifact.txt"])
        assert is_bootstrap_path("custom/artifact.txt", temp_repo)

    def test_record_bootstrap_paths_merges(self, temp_repo: Path):
        record_bootstrap_paths(temp_repo, ["a.txt"])
        record_bootstrap_paths(temp_repo, ["b.txt", "a.txt"])
        data = json.loads((temp_repo / BOOTSTRAP_MANIFEST).read_text(encoding="utf-8"))
        assert data["paths"] == ["a.txt", "b.txt"]

    def test_default_protect_paths_include_workflow_and_ignore(self):
        paths = default_protect_bootstrap_paths()
        assert ".github/workflows/deadpush-guard.yml" in paths
        assert ".cursorignore" in paths


@pytest.fixture
def guardian(temp_repo: Path) -> GuardianHandler:
    config = Config(repo_root=temp_repo)
    handler = GuardianHandler(config, intervention=True, daemon=False)
    handler.safety_score.score = 50
    return handler


class TestBootstrapGuardianSkip:
    def test_process_event_skips_cursorignore(self, guardian: GuardianHandler, temp_repo: Path):
        path = temp_repo / ".cursorignore"
        path.write_text(".env\nsecrets/\n")

        guardian._process_event(path, "modified")

        assert path.exists()
        assert not list(guardian.quarantine.quarantine_dir.glob("*cursorignore*"))

    def test_process_event_skips_deadpush_guard_workflow(
        self, guardian: GuardianHandler, temp_repo: Path,
    ):
        path = temp_repo / ".github" / "workflows" / "deadpush-guard.yml"
        path.parent.mkdir(parents=True)
        path.write_text("name: deadpush-guard\non: push\n")

        guardian._process_event(path, "modified")

        assert path.exists()

    def test_lockdown_still_skips_bootstrap_paths(
        self, guardian: GuardianHandler, temp_repo: Path,
    ):
        guardian.safety_score.score = 0
        path = temp_repo / ".cursorignore"
        path.write_text("node_modules/\n")

        guardian._process_event(path, "modified")

        assert path.exists()


class TestDebrisBootstrapSkip:
    def test_scan_skips_cursorignore(self, temp_repo: Path):
        path = temp_repo / ".cursorignore"
        path.write_text("# ignore patterns\n")
        config = Config(repo_root=temp_repo)
        detector = DebrisDetector(config)
        fi = FileInfo(
            path=path,
            rel_path=Path(".cursorignore"),
            size=path.stat().st_size,
            is_text=True,
            mtime=0.0,
        )
        assert detector.scan([fi]) == []


class TestQuarantineHardening:
    def test_quarantine_copies_then_unlinks(self, temp_repo: Path):
        target = temp_repo / "evil.py"
        target.write_text("eval('bad')\n")
        qm = QuarantineManager(temp_repo)

        dest = qm.quarantine(target, "test reason")

        assert not target.exists()
        assert dest.exists()
        assert dest.read_text() == "eval('bad')\n"
        reason = dest.with_suffix(dest.suffix + ".reason")
        assert reason.exists()
        assert "test reason" in reason.read_text(encoding="utf-8")

    def test_quarantine_retries_unlink_on_eperm(self, temp_repo: Path):
        target = temp_repo / "retry.py"
        target.write_text("payload\n")
        qm = QuarantineManager(temp_repo)
        calls = {"n": 0}
        real_unlink = Path.unlink

        def flaky_unlink(self, missing_ok=False):
            if self == target and calls["n"] == 0:
                calls["n"] += 1
                raise OSError(errno.EPERM, "Operation not permitted")
            return real_unlink(self, missing_ok=missing_ok)

        with patch.object(Path, "unlink", flaky_unlink):
            dest = qm.quarantine(target, "retry test")

        assert calls["n"] == 1
        assert not target.exists()
        assert dest.exists()

    def test_quarantine_missing_source_is_noop(self, temp_repo: Path):
        missing = temp_repo / "gone.py"
        qm = QuarantineManager(temp_repo)
        result = qm.quarantine(missing, "already gone")
        assert result == missing
