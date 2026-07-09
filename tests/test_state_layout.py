"""Tests for ~/.deadpush layout, registry, migration, and discovery."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from deadpush import guard, state


@pytest.fixture
def state_home(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "HARDENED_STATE_DIR", tmp_path / "hardened")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(state.Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr(guard, "_state_dir", lambda hardened=False: state.state_dir(hardened))
    state.reset_migration_flags()
    yield home / ".deadpush"
    state.reset_migration_flags()


class TestStateLayout:
    def test_scoped_paths_under_repos(self, state_home, tmp_path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        state.ensure_layout_migrated(hardened=False)
        log = state.scoped_log_file(repo, hardened=False)
        assert log == state_home / "repos" / state.repo_id(repo) / "guardian.log"

    def test_migrate_legacy_flat_files(self, state_home, tmp_path):
        repo = tmp_path / "proj"
        repo.mkdir()
        rid = state.repo_id(repo)

        legacy_log = state_home / f"guardian.{rid}.log"
        state_home.mkdir(parents=True, exist_ok=True)
        legacy_log.write_text("hello legacy\n", encoding="utf-8")
        holder = state_home / f"guardian.{rid}.holder"
        holder.write_text(str(repo.resolve()), encoding="utf-8")

        state.ensure_layout_migrated(hardened=False)
        new_log = state_home / "repos" / rid / "guardian.log"
        assert new_log.exists()
        assert new_log.read_text(encoding="utf-8") == "hello legacy\n"
        assert legacy_log.is_symlink()

    def test_registry_touch_and_discover(self, state_home, tmp_path):
        repo = tmp_path / "app"
        repo.mkdir()
        state.touch_registry(repo, hardened=False, running=True)
        entries = state.discover_repos(hardened=False)
        rid = state.repo_id(repo)
        match = [e for e in entries if e["id"] == rid]
        assert len(match) == 1
        assert match[0]["path"] == str(repo.resolve())
        assert match[0]["label"] == "app"

        reg = json.loads((state_home / "registry.json").read_text(encoding="utf-8"))
        assert rid in reg["repos"]


class TestStopAll:
    def test_kill_orphan_guardian_processes_no_crash(self):
        # Should not raise even when nothing matches
        n = guard.kill_orphan_guardian_processes()
        assert isinstance(n, int)

    def test_count_running_guardians(self):
        assert isinstance(guard.count_running_guardians(), int)
