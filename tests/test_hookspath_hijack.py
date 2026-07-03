"""Tests for detecting/repairing a hijacked `core.hooksPath`.

`git config core.hooksPath /dev/null` (or any dir other than `.git/hooks`)
silently disables every deadpush git hook without touching the hook files, so
the checksum/immutability checks alone report "OK". These tests cover the
detection, the repair, and the guardian's self-heal loop.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.hooks import (
    detect_hookspath_hijack,
    install_hook,
    install_postcommit_hook,
    install_precommit_hook,
    repair_deadpush_hooks,
    restore_hookspath,
    verify_hooks_installed,
)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)


class TestDetection:
    def test_clean_repo_not_flagged(self, temp_repo: Path):
        assert detect_hookspath_hijack(temp_repo) is None
        assert not any(p.startswith("core.hooksPath") for p in verify_hooks_installed(temp_repo))

    def test_devnull_hijack_detected(self, temp_repo: Path):
        _git(temp_repo, "config", "core.hooksPath", "/dev/null")
        assert detect_hookspath_hijack(temp_repo) == "/dev/null"
        assert any(p.startswith("core.hooksPath") for p in verify_hooks_installed(temp_repo))

    def test_other_dir_hijack_detected(self, temp_repo: Path, tmp_path: Path):
        evil = tmp_path / "evilhooks"
        evil.mkdir()
        _git(temp_repo, "config", "core.hooksPath", str(evil))
        assert detect_hookspath_hijack(temp_repo) == str(evil)

    def test_explicit_default_not_flagged(self, temp_repo: Path):
        # Pointing hooksPath *at* the real hooks dir is fine, not a hijack.
        default = (temp_repo / ".git" / "hooks").resolve()
        _git(temp_repo, "config", "core.hooksPath", str(default))
        assert detect_hookspath_hijack(temp_repo) is None


class TestRepair:
    def test_restore_removes_local_hijack(self, temp_repo: Path):
        _git(temp_repo, "config", "core.hooksPath", "/dev/null")
        assert restore_hookspath(temp_repo) is True
        assert detect_hookspath_hijack(temp_repo) is None
        # The local config key is actually gone.
        r = _git(temp_repo, "config", "--local", "--get", "core.hooksPath")
        assert r.returncode != 0

    def test_repair_deadpush_hooks_restores_hookspath(self, temp_repo: Path):
        install_hook(temp_repo)
        install_precommit_hook(temp_repo)
        install_postcommit_hook(temp_repo)
        _git(temp_repo, "config", "core.hooksPath", "/dev/null")

        repaired = repair_deadpush_hooks(temp_repo)

        assert "core.hooksPath" in repaired
        assert detect_hookspath_hijack(temp_repo) is None


class TestGuardianSelfHeal:
    def test_check_hook_integrity_restores_hookspath(self, temp_repo: Path):
        from deadpush.config import Config
        from deadpush.guard import GuardianHandler

        install_hook(temp_repo)
        _git(temp_repo, "config", "core.hooksPath", "/dev/null")

        handler = GuardianHandler(Config(repo_root=temp_repo), intervention=True, daemon=False)
        handler._check_hook_integrity()

        assert detect_hookspath_hijack(temp_repo) is None
