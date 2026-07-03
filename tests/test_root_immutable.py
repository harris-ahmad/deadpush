"""Tests for root-immutable (schg) hooks in hardened mode.

Soft mode locks hooks USER-immutable (`chflags uchg` / `chattr +i`) which the
file owner (a same-UID agent) can clear. Hardened mode locks them ROOT-immutable
(`sudo chflags schg` / `sudo chattr +i`) which only root can clear.

These tests avoid actually needing sudo/root by intercepting the subprocess call
that runs `chflags`/`chattr`, so they verify the *command construction* and the
control flow (fail-safe fallback, schg detection) deterministically in CI.
"""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush import hooks
from deadpush.hooks import (
    _is_immutable,
    _make_immutable,
    _make_mutable,
    install_hook,
    verify_hooks_installed,
)


class _Recorder:
    """Drop-in for subprocess.run that records commands and reports success."""

    def __init__(self, returncode: int = 0):
        self.calls: list[list[str]] = []
        self.returncode = returncode

    def __call__(self, cmd, *args, **kwargs):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self.returncode, stdout=b"", stderr=b"")

    def flag_calls(self) -> list[list[str]]:
        return [c for c in self.calls if any(x in ("chflags", "chattr") for x in c)]


def _immutable_cmd(rec: _Recorder) -> list[str]:
    """Return the single chflags/chattr command that was issued."""
    flag_calls = rec.flag_calls()
    assert len(flag_calls) == 1, f"expected one flag command, got {flag_calls}"
    return flag_calls[0]


class TestMakeImmutableCommand:
    def test_soft_uses_user_flag_without_sudo(self, monkeypatch, tmp_path):
        rec = _Recorder()
        monkeypatch.setattr(hooks.subprocess, "run", rec)
        assert _make_immutable(tmp_path / "pre-push", system=False) is True
        cmd = _immutable_cmd(rec)
        assert cmd[0] != "sudo"
        if sys.platform == "darwin":
            assert cmd[:3] == ["chflags", "uchg", str(tmp_path / "pre-push")]
        elif sys.platform.startswith("linux"):
            assert cmd[:2] == ["chattr", "+i"]

    def test_hardened_uses_system_flag_with_sudo(self, monkeypatch, tmp_path):
        rec = _Recorder()
        monkeypatch.setattr(hooks.subprocess, "run", rec)
        assert _make_immutable(tmp_path / "pre-push", system=True) is True
        cmd = _immutable_cmd(rec)
        assert cmd[0] == "sudo"
        if sys.platform == "darwin":
            assert "schg" in cmd
            assert "uchg" not in cmd
        elif sys.platform.startswith("linux"):
            assert "chattr" in cmd and "+i" in cmd

    def test_make_mutable_hardened_clears_both_flags_with_sudo(self, monkeypatch, tmp_path):
        rec = _Recorder()
        monkeypatch.setattr(hooks.subprocess, "run", rec)
        assert _make_mutable(tmp_path / "pre-push", system=True) is True
        cmd = _immutable_cmd(rec)
        assert cmd[0] == "sudo"
        if sys.platform == "darwin":
            # Clears system- AND user-immutable in one call.
            assert "noschg,nouchg" in cmd
        elif sys.platform.startswith("linux"):
            assert "chattr" in cmd and "-i" in cmd

    def test_make_mutable_soft_has_no_sudo(self, monkeypatch, tmp_path):
        rec = _Recorder()
        monkeypatch.setattr(hooks.subprocess, "run", rec)
        _make_mutable(tmp_path / "pre-push", system=False)
        cmd = _immutable_cmd(rec)
        assert cmd[0] != "sudo"


class TestInstallHookThreadsSystem:
    def test_hardened_install_sets_schg(self, monkeypatch, temp_repo):
        rec = _Recorder()
        monkeypatch.setattr(hooks.subprocess, "run", rec)
        install_hook(temp_repo, system=True)
        flag_cmds = rec.flag_calls()
        # A mutable (clear) then immutable (set) call, both privileged.
        assert flag_cmds, "no chflags/chattr commands issued"
        assert all(c[0] == "sudo" for c in flag_cmds)
        if sys.platform == "darwin":
            assert any("schg" in c for c in flag_cmds)

    def test_soft_install_never_uses_sudo(self, monkeypatch, temp_repo):
        rec = _Recorder()
        monkeypatch.setattr(hooks.subprocess, "run", rec)
        install_hook(temp_repo, system=False)
        assert all(c[0] != "sudo" for c in rec.flag_calls())


@pytest.mark.skipif(sys.platform != "darwin", reason="schg detection is macOS-only")
class TestImmutableDetection:
    def test_detects_system_immutable_flag(self, monkeypatch, tmp_path):
        target = tmp_path / "pre-push"
        target.write_text("#!/bin/sh\n")

        class _FakeStat:
            st_flags = getattr(stat, "SF_IMMUTABLE", 0x00020000)

        monkeypatch.setattr(Path, "stat", lambda self, *a, **k: _FakeStat())
        assert _is_immutable(target) is True

    def test_detects_user_immutable_flag(self, monkeypatch, tmp_path):
        target = tmp_path / "pre-push"
        target.write_text("#!/bin/sh\n")

        class _FakeStat:
            st_flags = stat.UF_IMMUTABLE

        monkeypatch.setattr(Path, "stat", lambda self, *a, **k: _FakeStat())
        assert _is_immutable(target) is True

    def test_no_flag_is_not_immutable(self, monkeypatch, tmp_path):
        target = tmp_path / "pre-push"
        target.write_text("#!/bin/sh\n")

        class _FakeStat:
            st_flags = 0

        monkeypatch.setattr(Path, "stat", lambda self, *a, **k: _FakeStat())
        assert _is_immutable(target) is False


class TestFailSafeFallback:
    def test_schg_failure_falls_back_to_uchg(self, monkeypatch, temp_repo, capsys):
        """If root-immutable can't be set (e.g. no sudo), the hook must still be
        user-immutable rather than silently unprotected, and warn loudly."""

        calls: list[list[str]] = []

        def fake_run(cmd, *args, **kwargs):
            calls.append(list(cmd))
            # Fail every privileged (sudo) call; succeed the non-sudo fallback.
            rc = 1 if (cmd and cmd[0] == "sudo") else 0
            return subprocess.CompletedProcess(cmd, rc, stdout=b"", stderr=b"")

        monkeypatch.setattr(hooks.subprocess, "run", fake_run)
        install_hook(temp_repo, system=True)

        out = capsys.readouterr().out
        # A non-sudo (user-immutable) fallback command was attempted.
        assert any(c and c[0] != "sudo" and any(x in ("chflags", "chattr") for x in c) for c in calls)
        if sys.platform in ("darwin",) or sys.platform.startswith("linux"):
            assert "fell back to user-immutable" in out


class TestHardenedHookVerification:
    def test_immutable_hook_not_flagged(self, monkeypatch, temp_repo):
        """A root-immutable hook must NOT be flagged as 'not immutable', or the
        daemon would loop trying to repair a file it cannot rewrite. `verify`
        must route its immutability judgement through `_is_immutable` (which now
        recognises schg)."""
        install_hook(temp_repo, system=False)  # real file on disk
        if sys.platform != "darwin":
            pytest.skip("immutability is only verified on macOS")

        monkeypatch.setattr(hooks, "_is_immutable", lambda p: True)
        problems = verify_hooks_installed(temp_repo)
        assert not any("immutable" in p for p in problems)
