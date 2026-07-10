"""Tests for Linux fanotify backend (ubuntu CI)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from deadpush.backends.linux import (
    LinuxEnforcementBackend,
    decide_fanotify_write,
    evaluate_repo_write,
)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_linux_backend_describe(temp_repo: Path):
    backend = LinuxEnforcementBackend(temp_repo)
    info = backend.describe()
    assert info["name"] == "linux-fanotify"
    assert "repo_root" in info
    assert "deny_count" in info


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="Non-Linux check")
def test_linux_backend_unavailable_off_linux(temp_repo: Path):
    backend = LinuxEnforcementBackend(temp_repo)
    assert not backend.available()


def test_linux_backend_wrap_sets_env(temp_repo: Path):
    backend = LinuxEnforcementBackend(temp_repo)
    env: dict[str, str] = {}
    cmd = backend.wrap_command(["echo"], repo_root=temp_repo, env=env)
    assert cmd == ["echo"]
    assert env.get("DEADPUSH_LINUX_SANDBOX") == "1"


def test_decide_fanotify_write_blocks_blocked_file(temp_repo: Path):
    evil = temp_repo / "CLAUDE.md"
    allowed, reason = decide_fanotify_write(
        temp_repo,
        abs_path=str(evil),
        content="# bad\n",
    )
    assert not allowed
    assert reason


def test_decide_fanotify_write_allows_clean(temp_repo: Path):
    good = temp_repo / "good.py"
    allowed, _ = decide_fanotify_write(
        temp_repo,
        abs_path=str(good),
        content="x = 1\n",
    )
    assert allowed


def test_decide_fanotify_write_skips_outside_repo(temp_repo: Path):
    allowed, _ = decide_fanotify_write(
        temp_repo,
        abs_path="/tmp/outside.py",
        content="eval(1)\n",
    )
    assert allowed


def test_decide_fanotify_write_skips_bootstrap_paths(temp_repo: Path):
    allowed, _ = decide_fanotify_write(
        temp_repo,
        abs_path=str(temp_repo / ".cursorignore"),
        content="# ignore\n",
    )
    assert allowed


def test_evaluate_repo_write_uses_enforcement_kernel(temp_repo: Path):
    allowed, _ = evaluate_repo_write(temp_repo, "CLAUDE.md", "# bad\n")
    assert not allowed
    allowed2, _ = evaluate_repo_write(temp_repo, "fine.py", "print('hi')\n")
    assert allowed2
