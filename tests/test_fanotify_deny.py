"""Tests for Linux fanotify backend (ubuntu CI)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from deadpush.backends.linux import LinuxEnforcementBackend


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_linux_backend_describe(temp_repo: Path):
    backend = LinuxEnforcementBackend(temp_repo)
    info = backend.describe()
    assert info["name"] == "linux-fanotify"
    assert "repo_root" in info


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
