"""Tests for Linux bubblewrap sandbox backend."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from deadpush.backends.bubblewrap import (
    BubblewrapEnforcementBackend,
    build_bwrap_argv,
    bubblewrap_available,
)
from deadpush.backends.sandbox_paths import collect_writable_sandbox_paths


def test_collect_writable_sandbox_paths_linux(temp_repo: Path):
    paths = collect_writable_sandbox_paths(temp_repo, platform="linux")
    assert temp_repo.resolve() in paths
    assert any("/tmp" in str(p) for p in paths)


def test_build_bwrap_argv_structure(temp_repo: Path):
    argv = build_bwrap_argv(
        ["python", "-c", "print(1)"],
        temp_repo,
        bwrap_bin="/usr/bin/bwrap",
    )
    assert argv[0] == "/usr/bin/bwrap"
    assert argv[1:4] == ["--ro-bind", "/", "/"]
    repo_s = str(temp_repo.resolve())
    assert "--bind" in argv
    assert repo_s in argv
    assert argv[-4:] == ["--", "python", "-c", "print(1)"]
    assert "--die-with-parent" in argv
    assert "--proc" in argv
    assert "--dev" in argv


def test_bubblewrap_capabilities(temp_repo: Path):
    backend = BubblewrapEnforcementBackend(temp_repo)
    caps = backend.capabilities
    assert caps.os_confinement is True
    assert caps.write_allowlist is True
    assert caps.content_deny is False


@pytest.mark.skipif(sys.platform != "linux", reason="linux only")
def test_bubblewrap_available_matches_path():
    with patch("deadpush.backends.bubblewrap.bubblewrap_binary", return_value="/usr/bin/bwrap"):
        assert bubblewrap_available() is True
    with patch("deadpush.backends.bubblewrap.bubblewrap_binary", return_value=None):
        assert bubblewrap_available() is False


def test_build_bwrap_argv_requires_binary(temp_repo: Path):
    with patch("deadpush.backends.bubblewrap.bubblewrap_binary", return_value=None):
        with pytest.raises(RuntimeError, match="bubblewrap not found"):
            build_bwrap_argv(["true"], temp_repo)
