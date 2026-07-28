"""Tests for Linux composite sandbox (bubblewrap + fanotify)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deadpush.backends.linux_sandbox import LinuxSandboxBackend


def test_linux_sandbox_capabilities_before_start(temp_repo: Path):
    backend = LinuxSandboxBackend(temp_repo)
    with patch.object(backend._bwrap, "available", return_value=True), \
         patch.object(backend._fanotify, "available", return_value=True):
        caps = backend.capabilities
    assert caps.os_confinement is True
    assert caps.write_allowlist is True
    assert caps.content_deny is True


def test_linux_sandbox_capabilities_fanotify_off_after_start(temp_repo: Path):
    backend = LinuxSandboxBackend(temp_repo)
    with patch.object(backend._bwrap, "start"), \
         patch.object(backend._bwrap, "available", return_value=True), \
         patch.object(backend._fanotify, "available", return_value=False):
        backend.start(temp_repo)
    caps = backend.capabilities
    assert caps.os_confinement is True
    assert caps.write_allowlist is True
    assert caps.content_deny is False


def test_linux_sandbox_wrap_delegates_to_bwrap(temp_repo: Path):
    backend = LinuxSandboxBackend(temp_repo)
    env: dict[str, str] = {}
    with patch.object(
        backend._bwrap,
        "wrap_command",
        return_value=["bwrap", "--", "echo", "hi"],
    ) as wrap:
        out = backend.wrap_command(["echo", "hi"], repo_root=temp_repo, env=env)
    wrap.assert_called_once()
    assert out[0] == "bwrap"
    assert env.get("DEADPUSH_BACKEND") == "linux-sandbox"


def test_linux_sandbox_attach_on_deny(temp_repo: Path):
    backend = LinuxSandboxBackend(temp_repo)
    cb = MagicMock()
    backend.attach_on_deny(cb)
    assert backend._fanotify._on_deny is cb


def test_linux_sandbox_available_requires_bwrap(temp_repo: Path):
    backend = LinuxSandboxBackend(temp_repo)
    with patch.object(backend._bwrap, "available", return_value=False):
        assert backend.available() is False
    with patch.object(backend._bwrap, "available", return_value=True):
        assert backend.available() is True


@pytest.mark.skipif(sys.platform != "linux", reason="linux only")
def test_get_backend_prefers_linux_sandbox_on_linux(temp_repo: Path):
    from deadpush.backends.base import get_backend

    with patch.object(LinuxSandboxBackend, "available", return_value=True):
        backend = get_backend(temp_repo)
    assert backend.name == "linux-sandbox"
