"""Tests for explicit sandbox backend capability contract (S2)."""

from __future__ import annotations

from pathlib import Path

from deadpush.backends.base import SandboxCapabilities, format_capabilities_summary
from deadpush.backends.linux import LinuxEnforcementBackend
from deadpush.backends.noop import NoopEnforcementBackend
from deadpush.backends.seatbelt import SeatbeltEnforcementBackend


def test_sandbox_capabilities_dataclass():
    caps = SandboxCapabilities(os_confinement=True, write_allowlist=True)
    assert caps.as_dict() == {
        "os_confinement": True,
        "write_allowlist": True,
        "content_deny": False,
    }
    assert caps.has_os_enforcement is True


def test_format_capabilities_summary():
    assert format_capabilities_summary(SandboxCapabilities()) == "gates only"
    assert format_capabilities_summary(
        SandboxCapabilities(os_confinement=True, write_allowlist=True),
    ) == "process confinement, write allowlist"
    assert format_capabilities_summary(
        {"content_deny": True, "os_confinement": False, "write_allowlist": False},
    ) == "content deny"


def test_seatbelt_capabilities(temp_repo: Path):
    backend = SeatbeltEnforcementBackend(temp_repo)
    caps = backend.capabilities
    assert caps.os_confinement is True
    assert caps.write_allowlist is True
    assert caps.content_deny is False
    info = backend.describe()
    assert info["capabilities"] == caps.as_dict()
    assert info["capabilities_summary"] == "process confinement, write allowlist"
    assert info["os_sandbox"] is True


def test_linux_fanotify_capabilities(temp_repo: Path):
    backend = LinuxEnforcementBackend(temp_repo)
    caps = backend.capabilities
    assert caps.os_confinement is False
    assert caps.write_allowlist is False
    assert caps.content_deny is True
    info = backend.describe()
    assert info["capabilities"] == caps.as_dict()
    assert info["capabilities_summary"] == "content deny"
    assert info["os_sandbox"] is True


def test_noop_capabilities(temp_repo: Path):
    backend = NoopEnforcementBackend(temp_repo)
    caps = backend.capabilities
    assert caps.os_confinement is False
    assert caps.write_allowlist is False
    assert caps.content_deny is False
    info = backend.describe()
    assert info["capabilities"] == caps.as_dict()
    assert info["capabilities_summary"] == "gates only"
    assert info["os_sandbox"] is False


def test_apply_env_markers_stamps_capabilities(temp_repo: Path):
    backend = SeatbeltEnforcementBackend(temp_repo)
    env: dict[str, str] = {}
    backend.apply_env_markers(env)
    assert env["DEADPUSH_SANDBOX_OS_CONFINEMENT"] == "1"
    assert env["DEADPUSH_SANDBOX_WRITE_ALLOWLIST"] == "1"
    assert env["DEADPUSH_SANDBOX_CONTENT_DENY"] == "0"
