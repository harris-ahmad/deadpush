"""Tests for noop enforcement backend."""

from __future__ import annotations

from pathlib import Path

from deadpush.backends.noop import NoopEnforcementBackend


def test_noop_backend_describe(temp_repo: Path):
    backend = NoopEnforcementBackend(temp_repo)
    info = backend.describe()
    assert info["name"] == "noop"
    assert info["tier"] == "T2-partial"
    assert info["os_sandbox"] is False
    assert "git-wrapper" in info["gates"]


def test_noop_backend_env_markers(temp_repo: Path):
    backend = NoopEnforcementBackend(temp_repo)
    backend.start(temp_repo)
    env: dict[str, str] = {}
    backend.wrap_command(["echo", "hi"], repo_root=temp_repo, env=env)
    assert env["DEADPUSH_BACKEND"] == "noop"
    assert env["DEADPUSH_NOOP_SANDBOX"] == "1"
    assert env["DEADPUSH_REPO_ROOT"] == str(temp_repo.resolve())


def test_noop_backend_preflight_rejects_empty(temp_repo: Path):
    backend = NoopEnforcementBackend(temp_repo)
    ok, reason = backend.preflight([])
    assert not ok
    assert reason
