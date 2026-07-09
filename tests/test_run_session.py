"""Tests for deadpush run --sandbox session wrapper."""

from __future__ import annotations

import sys
from pathlib import Path

from deadpush.backends.base import get_backend
from deadpush.backends.noop import NoopEnforcementBackend
from deadpush.run_session import describe_session, prepare_sandbox_env, run_sandbox


def test_describe_session(temp_repo: Path):
    info = describe_session(temp_repo)
    assert info["tier"] in ("T2", "T2-partial", "T2-max")
    assert "backend" in info
    assert info["repo_root"] == str(temp_repo.resolve())
    assert info["gpc"]["mandatory"] is True
    assert "gpc-mandatory" in info["features"]


def test_prepare_sandbox_env(temp_repo: Path):
    env = prepare_sandbox_env(temp_repo)
    assert env["DEADPUSH_REPO_ROOT"] == str(temp_repo.resolve())
    assert env["DEADPUSH_SANDBOX"] == "1"
    assert "DEADPUSH_BIN_DIR" in env
    bindir = Path(env["DEADPUSH_BIN_DIR"])
    assert (bindir / "git").exists()


def test_run_sandbox_echo(temp_repo: Path):
    code = run_sandbox(
        [sys.executable, "-c", "print('ok')"],
        repo_root=temp_repo,
        backend_prefer="noop",
    )
    assert code == 0


def test_get_backend_noop(temp_repo: Path):
    backend = get_backend(temp_repo, prefer="noop")
    assert isinstance(backend, NoopEnforcementBackend)
