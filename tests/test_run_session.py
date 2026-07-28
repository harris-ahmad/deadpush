"""Tests for deadpush run --sandbox session wrapper."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from deadpush.backends.base import SandboxUnavailableError, get_backend
from deadpush.backends.noop import NoopEnforcementBackend
from deadpush.run_session import describe_session, prepare_sandbox_env, run_sandbox


def test_describe_session_explicit_noop(temp_repo: Path):
    info = describe_session(temp_repo, backend_prefer="noop")
    assert info["tier"] == "T2-partial"
    assert info["backend"]["name"] == "noop"
    assert info["repo_root"] == str(temp_repo.resolve())
    assert info["gpc"]["mandatory"] is True
    assert "gpc-mandatory" in info["features"]


def test_describe_session_default_or_unavailable(temp_repo: Path):
    try:
        info = describe_session(temp_repo)
    except SandboxUnavailableError as e:
        assert "noop" in str(e)
        return
    assert info["tier"] in ("T2", "T2-max")
    assert info["backend"]["name"] != "noop"


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


def test_get_backend_no_silent_noop_fallback(temp_repo: Path):
    with patch("deadpush.backends.seatbelt.SeatbeltEnforcementBackend.available", return_value=False), \
         patch("deadpush.backends.linux.LinuxEnforcementBackend.available", return_value=False):
        with pytest.raises(SandboxUnavailableError, match="noop"):
            get_backend(temp_repo)


def test_get_backend_prefer_unavailable_raises(temp_repo: Path):
    with patch("deadpush.backends.seatbelt.SeatbeltEnforcementBackend.available", return_value=False):
        with pytest.raises(SandboxUnavailableError, match="seatbelt"):
            get_backend(temp_repo, prefer="seatbelt")


def test_run_sandbox_fails_loud_without_backend(temp_repo: Path):
    with patch("deadpush.run_session.get_backend", side_effect=SandboxUnavailableError("no backend")):
        code = run_sandbox(
            [sys.executable, "-c", "print('ok')"],
            repo_root=temp_repo,
            require_gpc=False,
        )
    assert code == 2


def test_run_sandbox_start_failure_no_noop_fallback(temp_repo: Path):
    backend = NoopEnforcementBackend(temp_repo)

    def boom(_repo):
        raise RuntimeError("simulated start failure")

    # Prefer a "real" backend object that fails start — run_sandbox must not
    # swap in noop; exit 2 instead.
    backend.name = "seatbelt"
    backend.start = boom  # type: ignore[method-assign]
    with patch("deadpush.run_session.get_backend", return_value=backend):
        code = run_sandbox(
            [sys.executable, "-c", "print('ok')"],
            repo_root=temp_repo,
            require_gpc=False,
        )
    assert code == 2
