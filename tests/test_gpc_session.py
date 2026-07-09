"""Tests for mandatory GPC in sandbox sessions (Slice D)."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from deadpush.gpc import GpcMessage, GpcServer
from deadpush.gpc_session import (
    GpcMandatoryError,
    GpcSessionRelay,
    apply_gpc_env,
    gpc_socket_reachable,
    start_gpc_session,
    stop_gpc_session,
)
from deadpush.run_session import prepare_sandbox_env, run_sandbox


def test_start_gpc_session_starts_server_and_relay(temp_repo: Path):
    session = start_gpc_session(temp_repo, mandatory=True)
    assert session is not None
    try:
        assert session.socket_path.exists()
        assert session.server is not None
        assert not session.attached_external
    finally:
        stop_gpc_session(session)
        assert not session.socket_path.exists()


def test_start_gpc_session_attaches_to_existing_server(temp_repo: Path):
    guardian_server = GpcServer(temp_repo, hardened=False)
    guardian_server.start()
    try:
        time.sleep(0.1)
        assert gpc_socket_reachable(guardian_server.socket_path)
        session = start_gpc_session(temp_repo, mandatory=True)
        assert session is not None
        try:
            assert session.attached_external
            assert session.server is None
        finally:
            stop_gpc_session(session)
        assert guardian_server.socket_path.exists()
    finally:
        guardian_server.stop()


def test_mandatory_gpc_fails_when_relay_cannot_connect(temp_repo: Path):
    with patch.object(GpcSessionRelay, "wait_connected", return_value=False):
        with pytest.raises(GpcMandatoryError, match="relay failed to connect"):
            start_gpc_session(temp_repo, mandatory=True)


def test_apply_gpc_env_sets_markers(temp_repo: Path):
    session = start_gpc_session(temp_repo, mandatory=True)
    try:
        env: dict[str, str] = {}
        apply_gpc_env(env, session)
        assert env["DEADPUSH_GPC_REQUIRED"] == "1"
        assert env["DEADPUSH_GPC_MANDATORY"] == "1"
        assert env["DEADPUSH_GPC_SOCKET"] == str(session.socket_path)
        assert env["DEADPUSH_REPO_ID"]
    finally:
        stop_gpc_session(session)


def test_prepare_sandbox_env_includes_gpc(temp_repo: Path):
    session = start_gpc_session(temp_repo, mandatory=True)
    try:
        env = prepare_sandbox_env(temp_repo, gpc_session=session)
        assert env["DEADPUSH_GPC_MANDATORY"] == "1"
        assert env["DEADPUSH_SANDBOX"] == "1"
    finally:
        stop_gpc_session(session)


def test_relay_surfaces_incidents(temp_repo: Path):
    received: list[GpcMessage] = []

    def capture(msg: GpcMessage) -> None:
        received.append(msg)

    session = start_gpc_session(temp_repo, mandatory=True, on_message=capture)
    try:
        session.server.emit_incident("security", "eval blocked", file="evil.py")
        time.sleep(0.3)
        assert any(m.type == "INCIDENT" for m in received)
    finally:
        stop_gpc_session(session)


def test_run_sandbox_mandatory_gpc_echo(temp_repo: Path):
    code = run_sandbox(
        [sys.executable, "-c", "print('ok')"],
        repo_root=temp_repo,
        backend_prefer="noop",
        require_gpc=True,
    )
    assert code == 0


def test_run_sandbox_fails_when_gpc_mandatory_unavailable(temp_repo: Path):
    with patch(
        "deadpush.run_session.start_gpc_session",
        side_effect=GpcMandatoryError("simulated failure"),
    ):
        code = run_sandbox(
            [sys.executable, "-c", "print('ok')"],
            repo_root=temp_repo,
            backend_prefer="noop",
            require_gpc=True,
        )
    assert code == 2


def test_run_sandbox_no_gpc_opt_out(temp_repo: Path):
    code = run_sandbox(
        [sys.executable, "-c", "print('ok')"],
        repo_root=temp_repo,
        backend_prefer="noop",
        require_gpc=False,
    )
    assert code == 0
