"""Tests for GPC staged-recovery events (thesis Phase 5)."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from deadpush.gpc import (
    GPC_LIFECYCLE_ACTION_REQUIRED,
    GPC_LIFECYCLE_OBSERVED,
    GpcClient,
    GpcServer,
)
from deadpush.gpc_outbox import DURABLE_TYPES
from deadpush.gpc_staged import emit_staged_recovery_events
from deadpush.staged_git import DestructiveGit, stage_and_deny


def test_staged_types_are_durable():
    assert "STAGED_DENY" in DURABLE_TYPES
    assert "SAVEPOINT_CREATED" in DURABLE_TYPES


def test_server_emit_staged_deny_payload(temp_repo: Path):
    from deadpush.gpc import _ClientState

    server = GpcServer(temp_repo, hardened=False)
    received: list[bytes] = []

    class _FakeConn:
        def sendall(self, data: bytes) -> None:
            received.append(data)

    server._clients = {
        1: _ClientState(conn=_FakeConn(), connected_at=0.0, last_heartbeat=0.0),  # type: ignore[arg-type]
    }
    n = server.emit_staged_deny(
        kind="reset_hard",
        reason="test",
        savepoint_id="abc",
        alternatives=["git reset --soft"],
    )
    assert n == 1
    payload = json.loads(received[-1].decode().split("\n")[0])
    assert payload["type"] == "STAGED_DENY"
    assert payload["payload"]["lifecycle"] == GPC_LIFECYCLE_ACTION_REQUIRED
    assert payload["payload"]["savepoint_id"] == "abc"


def _wait_socket(server: GpcServer) -> None:
    for _ in range(50):
        if server.socket_path.exists():
            return
        time.sleep(0.02)


def _wait_clients(server: GpcServer, n: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline and server.client_count < n:
        time.sleep(0.05)


def test_report_staged_rebroadcasts_to_subscriber(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    got: list[str] = []
    ready = threading.Event()

    def on_msg(msg):
        got.append(msg.type)
        if msg.type == "STAGED_DENY":
            ready.set()

    listener = GpcClient(temp_repo, on_message=on_msg)
    try:
        _wait_socket(server)
        listener.connect_and_listen()
        _wait_clients(server, 1)
        # One-shot reporter — accept loop starts readers before welcome.
        reporter = GpcClient(temp_repo, auto_ack=False)
        assert reporter.send_report_staged(
            kind="force_push",
            reason="force push blocked",
            savepoint_id="sp123",
            label="pre-force-push",
            alternatives=["git push"],
        )
        assert ready.wait(5.0), got
        assert "SAVEPOINT_CREATED" in got
        assert "STAGED_DENY" in got
    finally:
        listener.stop()
        server.stop()


def test_emit_skips_fast_without_socket(temp_repo: Path, monkeypatch):
    monkeypatch.setenv("DEADPUSH_SANDBOX", "1")
    monkeypatch.delenv("DEADPUSH_GPC_SOCKET", raising=False)
    t0 = time.perf_counter()
    ok = emit_staged_recovery_events(
        temp_repo,
        kind="reset_hard",
        reason="blocked",
        savepoint_id="sp9",
    )
    elapsed = time.perf_counter() - t0
    assert ok is False
    assert elapsed < 0.05


def test_emit_staged_recovery_events_via_env_socket(temp_repo: Path, monkeypatch):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    got = threading.Event()

    def on_msg(msg):
        if msg.type == "STAGED_DENY":
            got.set()

    listener = GpcClient(temp_repo, on_message=on_msg)
    try:
        _wait_socket(server)
        listener.connect_and_listen()
        _wait_clients(server, 1)
        monkeypatch.setenv("DEADPUSH_GPC_SOCKET", str(server.socket_path))
        t0 = time.perf_counter()
        ok = emit_staged_recovery_events(
            temp_repo,
            kind="reset_hard",
            reason="blocked",
            savepoint_id="sp9",
            label="pre-reset-hard",
            alternatives=["soft"],
        )
        emit_ms = (time.perf_counter() - t0) * 1000.0
        assert ok is True
        assert emit_ms < 50.0, f"emit took {emit_ms:.1f}ms (want <50ms one-shot)"
        assert got.wait(5.0)
    finally:
        listener.stop()
        server.stop()


def test_emit_does_not_ack_drain_outbox(temp_repo: Path, monkeypatch):
    """One-shot reporter must not ACK durable STAGED_* events."""
    from deadpush.gpc_outbox import GpcOutbox

    server = GpcServer(temp_repo, hardened=False)
    server.start()
    try:
        _wait_socket(server)
        monkeypatch.setenv("DEADPUSH_GPC_SOCKET", str(server.socket_path))
        ok = emit_staged_recovery_events(
            temp_repo,
            kind="reset_hard",
            reason="blocked",
            savepoint_id="sp-outbox",
            label="pre-reset-hard",
        )
        assert ok is True
        deadline = time.time() + 2.0
        pending_types: set[str] = set()
        while time.time() < deadline:
            outbox = GpcOutbox(temp_repo)
            with outbox._lock:
                rows = outbox._read_pending_unlocked()
            pending_types = {r.get("type", "") for r in rows}
            if "STAGED_DENY" in pending_types and "SAVEPOINT_CREATED" in pending_types:
                break
            time.sleep(0.05)
        assert "STAGED_DENY" in pending_types
        assert "SAVEPOINT_CREATED" in pending_types
    finally:
        server.stop()


def test_stage_and_deny_emits_gpc_when_socket_set(temp_repo: Path, monkeypatch):
    (temp_repo / "f.txt").write_text("x\n", encoding="utf-8")
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    payloads: list[dict] = []
    done = threading.Event()

    def on_msg(msg):
        payloads.append({"type": msg.type, **msg.payload})
        if msg.type == "STAGED_DENY":
            done.set()

    listener = GpcClient(temp_repo, on_message=on_msg)
    try:
        _wait_socket(server)
        listener.connect_and_listen()
        _wait_clients(server, 1)
        monkeypatch.setenv("DEADPUSH_GPC_SOCKET", str(server.socket_path))
        monkeypatch.setenv("DEADPUSH_SANDBOX", "1")
        hit = DestructiveGit(kind="reset_hard", reason="wipe", label="pre-reset-hard")
        code = stage_and_deny(temp_repo, hit, argv=["reset", "--hard", "HEAD"])
        assert code == 1
        assert done.wait(5.0), payloads
        deny = next(p for p in payloads if p["type"] == "STAGED_DENY")
        assert deny["lifecycle"] == GPC_LIFECYCLE_ACTION_REQUIRED
        assert deny["savepoint_id"]
        sp = next(p for p in payloads if p["type"] == "SAVEPOINT_CREATED")
        assert sp["lifecycle"] == GPC_LIFECYCLE_OBSERVED
    finally:
        listener.stop()
        server.stop()
