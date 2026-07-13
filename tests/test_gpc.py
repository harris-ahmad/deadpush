"""Tests for Guardian Push Channel (GPC)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deadpush.gpc import (
    GPC_PROTOCOL_VERSION,
    GpcClient,
    GpcMessage,
    GpcServer,
    gpc_socket_path,
)


def test_gpc_message_roundtrip():
    msg = GpcMessage(type="INCIDENT", repo_id="abc", payload={"category": "secret"})
    restored = GpcMessage.from_line(msg.to_line().strip())
    assert restored.type == "INCIDENT"
    assert restored.payload["category"] == "secret"
    assert restored.protocol_version == GPC_PROTOCOL_VERSION


def test_gpc_message_validation():
    msg = GpcMessage(type="INCIDENT", repo_id="abc")
    ok, _ = msg.validate()
    assert ok
    bad = GpcMessage(type="")
    ok, err = bad.validate()
    assert not ok
    assert "missing type" in err


def test_gpc_message_rejects_oversized_line():
    huge = "x" * 70000
    with pytest.raises(ValueError):
        GpcMessage.from_line(json.dumps({"type": "INCIDENT", "payload": {"data": huge}}))


def test_gpc_socket_path_scoped(temp_repo: Path):
    path = gpc_socket_path(temp_repo, hardened=False)
    assert "gpc." in path.name
    assert str(path).startswith(str(Path.home() / ".deadpush"))


def test_gpc_server_broadcast(temp_repo: Path):
    from deadpush.gpc import _ClientState

    server = GpcServer(temp_repo, hardened=False)
    received: list[bytes] = []

    class _FakeConn:
        def sendall(self, data: bytes) -> None:
            received.append(data)

    server._clients = {
        1: _ClientState(conn=_FakeConn(), connected_at=0.0, last_heartbeat=0.0),  # type: ignore[arg-type]
    }

    count = server.emit_incident("security", "eval() detected", file="evil.py")
    assert count == 1
    assert received
    assert b"INCIDENT" in received[0]
    payload = json.loads(received[0].decode().split("\n")[0])
    assert payload["payload"]["category"] == "security"
    assert payload["protocol_version"] == GPC_PROTOCOL_VERSION


def test_gpc_server_socket_lifecycle(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    try:
        assert server.socket_path.exists()
    finally:
        server.stop()
        assert not server.socket_path.exists()


def test_gpc_client_ack(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    try:
        import time
        time.sleep(0.1)
        client = GpcClient(temp_repo)
        assert client.send_heartbeat() is True
        assert client.send_ack("msg-1") is True
    finally:
        server.stop()


def test_gpc_override_request_logged(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    try:
        import time
        for _ in range(50):
            if server.socket_path.exists():
                break
            time.sleep(0.02)
        client = GpcClient(temp_repo)
        assert client.send_heartbeat() is True
        assert client.send_request_override("need to push hotfix", related_message_id="inc-1")
        log = temp_repo / ".deadpush" / "gpc_overrides.jsonl"
        for _ in range(50):
            if log.exists():
                break
            time.sleep(0.1)
        assert log.exists()
        line = json.loads(log.read_text(encoding="utf-8").strip().splitlines()[-1])
        assert line["payload"]["reason"] == "need to push hotfix"
    finally:
        server.stop()


def test_gpc_protocol_version():
    assert GPC_PROTOCOL_VERSION == "1.0"


def test_gpc_proxy_block_rebroadcasts_incident(temp_repo: Path):
    received: list[str] = []

    def on_msg(msg):
        received.append(msg.type)

    server = GpcServer(temp_repo, hardened=False)
    server.start()
    try:
        import time
        time.sleep(0.1)
        listener = GpcClient(temp_repo, on_message=on_msg)
        listener.connect_and_listen()
        time.sleep(0.2)
        reporter = GpcClient(temp_repo)
        assert reporter.send_proxy_block("run_terminal_cmd", "rm -rf /", file="_shell_")
        time.sleep(0.3)
        assert "INCIDENT" in received
    finally:
        server.stop()

