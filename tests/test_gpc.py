"""Tests for Guardian Push Channel (GPC) v0."""

from __future__ import annotations

import json
from pathlib import Path

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


def test_gpc_socket_path_scoped(temp_repo: Path):
    path = gpc_socket_path(temp_repo, hardened=False)
    assert "gpc." in path.name
    assert str(path).startswith(str(Path.home() / ".deadpush"))


def test_gpc_server_broadcast(temp_repo: Path):
    """Broadcast delivers INCIDENT JSON to connected clients."""
    server = GpcServer(temp_repo, hardened=False)
    received: list[bytes] = []

    class _FakeClient:
        def sendall(self, data: bytes) -> None:
            received.append(data)

    server._clients = [_FakeClient()]  # type: ignore[list-item]
    server.emit_incident("security", "eval() detected", file="evil.py")
    assert received
    assert b"INCIDENT" in received[0]
    payload = json.loads(received[0].decode().split("\n")[0])
    assert payload["payload"]["category"] == "security"


def test_gpc_server_socket_lifecycle(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    try:
        assert server.socket_path.exists()
    finally:
        server.stop()
        assert not server.socket_path.exists()


def test_gpc_client_ack(temp_repo: Path, tmp_path: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    try:
        client = GpcClient(temp_repo)
        client.send_heartbeat()
        client.send_ack("msg-1")
        # Should not raise
    finally:
        server.stop()


def test_gpc_protocol_version():
    assert GPC_PROTOCOL_VERSION == "0.1"
