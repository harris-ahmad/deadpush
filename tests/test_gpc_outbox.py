"""Tests for durable GPC outbox delivery."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from deadpush.gpc import GpcClient, GpcMessage, GpcServer
from deadpush.gpc_outbox import GpcOutbox, OUTBOX_FILENAME


def test_outbox_append_and_ack(temp_repo: Path):
    box = GpcOutbox(temp_repo)
    msg = GpcMessage(
        type="INCIDENT",
        message_id="inc-test-1",
        repo_id="rid",
        payload={"category": "security", "description": "eval"},
    )
    box.append(msg)
    assert box.path.exists()
    pending = box.list_pending()
    assert len(pending) == 1
    assert pending[0].message_id == "inc-test-1"
    assert box.ack("inc-test-1")
    assert box.list_pending() == []
    assert box.stats.acked == 1


def test_outbox_skips_welcome(temp_repo: Path):
    box = GpcOutbox(temp_repo)
    box.append(GpcMessage(type="WELCOME", message_id="wel-1", payload={}))
    assert not box.path.exists() or box.list_pending() == []


def test_offline_incident_replayed_on_connect(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    received: list[str] = []
    gate = threading.Event()

    def on_msg(msg):
        if msg.type == "INCIDENT":
            received.append(msg.message_id)
            gate.set()

    # Emit with no clients — should land in outbox only.
    msg_id = "inc-offline-1"
    server.broadcast(GpcMessage(
        type="INCIDENT",
        message_id=msg_id,
        payload={"category": "security", "description": "offline test"},
    ))
    assert (temp_repo / ".deadpush" / OUTBOX_FILENAME).exists()
    assert GpcOutbox(temp_repo).list_pending()

    server.start()
    client = GpcClient(temp_repo, on_message=on_msg, auto_ack=True)
    try:
        for _ in range(50):
            if server.socket_path.exists():
                break
            time.sleep(0.02)
        client.connect_and_listen()
        assert gate.wait(5.0), "client never received replayed INCIDENT"
        assert msg_id in received
        # ACK should drain outbox entry.
        deadline = time.time() + 3.0
        while time.time() < deadline and GpcOutbox(temp_repo).list_pending():
            time.sleep(0.05)
        assert GpcOutbox(temp_repo).list_pending() == []
    finally:
        client.stop()
        server.stop()


def test_broadcast_to_connected_client_then_ack_clears_outbox(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.start()
    client = GpcClient(temp_repo, auto_ack=True)
    try:
        for _ in range(50):
            if server.socket_path.exists():
                break
            time.sleep(0.02)
        client.connect_and_listen()
        time.sleep(0.15)
        mid = "inc-live-1"
        server.broadcast(GpcMessage(
            type="INCIDENT",
            message_id=mid,
            payload={"category": "security", "description": "live"},
        ))
        deadline = time.time() + 3.0
        while time.time() < deadline and GpcOutbox(temp_repo).list_pending():
            time.sleep(0.05)
        assert GpcOutbox(temp_repo).list_pending() == []
        status = server.describe()
        assert status["outbox"]["acked"] >= 1
    finally:
        client.stop()
        server.stop()


def test_server_describe_includes_outbox(temp_repo: Path):
    server = GpcServer(temp_repo, hardened=False)
    server.broadcast(GpcMessage(
        type="LOCKDOWN",
        message_id="lock-1",
        payload={"reason": "score"},
    ))
    d = server.describe()
    assert d["outbox"]["pending"] == 1
    assert d["outbox"]["appended"] == 1
