"""
Guardian Push Channel (GPC) v0 — bidirectional push protocol outside MCP.

Transport: Unix domain socket, newline-delimited JSON (same framing as MCP stdio).

Guardian → client: INCIDENT, LOCKDOWN, INSTRUCTION, POLICY_UPDATE, SESSION_PAUSE
Client → guardian: ACK, HEARTBEAT, REQUEST_OVERRIDE
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .config import is_hardened_install, repo_id

GPC_PROTOCOL_VERSION = "0.1"

GUARDIAN_TO_CLIENT = frozenset({
    "INCIDENT", "LOCKDOWN", "INSTRUCTION", "POLICY_UPDATE", "SESSION_PAUSE",
})
CLIENT_TO_GUARDIAN = frozenset({"ACK", "HEARTBEAT", "REQUEST_OVERRIDE"})


def _state_dir(hardened: bool = False) -> Path:
    if hardened:
        return Path("/var/db/deadpush")
    return Path.home() / ".deadpush"


def gpc_socket_path(repo_root: Path, *, hardened: bool | None = None) -> Path:
    """Path to the GPC Unix socket for a repo."""
    if hardened is None:
        hardened = is_hardened_install(repo_root)
    rid = repo_id(repo_root)
    return _state_dir(hardened) / f"gpc.{rid}.sock"


@dataclass
class GpcMessage:
    type: str
    repo_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    payload: dict[str, Any] = field(default_factory=dict)
    message_id: str = ""

    def to_line(self) -> str:
        return json.dumps(asdict(self), default=str) + "\n"

    @classmethod
    def from_line(cls, line: str) -> GpcMessage:
        data = json.loads(line)
        return cls(
            type=data.get("type", ""),
            repo_id=data.get("repo_id", ""),
            timestamp=data.get("timestamp", ""),
            payload=data.get("payload", {}),
            message_id=data.get("message_id", ""),
        )


class GpcServer:
    """Unix socket server that broadcasts guardian events to subscribers."""

    def __init__(self, repo_root: Path, *, hardened: bool = False):
        self.repo_root = repo_root.resolve()
        self.hardened = hardened
        self.rid = repo_id(self.repo_root)
        self.socket_path = gpc_socket_path(self.repo_root, hardened=hardened)
        self._clients: list[socket.socket] = []
        self._lock = threading.Lock()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(self.socket_path))
        try:
            os.chmod(self.socket_path, 0o600)
        except OSError:
            pass
        self._server.listen(8)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="gpc-server")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        with self._lock:
            for c in self._clients:
                try:
                    c.close()
                except OSError:
                    pass
            self._clients.clear()
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

    def broadcast(self, msg: GpcMessage) -> None:
        if not msg.repo_id:
            msg.repo_id = self.rid
        line = msg.to_line()
        dead: list[socket.socket] = []
        with self._lock:
            for client in self._clients:
                try:
                    client.sendall(line.encode("utf-8"))
                except OSError:
                    dead.append(client)
            for d in dead:
                try:
                    self._clients.remove(d)
                    d.close()
                except (ValueError, OSError):
                    pass

    def emit_incident(self, category: str, description: str, **extra: Any) -> None:
        self.broadcast(GpcMessage(
            type="INCIDENT",
            message_id=f"inc-{int(time.time() * 1000)}",
            payload={"category": category, "description": description, **extra},
        ))

    def emit_lockdown(self, reason: str) -> None:
        self.broadcast(GpcMessage(
            type="LOCKDOWN",
            message_id=f"lock-{int(time.time() * 1000)}",
            payload={"reason": reason},
        ))

    def emit_instruction(self, text: str, **extra: Any) -> None:
        self.broadcast(GpcMessage(
            type="INSTRUCTION",
            message_id=f"instr-{int(time.time() * 1000)}",
            payload={"text": text, **extra},
        ))

    def _accept_loop(self) -> None:
        while self._running and self._server:
            try:
                self._server.settimeout(1.0)
                conn, _ = self._server.accept()
                with self._lock:
                    self._clients.append(conn)
                threading.Thread(
                    target=self._client_reader,
                    args=(conn,),
                    daemon=True,
                    name="gpc-client-reader",
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _client_reader(self, conn: socket.socket) -> None:
        buf = b""
        try:
            while self._running:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        self._handle_client_message(line.decode("utf-8", errors="replace"))
        except OSError:
            pass
        finally:
            with self._lock:
                if conn in self._clients:
                    self._clients.remove(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _handle_client_message(self, line: str) -> None:
        try:
            msg = GpcMessage.from_line(line)
        except json.JSONDecodeError:
            return
        if msg.type not in CLIENT_TO_GUARDIAN:
            return
        # v0: ACK/HEARTBEAT are received but not acted on yet.


class GpcClient:
    """Subscribe to guardian push events on a Unix socket."""

    def __init__(
        self,
        repo_root: Path,
        *,
        hardened: bool = False,
        on_message: Callable[[GpcMessage], None] | None = None,
    ):
        self.repo_root = repo_root.resolve()
        self.hardened = hardened
        self.socket_path = gpc_socket_path(repo_root, hardened=hardened)
        self.on_message = on_message
        self._thread: threading.Thread | None = None
        self._running = False

    def connect_and_listen(self, *, blocking: bool = False) -> None:
        self._running = True
        if blocking:
            self._listen_loop()
        else:
            self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="gpc-client")
            self._thread.start()

    def stop(self) -> None:
        self._running = False

    def send_ack(self, message_id: str) -> None:
        self._send(GpcMessage(type="ACK", message_id=message_id, repo_id=repo_id(self.repo_root)))

    def send_heartbeat(self) -> None:
        self._send(GpcMessage(type="HEARTBEAT", repo_id=repo_id(self.repo_root)))

    def _send(self, msg: GpcMessage) -> None:
        if not self.socket_path.exists():
            return
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(str(self.socket_path))
                s.sendall(msg.to_line().encode("utf-8"))
        except OSError:
            pass

    def _listen_loop(self) -> None:
        while self._running:
            if not self.socket_path.exists():
                time.sleep(1.0)
                continue
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(str(self.socket_path))
                    buf = b""
                    while self._running:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            if not line.strip():
                                continue
                            try:
                                msg = GpcMessage.from_line(line.decode("utf-8"))
                            except json.JSONDecodeError:
                                continue
                            if self.on_message:
                                self.on_message(msg)
            except OSError:
                time.sleep(1.0)
