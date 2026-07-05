"""
Guardian Push Channel (GPC) — bidirectional push protocol outside MCP.

Transport: Unix domain socket, newline-delimited JSON.

Guardian → client: INCIDENT, LOCKDOWN, INSTRUCTION, POLICY_UPDATE, SESSION_PAUSE, WELCOME
Client → guardian: ACK, HEARTBEAT, REQUEST_OVERRIDE
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .config import is_hardened_install, repo_id

logger = logging.getLogger("deadpush.gpc")

GPC_PROTOCOL_VERSION = "1.0"
MAX_LINE_BYTES = 65536
CLIENT_STALE_SECONDS = 120.0
RECONNECT_BASE_DELAY = 0.5
RECONNECT_MAX_DELAY = 30.0

GUARDIAN_TO_CLIENT = frozenset({
    "INCIDENT", "LOCKDOWN", "INSTRUCTION", "POLICY_UPDATE", "SESSION_PAUSE", "WELCOME",
})
CLIENT_TO_GUARDIAN = frozenset({"ACK", "HEARTBEAT", "REQUEST_OVERRIDE"})


def _state_dir(hardened: bool = False) -> Path:
    if hardened:
        return Path("/var/db/deadpush")
    return Path.home() / ".deadpush"


def gpc_socket_path(repo_root: Path, *, hardened: bool | None = None) -> Path:
    """Path to the GPC Unix socket for a repo."""
    resolved = Path(repo_root).resolve()
    if hardened is None:
        hardened = is_hardened_install(resolved)
    rid = repo_id(resolved)
    return _state_dir(hardened) / f"gpc.{rid}.sock"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_message_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class GpcMessage:
    type: str
    repo_id: str = ""
    timestamp: str = field(default_factory=_now_iso)
    payload: dict[str, Any] = field(default_factory=dict)
    message_id: str = ""
    protocol_version: str = GPC_PROTOCOL_VERSION

    def validate(self) -> tuple[bool, str]:
        if not self.type:
            return False, "missing type"
        if len(self.type) > 64:
            return False, "type too long"
        if self.type in GUARDIAN_TO_CLIENT | CLIENT_TO_GUARDIAN:
            if not self.protocol_version:
                return False, "missing protocol_version"
        return True, ""

    def to_line(self) -> str:
        data = asdict(self)
        line = json.dumps(data, default=str, separators=(",", ":"))
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ValueError(f"GPC message exceeds {MAX_LINE_BYTES} bytes")
        return line + "\n"

    @classmethod
    def from_line(cls, line: str) -> GpcMessage:
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ValueError("GPC line too large")
        data = json.loads(line)
        return cls(
            type=str(data.get("type", "")),
            repo_id=str(data.get("repo_id", "")),
            timestamp=str(data.get("timestamp", "")),
            payload=data.get("payload") if isinstance(data.get("payload"), dict) else {},
            message_id=str(data.get("message_id", "")),
            protocol_version=str(data.get("protocol_version", GPC_PROTOCOL_VERSION)),
        )


@dataclass
class _ClientState:
    conn: socket.socket
    connected_at: float
    last_heartbeat: float
    acks: set[str] = field(default_factory=set)


class GpcServer:
    """Unix socket server that broadcasts guardian events to subscribers."""

    def __init__(
        self,
        repo_root: Path,
        *,
        hardened: bool = False,
        on_client_message: Callable[[GpcMessage, _ClientState], None] | None = None,
    ):
        self.repo_root = repo_root.resolve()
        self.hardened = hardened
        self.rid = repo_id(self.repo_root)
        self.socket_path = gpc_socket_path(self.repo_root, hardened=hardened)
        self.on_client_message = on_client_message
        self._clients: dict[int, _ClientState] = {}
        self._lock = threading.RLock()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._override_log = self.repo_root / ".deadpush" / "gpc_overrides.jsonl"

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def start(self) -> None:
        if self._running:
            return
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError as e:
                logger.warning("Could not remove stale GPC socket %s: %s", self.socket_path, e)

        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except (OSError, AttributeError):
            pass
        self._server.bind(str(self.socket_path))
        try:
            os.chmod(self.socket_path, 0o600)
        except OSError:
            pass
        self._server.listen(16)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="gpc-server")
        self._thread.start()
        logger.info("GPC server listening on %s", self.socket_path)

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        with self._lock:
            for state in list(self._clients.values()):
                try:
                    state.conn.close()
                except OSError:
                    pass
            self._clients.clear()
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

    def _prepare(self, msg: GpcMessage) -> GpcMessage:
        if not msg.repo_id:
            msg.repo_id = self.rid
        if not msg.message_id:
            msg.message_id = _new_message_id(msg.type.lower())
        msg.protocol_version = GPC_PROTOCOL_VERSION
        ok, err = msg.validate()
        if not ok:
            raise ValueError(f"invalid GPC message: {err}")
        return msg

    def broadcast(self, msg: GpcMessage) -> int:
        """Send *msg* to all connected clients. Returns delivery count."""
        msg = self._prepare(msg)
        line = msg.to_line()
        payload = line.encode("utf-8")
        delivered = 0
        dead: list[int] = []
        with self._lock:
            for cid, state in self._clients.items():
                try:
                    state.conn.sendall(payload)
                    delivered += 1
                except OSError:
                    dead.append(cid)
            for cid in dead:
                try:
                    self._clients[cid].conn.close()
                except OSError:
                    pass
                self._clients.pop(cid, None)
        return delivered

    def emit_welcome(self) -> None:
        self.broadcast(GpcMessage(
            type="WELCOME",
            payload={
                "repo_root": str(self.repo_root),
                "protocol_version": GPC_PROTOCOL_VERSION,
                "supported": sorted(GUARDIAN_TO_CLIENT | CLIENT_TO_GUARDIAN),
            },
        ))

    def emit_incident(self, category: str, description: str, **extra: Any) -> int:
        return self.broadcast(GpcMessage(
            type="INCIDENT",
            message_id=_new_message_id("inc"),
            payload={"category": category, "description": description, **extra},
        ))

    def emit_lockdown(self, reason: str, **extra: Any) -> int:
        return self.broadcast(GpcMessage(
            type="LOCKDOWN",
            message_id=_new_message_id("lock"),
            payload={"reason": reason, **extra},
        ))

    def emit_instruction(self, text: str, **extra: Any) -> int:
        return self.broadcast(GpcMessage(
            type="INSTRUCTION",
            message_id=_new_message_id("instr"),
            payload={"text": text, **extra},
        ))

    def emit_policy_update(self, summary: str, **extra: Any) -> int:
        return self.broadcast(GpcMessage(
            type="POLICY_UPDATE",
            message_id=_new_message_id("pol"),
            payload={"summary": summary, **extra},
        ))

    def emit_session_pause(self, reason: str, until: str | None = None, **extra: Any) -> int:
        payload: dict[str, Any] = {"reason": reason, **extra}
        if until:
            payload["until"] = until
        return self.broadcast(GpcMessage(
            type="SESSION_PAUSE",
            message_id=_new_message_id("pause"),
            payload=payload,
        ))

    def _accept_loop(self) -> None:
        while self._running and self._server:
            try:
                self._server.settimeout(1.0)
                conn, _ = self._server.accept()
                now = time.time()
                state = _ClientState(conn=conn, connected_at=now, last_heartbeat=now)
                with self._lock:
                    self._clients[id(conn)] = state
                threading.Thread(
                    target=self._client_reader,
                    args=(conn, state),
                    daemon=True,
                    name="gpc-client-reader",
                ).start()
                self.emit_welcome()
            except socket.timeout:
                self._prune_stale_clients()
                continue
            except OSError:
                if self._running:
                    logger.debug("GPC accept loop ended", exc_info=True)
                break

    def _prune_stale_clients(self) -> None:
        cutoff = time.time() - CLIENT_STALE_SECONDS
        with self._lock:
            stale = [cid for cid, s in self._clients.items() if s.last_heartbeat < cutoff]
            for cid in stale:
                try:
                    self._clients[cid].conn.close()
                except OSError:
                    pass
                self._clients.pop(cid, None)

    def _client_reader(self, conn: socket.socket, state: _ClientState) -> None:
        buf = b""
        try:
            conn.settimeout(5.0)
            while self._running:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        self._handle_client_message(line.decode("utf-8", errors="replace"), state)
        except OSError:
            pass
        finally:
            with self._lock:
                self._clients.pop(id(conn), None)
            try:
                conn.close()
            except OSError:
                pass

    def _handle_client_message(self, line: str, state: _ClientState) -> None:
        try:
            msg = GpcMessage.from_line(line)
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug("Ignoring malformed GPC client message: %s", e)
            return
        if msg.type not in CLIENT_TO_GUARDIAN:
            logger.debug("Ignoring unknown GPC client message type: %s", msg.type)
            return

        state.last_heartbeat = time.time()

        if msg.type == "ACK" and msg.message_id:
            state.acks.add(msg.message_id)
        elif msg.type == "HEARTBEAT":
            pass
        elif msg.type == "REQUEST_OVERRIDE":
            self._log_override_request(msg)

        if self.on_client_message:
            try:
                self.on_client_message(msg, state)
            except Exception:
                logger.exception("GPC on_client_message handler failed")

    def _log_override_request(self, msg: GpcMessage) -> None:
        record = {
            "timestamp": _now_iso(),
            "message_id": msg.message_id,
            "payload": msg.payload,
            "status": "pending_human_review",
        }
        try:
            self._override_log.parent.mkdir(parents=True, exist_ok=True)
            with self._override_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError as e:
            logger.warning("Could not persist GPC override request: %s", e)


class GpcClient:
    """Subscribe to guardian push events on a Unix socket."""

    def __init__(
        self,
        repo_root: Path,
        *,
        hardened: bool = False,
        on_message: Callable[[GpcMessage], None] | None = None,
        auto_ack: bool = True,
    ):
        self.repo_root = repo_root.resolve()
        self.hardened = hardened
        self.rid = repo_id(self.repo_root)
        self.socket_path = gpc_socket_path(self.repo_root, hardened=hardened)
        self.on_message = on_message
        self.auto_ack = auto_ack
        self._thread: threading.Thread | None = None
        self._running = False
        self._conn: socket.socket | None = None
        self._conn_lock = threading.Lock()
        self._backoff = RECONNECT_BASE_DELAY

    def stop(self) -> None:
        self._running = False
        with self._conn_lock:
            if self._conn:
                try:
                    self._conn.close()
                except OSError:
                    pass
                self._conn = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def connect_and_listen(self, *, blocking: bool = False) -> None:
        self._running = True
        if blocking:
            self._listen_loop()
        else:
            self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="gpc-client")
            self._thread.start()

    def send_ack(self, message_id: str) -> bool:
        return self._send(GpcMessage(
            type="ACK",
            message_id=message_id,
            repo_id=self.rid,
            payload={"ack_for": message_id},
        ))

    def send_heartbeat(self) -> bool:
        return self._send(GpcMessage(type="HEARTBEAT", repo_id=self.rid))

    def send_request_override(self, reason: str, *, related_message_id: str = "") -> bool:
        return self._send(GpcMessage(
            type="REQUEST_OVERRIDE",
            message_id=_new_message_id("ovr"),
            repo_id=self.rid,
            payload={"reason": reason, "related_message_id": related_message_id},
        ))

    def _send(self, msg: GpcMessage, *, keep_open: bool | None = None) -> bool:
        if keep_open is None:
            keep_open = self._thread is not None and self._thread.is_alive()

        for attempt in range(5):
            if not self.socket_path.exists():
                time.sleep(0.05 * (attempt + 1))
                continue
            try:
                data = msg.to_line().encode("utf-8")
                with self._conn_lock:
                    if self._conn is None or not keep_open:
                        if self._conn is not None:
                            try:
                                self._conn.close()
                            except OSError:
                                pass
                        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        s.settimeout(5.0)
                        s.connect(str(self.socket_path))
                        if keep_open:
                            self._conn = s
                        else:
                            s.sendall(data)
                            try:
                                s.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            s.close()
                            return True
                    assert self._conn is not None
                    self._conn.sendall(data)
                    if not keep_open:
                        try:
                            self._conn.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        self._conn.close()
                        self._conn = None
                return True
            except OSError as e:
                logger.debug("GPC send attempt %s failed: %s", attempt + 1, e)
                with self._conn_lock:
                    if self._conn:
                        try:
                            self._conn.close()
                        except OSError:
                            pass
                        self._conn = None
                time.sleep(0.05 * (attempt + 1))
        return False

    def _listen_loop(self) -> None:
        while self._running:
            if not self.socket_path.exists():
                time.sleep(min(self._backoff, RECONNECT_MAX_DELAY))
                self._backoff = min(self._backoff * 2, RECONNECT_MAX_DELAY)
                continue
            try:
                with self._conn_lock:
                    self._conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self._conn.settimeout(30.0)
                    self._conn.connect(str(self.socket_path))
                self._backoff = RECONNECT_BASE_DELAY
                self.send_heartbeat()
                buf = b""
                while self._running:
                    with self._conn_lock:
                        conn = self._conn
                    if conn is None:
                        break
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        self.send_heartbeat()
                        continue
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            msg = GpcMessage.from_line(line.decode("utf-8"))
                        except (json.JSONDecodeError, ValueError):
                            continue
                        if self.auto_ack and msg.message_id and msg.type in GUARDIAN_TO_CLIENT:
                            self.send_ack(msg.message_id)
                        if self.on_message:
                            try:
                                self.on_message(msg)
                            except Exception:
                                logger.exception("GPC client on_message failed")
            except OSError:
                with self._conn_lock:
                    if self._conn:
                        try:
                            self._conn.close()
                        except OSError:
                            pass
                        self._conn = None
                if self._running:
                    time.sleep(min(self._backoff, RECONNECT_MAX_DELAY))
                    self._backoff = min(self._backoff * 2, RECONNECT_MAX_DELAY)
