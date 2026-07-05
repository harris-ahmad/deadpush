"""GPC session wiring for deadpush run --sandbox (T2 mandatory integration)."""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import is_hardened_install, repo_id
from .gpc import GpcClient, GpcMessage, GpcServer, gpc_socket_path

logger = logging.getLogger("deadpush.gpc_session")

GPC_CONNECT_TIMEOUT = 5.0
GPC_STDERR_PREFIX = "DEADPUSH_GPC"


class GpcMandatoryError(RuntimeError):
    """Raised when a T2 sandbox session cannot establish mandatory GPC."""


def gpc_socket_reachable(socket_path: Path, *, timeout: float = 1.0) -> bool:
    """True when *socket_path* accepts a client connection and heartbeat."""
    if not socket_path.exists():
        return False
    client = GpcClient(Path("/"), hardened=False)
    client.socket_path = socket_path
    try:
        return client.send_heartbeat()
    except Exception:
        return False


def _default_relay_handler(msg: GpcMessage) -> None:
    """Surface guardian push events on stderr for wrapped agent processes."""
    if msg.type not in {"INCIDENT", "LOCKDOWN", "SESSION_PAUSE", "INSTRUCTION", "POLICY_UPDATE"}:
        return
    line = json.dumps(
        {"type": msg.type, "payload": msg.payload, "message_id": msg.message_id},
        default=str,
        separators=(",", ":"),
    )
    try:
        print(f"{GPC_STDERR_PREFIX}: {line}", file=sys.stderr, flush=True)
    except OSError:
        pass


class GpcSessionRelay:
    """Background GPC client — mandatory session-side subscription."""

    def __init__(
        self,
        repo_root: Path,
        *,
        hardened: bool = False,
        on_message: Callable[[GpcMessage], None] | None = None,
    ):
        self.repo_root = repo_root.resolve()
        self.hardened = hardened
        self._on_message = on_message or _default_relay_handler
        self._client: GpcClient | None = None
        self._connected = threading.Event()
        self._lockdown = threading.Event()
        self._running = False

    @property
    def lockdown_active(self) -> bool:
        return self._lockdown.is_set()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._client = GpcClient(self.repo_root, hardened=self.hardened, on_message=self._dispatch)
        self._client.connect_and_listen()

    def stop(self) -> None:
        self._running = False
        if self._client:
            self._client.stop()
            self._client = None

    def wait_connected(self, timeout: float = GPC_CONNECT_TIMEOUT) -> bool:
        return self._connected.wait(timeout)

    def _dispatch(self, msg: GpcMessage) -> None:
        if msg.type == "WELCOME":
            self._connected.set()
        elif msg.type == "LOCKDOWN":
            self._lockdown.set()
        try:
            self._on_message(msg)
        except Exception:
            logger.exception("GPC session relay handler failed")


@dataclass
class GpcSession:
    """Active GPC integration for a sandbox session."""

    repo_root: Path
    socket_path: Path
    relay: GpcSessionRelay
    server: GpcServer | None = None
    attached_external: bool = False
    _reporter: GpcClient | None = field(default=None, repr=False)

    @property
    def mandatory(self) -> bool:
        return True

    def emit_incident(self, category: str, description: str, **extra: Any) -> int:
        if self.server is not None:
            return self.server.emit_incident(category, description, **extra)
        reporter = self._reporter_client()
        if reporter.send_proxy_block(
            tool=str(extra.get("source", "sandbox")),
            description=description,
            file=str(extra.get("file", "")),
        ):
            return 1
        return 0

    def _reporter_client(self) -> GpcClient:
        if self._reporter is None:
            self._reporter = GpcClient(
                self.repo_root,
                hardened=is_hardened_install(self.repo_root),
            )
        return self._reporter

    def stop(self) -> None:
        self.relay.stop()
        if self._reporter is not None:
            self._reporter.stop()
            self._reporter = None
        if self.server is not None:
            self.server.stop()
            self.server = None


def apply_gpc_env(env: dict[str, str], session: GpcSession) -> None:
    env["DEADPUSH_GPC_SOCKET"] = str(session.socket_path)
    env["DEADPUSH_GPC_REQUIRED"] = "1"
    env["DEADPUSH_GPC_MANDATORY"] = "1"
    env["DEADPUSH_REPO_ID"] = repo_id(session.repo_root)


def start_gpc_session(
    repo_root: Path,
    *,
    hardened: bool = False,
    mandatory: bool = True,
    on_message: Callable[[GpcMessage], None] | None = None,
) -> GpcSession | None:
    """Start or attach GPC for a sandbox session.

    When the guardian daemon already owns the socket, attach a relay client
    without replacing the server. Otherwise start a session-local server.
    """
    repo = repo_root.resolve()
    socket_path = gpc_socket_path(repo, hardened=hardened)
    owned_server: GpcServer | None = None
    attached_external = False

    if gpc_socket_reachable(socket_path):
        attached_external = True
        logger.info("GPC attached to existing socket at %s", socket_path)
    else:
        owned_server = GpcServer(repo, hardened=hardened)
        try:
            owned_server.start()
        except OSError as e:
            if mandatory:
                raise GpcMandatoryError(f"GPC server could not start: {e}") from e
            logger.warning("GPC server unavailable: %s", e)
            return None
        if not owned_server.socket_path.exists():
            if mandatory:
                raise GpcMandatoryError("GPC server failed to bind socket")
            owned_server.stop()
            return None

    relay = GpcSessionRelay(repo, hardened=hardened, on_message=on_message)
    relay.start()

    if mandatory and not relay.wait_connected(GPC_CONNECT_TIMEOUT):
        relay.stop()
        if owned_server is not None:
            owned_server.stop()
        raise GpcMandatoryError(
            f"GPC session relay failed to connect within {GPC_CONNECT_TIMEOUT}s "
            f"(socket: {socket_path})"
        )

    return GpcSession(
        repo_root=repo,
        socket_path=socket_path,
        relay=relay,
        server=owned_server,
        attached_external=attached_external,
    )


def stop_gpc_session(session: GpcSession | None) -> None:
    if session is not None:
        session.stop()
