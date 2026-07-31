"""Best-effort GPC emission for staged git recovery (thesis Phase 5).

Does not implement negotiate / human escalate — only structured events with a
lightweight ``lifecycle`` tag for a future protocol state machine.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Sequence

logger = logging.getLogger("deadpush.gpc_staged")


def emit_staged_recovery_events(
    repo_root: Path,
    *,
    kind: str,
    reason: str,
    savepoint_id: str = "",
    label: str = "",
    alternatives: Sequence[str] = (),
    argv: Sequence[str] = (),
) -> bool:
    """Notify the GPC guardian of a staged deny when a socket is available.

    Returns True if a REPORT_STAGED (or equivalent) was sent. Failures are
    swallowed — staged deny must still work with stderr-only feedback.

    Requires ``DEADPUSH_GPC_SOCKET`` pointing at an existing socket. Sandbox
    without a socket must not stall the deny path.
    """
    socket_env = os.environ.get("DEADPUSH_GPC_SOCKET", "").strip()
    if not socket_env:
        return False
    socket_path = Path(socket_env)
    if not socket_path.exists():
        logger.debug("GPC staged emit skipped: socket missing %s", socket_path)
        return False

    client = None
    try:
        from .config import is_hardened_install
        from .gpc import GpcClient

        # Reporter only — must not auto-ACK re-broadcast durable events or it
        # would drain the shared outbox before a reconnecting relay can replay.
        client = GpcClient(
            repo_root,
            hardened=is_hardened_install(repo_root),
            auto_ack=False,
        )
        client.socket_path = socket_path
        # Persistent connection avoids short-lived connect/send/close races
        # (same pattern as MCP PROXY_BLOCK tests / Linux CI).
        client.connect_and_listen()
        time.sleep(0.05)
        return client.send_report_staged(
            kind=kind,
            reason=reason,
            savepoint_id=savepoint_id,
            label=label,
            alternatives=list(alternatives),
            source="staged-git",
            argv=list(argv),
        )
    except Exception as e:  # noqa: BLE001 — never fail the deny path
        logger.debug("GPC staged emit skipped: %s", e)
        return False
    finally:
        if client is not None:
            try:
                client.stop()
            except Exception:
                pass
