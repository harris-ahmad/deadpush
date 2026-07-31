"""Best-effort GPC emission for staged git recovery (thesis Phase 5).

Does not implement negotiate / human escalate — only structured events with a
lightweight ``lifecycle`` tag for a future protocol state machine.
"""

from __future__ import annotations

import logging
import os
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

    Requires ``DEADPUSH_GPC_SOCKET`` pointing at an existing socket. Uses a
    one-shot send (no listen thread, no fixed sleep) so the deny path stays
    latency-sensitive. The client waits for server WELCOME then SHUT_WR so
    short-lived REPORT_STAGED deliveries are reliable on Linux.
    """
    socket_env = os.environ.get("DEADPUSH_GPC_SOCKET", "").strip()
    if not socket_env:
        return False
    socket_path = Path(socket_env)
    if not socket_path.exists():
        logger.debug("GPC staged emit skipped: socket missing %s", socket_path)
        return False

    try:
        from .config import is_hardened_install
        from .gpc import GpcClient

        # One-shot reporter: no connect_and_listen (avoids auto-ACK draining the
        # durable outbox and avoids a mandatory sleep on the deny path).
        client = GpcClient(
            repo_root,
            hardened=is_hardened_install(repo_root),
            auto_ack=False,
        )
        client.socket_path = socket_path
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
