"""Durable GPC outbox — incidents survive until a client ACKs delivery."""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .gpc import GpcMessage

logger = logging.getLogger("deadpush.gpc.outbox")

OUTBOX_FILENAME = "gpc.outbox.jsonl"
MAX_PENDING = 500

# Guardian → client types that must survive offline clients until ACK.
DURABLE_TYPES = frozenset({
    "INCIDENT", "LOCKDOWN", "INSTRUCTION", "POLICY_UPDATE", "SESSION_PAUSE",
})


@dataclass
class OutboxStats:
    pending: int = 0
    appended: int = 0
    acked: int = 0
    drained: int = 0
    dropped: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "pending": self.pending,
            "appended": self.appended,
            "acked": self.acked,
            "drained": self.drained,
            "dropped": self.dropped,
        }


class GpcOutbox:
    """Append-only pending queue replayed to new subscribers until ACK."""

    def __init__(self, repo_root: Path):
        self._path = Path(repo_root).resolve() / ".deadpush" / OUTBOX_FILENAME
        self._lock = threading.RLock()
        self._stats = OutboxStats()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def stats(self) -> OutboxStats:
        return self._stats

    def describe(self) -> dict:
        with self._lock:
            pending = self._read_pending_unlocked()
            return {
                "path": str(self._path),
                "max_pending": MAX_PENDING,
                **self._stats.snapshot(),
                "pending": len(pending),
            }

    def append(self, msg: "GpcMessage") -> None:
        if msg.type not in DURABLE_TYPES or not msg.message_id:
            return
        record = {
            "message_id": msg.message_id,
            "type": msg.type,
            "repo_id": msg.repo_id,
            "timestamp": msg.timestamp,
            "payload": msg.payload,
            "protocol_version": msg.protocol_version,
        }
        line = json.dumps(record, default=str, separators=(",", ":"))
        with self._lock:
            pending = self._read_pending_unlocked()
            if any(e["message_id"] == msg.message_id for e in pending):
                return
            if len(pending) >= MAX_PENDING:
                self._stats.dropped += 1
                logger.warning(
                    "GPC outbox full (%s); dropping oldest pending message",
                    MAX_PENDING,
                )
                pending = pending[1:]
            pending.append(record)
            self._write_pending_unlocked(pending)
            self._stats.appended += 1

    def list_pending(self) -> list["GpcMessage"]:
        from .gpc import GpcMessage

        with self._lock:
            return [self._record_to_message(r) for r in self._read_pending_unlocked()]

    def ack(self, message_id: str) -> bool:
        if not message_id:
            return False
        with self._lock:
            pending = self._read_pending_unlocked()
            kept = [r for r in pending if r.get("message_id") != message_id]
            if len(kept) == len(pending):
                return False
            self._write_pending_unlocked(kept)
            self._stats.acked += 1
            return True

    def mark_drained(self, count: int) -> None:
        if count <= 0:
            return
        with self._lock:
            self._stats.drained += count

    def _record_to_message(self, record: dict) -> "GpcMessage":
        from .gpc import GpcMessage

        return GpcMessage(
            type=str(record.get("type", "")),
            repo_id=str(record.get("repo_id", "")),
            timestamp=str(record.get("timestamp", "")),
            payload=record.get("payload") if isinstance(record.get("payload"), dict) else {},
            message_id=str(record.get("message_id", "")),
            protocol_version=str(record.get("protocol_version", "")),
        )

    def _read_pending_unlocked(self) -> list[dict]:
        if not self._path.exists():
            return []
        entries: list[dict] = []
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("Could not read GPC outbox %s: %s", self._path, e)
            return []
        for raw in text.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("message_id"):
                entries.append(data)
        return entries

    def _write_pending_unlocked(self, entries: list[dict]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            body = "".join(
                json.dumps(e, default=str, separators=(",", ":")) + "\n"
                for e in entries
            )
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(body, encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as e:
            logger.warning("Could not write GPC outbox %s: %s", self._path, e)
