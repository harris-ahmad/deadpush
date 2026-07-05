"""Append-only tamper-evident audit log with content-hashed chain."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import policy_dir

logger = logging.getLogger("deadpush.audit")

GENESIS_HASH = "0" * 64
AUDIT_FILENAME = "audit.chain.jsonl"

# Canonical event names for the audit trail.
EVENT_QUARANTINE = "guardrail.quarantine"
EVENT_LOCKDOWN = "guardrail.lockdown"
EVENT_MCP_PROXY_BLOCK = "mcp.proxy_block"
EVENT_POLICY_UPDATE = "policy.update"
EVENT_SESSION_PAUSE = "session.pause"
EVENT_GIT_HOOK_BLOCK = "git.hook_block"

_LOCKS: dict[str, threading.Lock] = {}


def audit_log_path(repo_root: Path) -> Path:
    """Return the append-only audit chain path for *repo_root*."""
    return policy_dir(repo_root) / AUDIT_FILENAME


def _lock_for(path: Path) -> threading.Lock:
    key = str(path.resolve())
    if key not in _LOCKS:
        _LOCKS[key] = threading.Lock()
    return _LOCKS[key]


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(prev_hash: str, seq: int, timestamp: str, event: str, payload: dict[str, Any]) -> str:
    body = f"{prev_hash}\n{seq}\n{timestamp}\n{event}\n{_canonical_payload(payload)}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _read_last_hash(path: Path) -> tuple[int, str]:
    if not path.exists():
        return 0, GENESIS_HASH
    seq = 0
    last_hash = GENESIS_HASH
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            seq = int(record.get("seq", seq))
            last_hash = str(record.get("hash", last_hash))
    except (OSError, json.JSONDecodeError, ValueError) as e:
        logger.warning("Could not read audit tail from %s: %s", path, e)
    return seq, last_hash


def append_audit_event(
    repo_root: Path,
    event: str,
    payload: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> dict[str, Any] | None:
    """Append one hash-chained audit record. Returns the record or None on failure."""
    path = audit_log_path(repo_root)
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    with _lock_for(path):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            seq, prev_hash = _read_last_hash(path)
            seq += 1
            entry_hash = _entry_hash(prev_hash, seq, ts, event, payload)
            record = {
                "seq": seq,
                "timestamp": ts,
                "event": event,
                "payload": payload,
                "prev_hash": prev_hash,
                "hash": entry_hash,
            }
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str, separators=(",", ":")) + "\n")
            return record
        except OSError as e:
            logger.warning("Failed to append audit event %s: %s", event, e)
            return None


def load_audit_chain(path: Path | None = None, *, repo_root: Path | None = None) -> list[dict[str, Any]]:
    """Load all audit records from the chain file."""
    if path is None:
        if repo_root is None:
            raise ValueError("provide path or repo_root")
        path = audit_log_path(repo_root)
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to load audit chain %s: %s", path, e)
    return records


def verify_audit_chain(
    path: Path | None = None,
    *,
    repo_root: Path | None = None,
) -> tuple[bool, list[str]]:
    """Verify hash chain integrity. Returns (ok, error_messages)."""
    if path is None:
        if repo_root is None:
            raise ValueError("provide path or repo_root")
        path = audit_log_path(repo_root)

    if not path.exists():
        return True, []

    errors: list[str] = []
    expected_prev = GENESIS_HASH
    expected_seq = 0

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return False, [f"cannot read audit log: {e}"]

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line {i}: invalid JSON")
            continue

        seq = int(record.get("seq", -1))
        prev_hash = str(record.get("prev_hash", ""))
        entry_hash = str(record.get("hash", ""))
        event = str(record.get("event", ""))
        ts = str(record.get("timestamp", ""))
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}

        if seq != expected_seq + 1:
            errors.append(f"line {i}: expected seq {expected_seq + 1}, got {seq}")
        if prev_hash != expected_prev:
            errors.append(f"line {i}: prev_hash mismatch (tamper?)")
        computed = _entry_hash(prev_hash, seq, ts, event, payload)
        if computed != entry_hash:
            errors.append(f"line {i}: hash mismatch (tamper?)")

        expected_prev = entry_hash
        expected_seq = seq

    return len(errors) == 0, errors


def audit_summary(repo_root: Path) -> dict[str, Any]:
    """Return counts and verify status for doctor/status."""
    path = audit_log_path(repo_root)
    records = load_audit_chain(path)
    ok, errors = verify_audit_chain(path)
    by_event: dict[str, int] = {}
    for r in records:
        ev = str(r.get("event", "unknown"))
        by_event[ev] = by_event.get(ev, 0) + 1
    return {
        "path": str(path),
        "entries": len(records),
        "valid": ok,
        "errors": errors[:5],
        "by_event": by_event,
    }


def export_sarif(repo_root: Path, *, max_entries: int = 500) -> dict[str, Any]:
    """Export guardrail-related audit entries as SARIF 2.1.0."""
    from . import __version__

    records = load_audit_chain(repo_root=repo_root)[-max_entries:]
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    for record in records:
        event = str(record.get("event", ""))
        if event not in (EVENT_QUARANTINE, EVENT_LOCKDOWN, EVENT_MCP_PROXY_BLOCK, EVENT_GIT_HOOK_BLOCK):
            continue
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        category = str(payload.get("category", "guardrail"))
        rule_id = f"deadpush/{category}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": category,
                "shortDescription": {"text": f"deadpush {category} violation"},
            }
        file_uri = str(payload.get("file", ""))
        results.append({
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": str(payload.get("description", event))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri or "unknown"},
                },
            }],
            "partialFingerprints": {
                "auditSeq": str(record.get("seq", "")),
                "auditHash": str(record.get("hash", ""))[:16],
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "deadpush",
                    "version": __version__,
                    "informationUri": "https://github.com/harris-ahmad/deadpush",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }
