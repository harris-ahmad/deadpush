"""Tests for tamper-evident audit chain."""

from __future__ import annotations

import json
from pathlib import Path

from deadpush.audit import (
    EVENT_MCP_PROXY_BLOCK,
    EVENT_QUARANTINE,
    append_audit_event,
    audit_log_path,
    export_sarif,
    verify_audit_chain,
)


def test_append_and_verify_chain(temp_repo: Path):
    append_audit_event(temp_repo, EVENT_QUARANTINE, {"file": "a.py", "description": "eval"})
    append_audit_event(temp_repo, EVENT_MCP_PROXY_BLOCK, {"tool": "write_file", "file": "b.py"})
    path = audit_log_path(temp_repo)
    ok, errors = verify_audit_chain(path)
    assert ok, errors
    assert path.exists()
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    second = json.loads(lines[1])
    first = json.loads(lines[0])
    assert second["prev_hash"] == first["hash"]


def test_verify_detects_tamper(temp_repo: Path):
    append_audit_event(temp_repo, EVENT_QUARANTINE, {"file": "x.py"})
    path = audit_log_path(temp_repo)
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["payload"]["description"] = "tampered"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    ok, errors = verify_audit_chain(path)
    assert not ok
    assert any("hash mismatch" in e for e in errors)


def test_export_sarif(temp_repo: Path):
    append_audit_event(temp_repo, EVENT_QUARANTINE, {
        "file": "src/evil.py",
        "description": "Dynamic code execution",
        "category": "security",
    })
    sarif = export_sarif(temp_repo)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert sarif["runs"][0]["results"][0]["ruleId"] == "deadpush/security"


def test_empty_chain_valid(temp_repo: Path):
    ok, errors = verify_audit_chain(repo_root=temp_repo)
    assert ok
    assert errors == []
