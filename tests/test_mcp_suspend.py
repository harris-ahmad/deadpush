"""Tests for MCP suspension honored by mcp-proxy."""

from __future__ import annotations

from pathlib import Path

from deadpush.guard import _scoped_suspend_file
from deadpush.mcp_proxy import scan_tool_call


def test_scan_tool_call_blocked_when_suspended(temp_repo: Path):
    suspend = _scoped_suspend_file(temp_repo, hardened=False)
    suspend.parent.mkdir(parents=True, exist_ok=True)
    suspend.write_text("Safety score critical — MCP paused", encoding="utf-8")

    block = scan_tool_call(
        "read_file",
        {"path": "hello.py"},
        temp_repo,
    )
    assert block is not None
    assert block.get("isError") is True
    text = block["content"][0]["text"]
    assert "suspended" in text.lower()
    assert "Safety score critical" in text


def test_scan_tool_call_write_still_blocked_when_not_suspended(temp_repo: Path):
    block = scan_tool_call(
        "write_file",
        {"path": "CLAUDE.md", "content": "# bad instructions\n"},
        temp_repo,
    )
    assert block is not None
    assert "Blocked by deadpush guardrails" in block["content"][0]["text"]


def test_scan_tool_call_allows_read_when_not_suspended(temp_repo: Path):
    block = scan_tool_call("read_file", {"path": "hello.py"}, temp_repo)
    assert block is None
