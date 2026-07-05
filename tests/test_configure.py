"""Tests for deadpush configure cursor/claude MCP wrapping."""

from __future__ import annotations

import json
from pathlib import Path

from deadpush.configure import (
    ORIGINAL_MARKER,
    PROXY_MARKER,
    configure_cursor_mcp,
    unwrap_server_entry,
    wrap_server_entry,
)


def test_wrap_server_entry():
    entry = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]}
    wrapped = wrap_server_entry(entry, deadpush_cmd="/usr/bin/deadpush")
    assert wrapped["command"] == "/usr/bin/deadpush"
    assert wrapped["args"] == [
        "mcp-proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", ".",
    ]
    assert wrapped[PROXY_MARKER] is True
    assert wrapped[ORIGINAL_MARKER]["command"] == "npx"


def test_wrap_server_entry_idempotent():
    entry = {"command": "npx", "args": ["x"]}
    once = wrap_server_entry(entry, deadpush_cmd="/usr/bin/deadpush")
    twice = wrap_server_entry(once, deadpush_cmd="/usr/bin/deadpush")
    assert twice["args"].count("mcp-proxy") == 1


def test_unwrap_server_entry():
    wrapped = {
        "command": "/usr/bin/deadpush",
        "args": ["mcp-proxy", "--", "npx", "x"],
        PROXY_MARKER: True,
        ORIGINAL_MARKER: {"command": "npx", "args": ["x"]},
    }
    restored = unwrap_server_entry(wrapped)
    assert restored == {"command": "npx", "args": ["x"]}


def test_configure_cursor_mcp_wrap_and_unwrap(temp_repo: Path):
    cursor_dir = temp_repo / ".cursor"
    cursor_dir.mkdir()
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "server-filesystem", "."],
            },
        },
    }
    (cursor_dir / "mcp.json").write_text(json.dumps(config), encoding="utf-8")

    result = configure_cursor_mcp(temp_repo)
    assert result["proxied"] is True
    assert "filesystem" in result["servers"]

    data = json.loads((cursor_dir / "mcp.json").read_text(encoding="utf-8"))
    entry = data["mcpServers"]["filesystem"]
    assert entry["args"][0] == "mcp-proxy"
    assert (cursor_dir / "mcp.json.deadpush.bak").exists()

    configure_cursor_mcp(temp_repo, unwrap=True)
    data2 = json.loads((cursor_dir / "mcp.json").read_text(encoding="utf-8"))
    entry2 = data2["mcpServers"]["filesystem"]
    assert entry2["command"] == "npx"
    assert PROXY_MARKER not in entry2
