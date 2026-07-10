"""End-to-end stdio tests for deadpush mcp-proxy."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from deadpush.mcp_proxy import McpProxy


FIXTURE = Path(__file__).parent / "fixtures" / "mock_mcp_downstream.py"


def test_mcp_proxy_intercepts_blocked_tools_call(temp_repo: Path, tmp_path: Path):
    """Blocked tools/call must not reach the downstream MCP server."""
    marker = tmp_path / "downstream_called.txt"
    downstream = [sys.executable, str(FIXTURE)]
    proxy = McpProxy(downstream, repo_root=temp_repo)

    proc = subprocess.Popen(
        downstream,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env={**dict(**{"MOCK_MCP_MARKER": str(marker)}), **dict(__import__("os").environ)},
    )
    assert proc.stdin and proc.stdout

    proxy._proc = proc  # type: ignore[attr-defined]

    blocked_line = json.dumps({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "CLAUDE.md", "content": "# bad instructions\n"},
        },
    })
    response_line = proxy._maybe_intercept(blocked_line)
    assert response_line is not None
    resp = json.loads(response_line)
    assert resp["id"] == 42
    assert resp["result"]["isError"] is True
    assert not marker.exists()

    allowed_line = json.dumps({
        "jsonrpc": "2.0",
        "id": 43,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "good.py", "content": "x = 1\n"},
        },
    })
    assert proxy._maybe_intercept(allowed_line) is None

    proc.terminate()


def test_mcp_proxy_forwards_allowed_call(temp_repo: Path, tmp_path: Path):
    """Allowed tools/call is forwarded to the downstream MCP server."""
    import os

    marker = tmp_path / "downstream_called.txt"
    env = {**os.environ, "MOCK_MCP_MARKER": str(marker)}
    proc = subprocess.Popen(
        [sys.executable, str(FIXTURE)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
    )
    assert proc.stdin and proc.stdout

    proxy = McpProxy([sys.executable, str(FIXTURE)], repo_root=temp_repo)
    proxy._proc = proc

    allowed_line = json.dumps({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "ok.py", "content": "def ok(): return 1\n"},
        },
    })
    assert proxy._maybe_intercept(allowed_line) is None

    proc.stdin.write(allowed_line + "\n")
    proc.stdin.flush()
    out = proc.stdout.readline()
    assert out
    resp = json.loads(out)
    assert resp.get("id") == 99
    assert marker.exists()

    proc.terminate()
