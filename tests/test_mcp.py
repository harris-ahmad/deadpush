"""Tests for MCP server protocol and tool handlers."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = str(Path(__file__).resolve().parent.parent)
VENV_PY = str(Path(REPO_ROOT) / ".venv" / "bin" / "python3")


def _spawn_mcp_server(repo_root: Path):
    """Launch MCP server as a subprocess and return stdin/stdout."""
    proc = subprocess.Popen(
        [VENV_PY, "-c", f"""
import sys, os
sys.path.insert(0, {json.dumps(REPO_ROOT)})
os.environ['PYTHONPATH'] = {json.dumps(REPO_ROOT)}
from deadpush.mcp_server import McpServer
server = McpServer()
server.run()
"""],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(repo_root),
    )
    return proc


def _send(proc, msg):
    line = json.dumps(msg) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


class TestMcpProtocol:
    def test_initialize(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            resp = _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            assert "result" in resp
            assert resp["result"]["protocolVersion"] == "2024-11-05"
            assert resp["result"]["capabilities"]["tools"] == {}
            assert resp["result"]["serverInfo"]["name"] == "deadpush"
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_tools_list(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            tools = resp["result"]["tools"]
            names = [t["name"] for t in tools]
            assert "write_file" in names
            assert "check_file" in names
            assert "scan" in names
            assert "get_runtime_config" in names
            assert "add_allowed_pattern" in names
            assert "remove_allowed_pattern" in names
            assert "ignore_path" in names
            assert "set_guardrail_level" in names
            assert "reset_runtime_config" in names
            assert "get_write_diff" in names
            assert "allow_sensitive_write" in names
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)


class TestMcpConfigTools:
    def test_add_and_get_allowed_pattern(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            # Add pattern — omit description to test optional
            ap = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "add_allowed_pattern", "arguments": {"pattern": "safe_eval"}
            }})
            assert json.loads(ap["result"]["content"][0]["text"])["success"]

            # Get config
            gc = _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "get_runtime_config", "arguments": {}
            }})
            data = json.loads(gc["result"]["content"][0]["text"])
            assert len(data["data"]["allowed_patterns"]) == 1
            assert data["data"]["allowed_patterns"][0]["pattern"] == "safe_eval"
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_remove_allowed_pattern(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "add_allowed_pattern", "arguments": {"pattern": "my_pat"}
            }})

            rp = _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "remove_allowed_pattern", "arguments": {"pattern": "my_pat"}
            }})
            assert json.loads(rp["result"]["content"][0]["text"])["success"]

            gc = _send(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                "name": "get_runtime_config", "arguments": {}
            }})
            assert len(json.loads(gc["result"]["content"][0]["text"])["data"]["allowed_patterns"]) == 0
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_set_guardrail_level(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            sg = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "set_guardrail_level", "arguments": {"category": "debris", "level": "off"}
            }})
            assert json.loads(sg["result"]["content"][0]["text"])["success"]

            gc = _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "get_runtime_config", "arguments": {}
            }})
            assert json.loads(gc["result"]["content"][0]["text"])["data"]["guardrail_levels"]["debris"] == "off"
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_ignore_path(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            ig = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "ignore_path", "arguments": {"path": "generated/*"}
            }})
            assert json.loads(ig["result"]["content"][0]["text"])["success"]
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_reset_runtime_config(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "add_allowed_pattern", "arguments": {"pattern": "p1"}
            }})
            _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "set_guardrail_level", "arguments": {"category": "debris", "level": "off"}
            }})

            rs = _send(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                "name": "reset_runtime_config", "arguments": {}
            }})
            assert json.loads(rs["result"]["content"][0]["text"])["success"]

            gc = _send(proc, {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
                "name": "get_runtime_config", "arguments": {}
            }})
            data = json.loads(gc["result"]["content"][0]["text"])["data"]
            assert len(data["allowed_patterns"]) == 0
            assert data["guardrail_levels"]["debris"] == "warn"
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_invalid_guardrail_level_rejected(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            bad = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "set_guardrail_level", "arguments": {"category": "debris", "level": "invalid"}
            }})
            assert json.loads(bad["result"]["content"][0]["text"])["success"] is False
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_unknown_tool(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "nonexistent_tool", "arguments": {}
            }})
            assert resp["result"]["isError"] is True
            assert "Unknown tool" in resp["result"]["content"][0]["text"]
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_missing_required_args(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "add_allowed_pattern", "arguments": {}
            }})
            assert json.loads(resp["result"]["content"][0]["text"])["success"] is False
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_check_file_tool(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "check_file", "arguments": {"path": "test.py", "content": "x = 1"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]
            assert result["data"]["would_block"] is False
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_check_file_blocked(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "check_file", "arguments": {"path": "evil.py", "content": "eval(inject)"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]
            assert result["data"]["would_block"] is True
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_get_status(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_status", "arguments": {}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]
            assert "repo_root" in result["data"]
            assert "tools" in result["data"]
            assert "write_file" in result["data"]["tools"]
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_get_feedback_empty(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_feedback", "arguments": {}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]
            assert result["data"]["count"] == 0
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_quarantine_list_empty(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "quarantine_list", "arguments": {}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_get_write_diff_new_file(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_write_diff", "arguments": {"path": "new.py", "content": "x = 1"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]
            assert result["data"]["file_exists"] is False
            assert result["data"]["would_block"] is False
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_get_write_diff_existing_file(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            (temp_repo / "existing.py").write_text("old content\n")
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_write_diff", "arguments": {"path": "existing.py", "content": "new content\n"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]
            assert result["data"]["file_exists"] is True
            assert "diff" in result["data"]
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)

    def test_allow_sensitive_write(self, temp_repo):
        proc = _spawn_mcp_server(temp_repo)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "allow_sensitive_write", "arguments": {"path": "Dockerfile"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"]

            # Verify path was added to allowed patterns
            gc = _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "get_runtime_config", "arguments": {}
            }})
            config = json.loads(gc["result"]["content"][0]["text"])
            patterns = [p["pattern"] for p in config["data"]["allowed_patterns"]]
            assert any("Dockerfile" in p for p in patterns)
        finally:
            _send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
            proc.wait(timeout=5)
