"""Tests for MCP server protocol and tool handlers."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = str(Path(__file__).resolve().parent.parent)
VENV_PY = str(Path(REPO_ROOT) / ".venv" / "bin" / "python3")


def _spawn_mcp_server(repo_root: Path, *, danger: bool = False):
    """Launch MCP server as a subprocess and return stdin/stdout."""
    danger_arg = "True" if danger else "False"
    proc = subprocess.Popen(
        [VENV_PY, "-c", f"""
import sys, os
sys.path.insert(0, {json.dumps(REPO_ROOT)})
os.environ['PYTHONPATH'] = {json.dumps(REPO_ROOT)}
from deadpush.mcp_server import McpServer
server = McpServer(repo_root=r'{repo_root}', danger_mode={danger_arg})
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


def _init_and_notify(proc):
    """Initialize MCP session: send initialize + notifications/initialized."""
    _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    proc.stdin.flush()
    return proc


def _shutdown_and_wait(proc):
    """Send shutdown and wait for process exit."""
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 999, "method": "shutdown", "params": {}})
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


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
            assert "quarantine_list" in names
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
        proc = _spawn_mcp_server(temp_repo, danger=True)
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
        proc = _spawn_mcp_server(temp_repo, danger=True)
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
        proc = _spawn_mcp_server(temp_repo, danger=True)
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
        proc = _spawn_mcp_server(temp_repo, danger=True)
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
        proc = _spawn_mcp_server(temp_repo, danger=True)
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


# ======================================================================
# Phase 4 — JSON-RPC protocol compliance
# ======================================================================

class TestMcpProtocolCompliance:
    """JSON-RPC 2.0 protocol compliance for the MCP server."""

    def test_shutdown_clean_exit(self, temp_repo):
        """Shutdown returns result=None and process exits with code 0."""
        proc = _spawn_mcp_server(temp_repo)
        resp = _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert "result" in resp
        resp2 = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}})
        assert resp2["result"] is None
        proc.wait(timeout=5)
        assert proc.returncode == 0

    def test_malformed_json_returns_parse_error(self, temp_repo):
        """Invalid JSON on stdin returns JSON-RPC -32700 Parse error."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)

            # Send line that is not valid JSON
            proc.stdin.write("not valid json\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            resp = json.loads(line)
            assert "error" in resp, f"Expected error response, got: {resp}"
            assert resp["error"]["code"] == -32700
            assert resp["id"] is None

            # Server should still respond to subsequent valid requests
            resp2 = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            assert "result" in resp2
        finally:
            _shutdown_and_wait(proc)

    def test_unknown_method_returns_is_error(self, temp_repo):
        """Unknown JSON-RPC method returns an error result (not silent hang)."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "unknown_method_xyz", "params": {}})
            # Must get a response (not hang) — either isError or JSON-RPC error
            assert "result" in resp or "error" in resp
            if "result" in resp:
                assert resp["result"].get("isError") is True
        finally:
            _shutdown_and_wait(proc)

    def test_notification_cancelled_no_crash(self, temp_repo):
        """notifications/cancelled is silently accepted (no crash, no hang)."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            # Send notifications/cancelled — no response expected
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled"}) + "\n")
            proc.stdin.flush()
            time.sleep(0.1)
            # Server should still respond to next request
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            assert "result" in resp
            assert "tools" in resp["result"]
        finally:
            _shutdown_and_wait(proc)

    def test_double_initialize_no_crash(self, temp_repo):
        """Receiving initialize twice does not crash the server."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            resp1 = _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            assert "result" in resp1
            resp2 = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}})
            assert "result" in resp2
            # Server should still be operational
            resp3 = _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
            assert "result" in resp3
        finally:
            _shutdown_and_wait(proc)

    def test_double_shutdown_no_crash(self, temp_repo):
        """Sending shutdown twice does not crash the server."""
        proc = _spawn_mcp_server(temp_repo)
        _init_and_notify(proc)
        resp1 = _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "shutdown", "params": {}})
        assert resp1["result"] is None
        # Second shutdown should not hang — server may ignore or error
        try:
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}}) + "\n")
            proc.stdin.flush()
            proc.wait(timeout=5)
        except Exception:
            pass
        assert proc.returncode == 0


# ======================================================================
# Phase 4 — Argument validation
# ======================================================================

class TestMcpArgValidation:
    """Server returns structured errors for invalid argument types."""

    def test_get_feedback_invalid_limit(self, temp_repo):
        """get_feedback with non-numeric limit returns error."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_feedback", "arguments": {"limit": "xyz"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"] is False
        finally:
            _shutdown_and_wait(proc)

    def test_get_test_results_invalid_limit(self, temp_repo):
        """get_test_results with non-numeric limit returns error."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_test_results", "arguments": {"limit": [1, 2, 3]}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"] is False
        finally:
            _shutdown_and_wait(proc)

    def test_quarantine_list_invalid_limit(self, temp_repo):
        """quarantine_list with non-numeric limit returns error."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "quarantine_list", "arguments": {"limit": None}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"] is False
        finally:
            _shutdown_and_wait(proc)

    def test_get_recent_feedback_invalid_limit(self, temp_repo):
        """get_recent_feedback with non-numeric limit returns error."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_recent_feedback", "arguments": {"limit": "3.14"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"] is False
        finally:
            _shutdown_and_wait(proc)

    def test_float_limit_truncated(self, temp_repo):
        """Float limit for quarantine_list is silently truncated to int."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "quarantine_list", "arguments": {"limit": 1.5}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            # Should succeed (float silently converted to int)
            assert result["success"]
        finally:
            _shutdown_and_wait(proc)

    def test_empty_path_rejected(self, temp_repo):
        """write_file with empty path returns error."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "write_file", "arguments": {"path": "", "content": "x = 1\n"}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"] is False
        finally:
            _shutdown_and_wait(proc)

    def test_nonexistent_tool_name(self, temp_repo):
        """tools/call with nonexistent tool name returns error (not crash)."""
        proc = _spawn_mcp_server(temp_repo)
        try:
            _init_and_notify(proc)
            resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "nonexistent_tool_xyz", "arguments": {}
            }})
            result = json.loads(resp["result"]["content"][0]["text"])
            assert result["success"] is False
            assert "Unknown tool" in result.get("summary", "") or "Unknown tool" in result.get("error", "")
        finally:
            _shutdown_and_wait(proc)
