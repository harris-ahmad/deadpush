"""
MCP transparent proxy — intercept tools/call before downstream MCP servers execute.

Usage:
    deadpush mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /path
    deadpush mcp-proxy --config .cursor/mcp.json --server filesystem
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from .config import load_config
from .intercept import enforce_content, violations_from_result
from .rules import RuntimeConfig

MCP_PROTOCOL_VERSION = "2024-11-05"

# Tool names (and substrings) that perform repo writes and must be scanned.
WRITE_TOOL_NAMES = frozenset({
    "write_file", "create_file", "edit_file", "write", "save_file",
    "str_replace", "search_replace", "apply_patch", "patch_file",
    "create_or_update_file", "file_write",
})

GIT_TOOL_PATTERNS = ("git commit", "git push", "git add")

# Argument keys that may hold file path or content.
PATH_KEYS = ("path", "file_path", "filepath", "filename", "target", "file")
CONTENT_KEYS = ("content", "contents", "text", "data", "new_string", "new_str", "replacement")


def _extract_path_and_content(arguments: dict[str, Any]) -> tuple[str | None, str | None]:
    rel_path: str | None = None
    content: str | None = None
    for k, v in arguments.items():
        kl = k.lower()
        if rel_path is None and kl in PATH_KEYS and isinstance(v, str):
            rel_path = v
        if content is None and kl in CONTENT_KEYS and isinstance(v, str):
            content = v
    # Nested edits (some MCP tools use edits=[{path, content}])
    edits = arguments.get("edits") or arguments.get("changes")
    if isinstance(edits, list) and edits:
        first = edits[0]
        if isinstance(first, dict):
            if rel_path is None:
                rel_path = first.get("path") or first.get("file_path")
            if content is None:
                content = first.get("content") or first.get("new_string")
    return rel_path, content


def _tool_needs_scan(tool_name: str, arguments: dict[str, Any]) -> bool:
    name_lower = tool_name.lower()
    if name_lower in WRITE_TOOL_NAMES:
        return True
    for part in WRITE_TOOL_NAMES:
        if part in name_lower:
            return True
    # Shell/bash tools with write-like commands
    cmd = arguments.get("command") or arguments.get("cmd") or ""
    if isinstance(cmd, str):
        cmd_lower = cmd.lower()
        if any(p in cmd_lower for p in GIT_TOOL_PATTERNS):
            return True
        if any(w in cmd_lower for w in ("write_file", " echo ", " > ", " >> ", "tee ")):
            return True
    return False


def scan_tool_call(tool_name: str, arguments: dict[str, Any], repo_root: Path) -> dict[str, Any] | None:
    """Return MCP error result if blocked, else None (allow)."""
    if not _tool_needs_scan(tool_name, arguments):
        return None

    config = load_config(explicit_root=repo_root)
    runtime = RuntimeConfig(repo_root)
    rel_path, content = _extract_path_and_content(arguments)

    if content is None and rel_path:
        # Path-only call — check if file exists and scan content
        full = repo_root / rel_path
        if full.is_file():
            try:
                content = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""

    if rel_path is None:
        rel_path = "_unknown_"
    if content is None:
        content = json.dumps(arguments, default=str)

    result = enforce_content(rel_path, content, config, runtime)
    if result.allowed:
        return None

    violations = violations_from_result(rel_path, result)
    summary = "; ".join(v["description"] for v in violations[:3])
    return {
        "content": [{
            "type": "text",
            "text": json.dumps({
                "success": False,
                "blocked_by": "deadpush-mcp-proxy",
                "tool": tool_name,
                "violations": violations,
                "summary": f"Blocked by deadpush guardrails: {summary}",
            }, indent=2),
        }],
        "isError": True,
    }


class McpProxy:
    """Transparent stdio proxy between MCP client and downstream MCP server."""

    def __init__(self, downstream_cmd: list[str], repo_root: Path | None = None):
        self.repo_root = (repo_root or Path.cwd()).resolve()
        self.downstream_cmd = downstream_cmd
        self._proc: subprocess.Popen[str] | None = None
        self._initialized = False
        self._lock = threading.Lock()

    def start_downstream(self) -> None:
        self._proc = subprocess.Popen(
            self.downstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

    def run(self) -> int:
        self.start_downstream()
        assert self._proc and self._proc.stdin and self._proc.stdout

        def forward_client():
            for line in sys.stdin:
                line = line.rstrip("\n")
                if not line:
                    continue
                handled = self._maybe_intercept(line)
                if handled is not None:
                    sys.stdout.write(handled + "\n")
                    sys.stdout.flush()
                    continue
                try:
                    self._proc.stdin.write(line + "\n")  # type: ignore[union-attr]
                    self._proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    break

        def forward_server():
            for line in self._proc.stdout:  # type: ignore[union-attr]
                sys.stdout.write(line)
                sys.stdout.flush()

        t1 = threading.Thread(target=forward_client, daemon=True)
        t2 = threading.Thread(target=forward_server, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        try:
            self._proc.terminate()
        except OSError:
            pass
        return self._proc.wait()

    def _maybe_intercept(self, line: str) -> str | None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return None

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "initialize":
            self._initialized = True
            return None  # forward

        if method != "tools/call" or msg_id is None:
            return None

        params = msg.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}

        block_result = scan_tool_call(tool_name, arguments, self.repo_root)
        if block_result is None:
            return None

        response = {"jsonrpc": "2.0", "id": msg_id, "result": block_result}
        return json.dumps(response)


def load_mcp_server_command(config_path: Path, server_name: str) -> list[str]:
    """Extract command+args for an MCP server from a JSON config file."""
    data = json.loads(config_path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or data.get("servers") or {}
    if server_name not in servers:
        raise ValueError(f"Server {server_name!r} not found in {config_path}")
    entry = servers[server_name]
    if isinstance(entry, dict):
        cmd = entry.get("command") or entry.get("cmd")
        args = entry.get("args") or []
    else:
        raise ValueError(f"Invalid server entry for {server_name!r}")
    if not cmd:
        raise ValueError(f"No command for server {server_name!r}")
    return [cmd, *[str(a) for a in args]]


def run_mcp_proxy(
    downstream_cmd: list[str] | None = None,
    *,
    config_path: Path | None = None,
    server_name: str | None = None,
    repo_root: Path | None = None,
) -> int:
    if downstream_cmd is None:
        if config_path is None or server_name is None:
            print("Provide downstream command after -- or --config + --server", file=sys.stderr)
            return 2
        downstream_cmd = load_mcp_server_command(config_path, server_name)

    proxy = McpProxy(downstream_cmd, repo_root=repo_root)
    return proxy.run()
