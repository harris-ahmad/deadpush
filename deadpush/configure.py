"""IDE / agent MCP configuration helpers."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any


PROXY_MARKER = "_deadpush_proxied"
ORIGINAL_MARKER = "_deadpush_original"


def _deadpush_cmd() -> str:
    found = shutil.which("deadpush")
    if found:
        return found
    return sys.executable


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _servers_dict(config: dict[str, Any]) -> dict[str, Any]:
    servers = config.get("mcpServers") or config.get("servers") or {}
    return servers if isinstance(servers, dict) else {}


def wrap_server_entry(entry: dict[str, Any], *, deadpush_cmd: str | None = None) -> dict[str, Any]:
    """Wrap one MCP server entry to route through deadpush mcp-proxy."""
    if not isinstance(entry, dict):
        raise ValueError("invalid MCP server entry")
    if entry.get(PROXY_MARKER):
        return entry

    cmd = entry.get("command") or entry.get("cmd")
    if not cmd:
        raise ValueError("MCP server entry missing command")

    args = [str(a) for a in (entry.get("args") or [])]
    dp = deadpush_cmd or _deadpush_cmd()

    # Already deadpush mcp-proxy
    if cmd == dp and args[:1] == ["mcp-proxy"]:
        entry[PROXY_MARKER] = True
        return entry

    # deadpush mcp native — no wrap needed
    if cmd == dp and args == ["mcp"]:
        return entry

    wrapped: dict[str, Any] = {
        "command": dp,
        "args": ["mcp-proxy", "--", cmd, *args],
        PROXY_MARKER: True,
        ORIGINAL_MARKER: {"command": cmd, "args": args},
    }
    if "env" in entry:
        wrapped["env"] = entry["env"]
    return wrapped


def unwrap_server_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Restore a wrapped MCP server entry to its original command."""
    if not isinstance(entry, dict):
        return entry
    original = entry.get(ORIGINAL_MARKER)
    if isinstance(original, dict) and original.get("command"):
        restored = {"command": original["command"], "args": original.get("args") or []}
        if "env" in entry:
            restored["env"] = entry["env"]
        return restored
    return {k: v for k, v in entry.items() if k not in (PROXY_MARKER, ORIGINAL_MARKER)}


def configure_cursor_mcp(repo_root: Path, *, unwrap: bool = False) -> dict[str, Any]:
    """Wrap or unwrap `.cursor/mcp.json` servers with deadpush mcp-proxy."""
    repo = repo_root.resolve()
    cursor_path = repo / ".cursor" / "mcp.json"
    backup_path = repo / ".cursor" / "mcp.json.deadpush.bak"

    if not cursor_path.exists() and not unwrap:
        from .hooks import setup_mcp_discovery
        setup_mcp_discovery(repo)

    config = _load_json(cursor_path)
    servers = _servers_dict(config)
    if not servers and not unwrap:
        raise FileNotFoundError(f"No MCP servers in {cursor_path}")

    if not unwrap and not backup_path.exists() and cursor_path.exists():
        shutil.copy2(cursor_path, backup_path)

    dp = _deadpush_cmd()
    updated: dict[str, Any] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        if unwrap:
            updated[name] = unwrap_server_entry(entry)
        else:
            try:
                updated[name] = wrap_server_entry(entry, deadpush_cmd=dp)
            except ValueError:
                updated[name] = entry

    if "mcpServers" in config or "servers" not in config:
        config["mcpServers"] = updated
    else:
        config["servers"] = updated

    _save_json(cursor_path, config)
    return {
        "path": str(cursor_path),
        "backup": str(backup_path) if backup_path.exists() else None,
        "servers": list(updated.keys()),
        "proxied": not unwrap,
    }


def configure_claude_mcp(repo_root: Path, *, unwrap: bool = False) -> dict[str, Any]:
    """Wrap Claude Desktop project MCP config if present."""
    repo = repo_root.resolve()
    for candidate in (
        repo / ".mcp.json",
        repo / "claude_mcp.json",
        Path.home() / ".claude" / "mcp.json",
    ):
        if not candidate.exists():
            continue
        config = _load_json(candidate)
        servers = _servers_dict(config)
        if not servers:
            continue
        dp = _deadpush_cmd()
        updated = {}
        for name, entry in servers.items():
            if isinstance(entry, dict):
                updated[name] = unwrap_server_entry(entry) if unwrap else wrap_server_entry(entry, deadpush_cmd=dp)
        if "mcpServers" in config:
            config["mcpServers"] = updated
        else:
            config["servers"] = updated
        _save_json(candidate, config)
        return {"path": str(candidate), "servers": list(updated.keys()), "proxied": not unwrap}
    raise FileNotFoundError("No Claude MCP config found to configure")
