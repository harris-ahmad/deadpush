"""Tests for configure vscode/all and GPC snippet generation."""

from __future__ import annotations

import json
from pathlib import Path

from deadpush.configure import configure_all_ides, configure_vscode_mcp, write_gpc_agent_snippet


def test_configure_vscode_mcp(temp_repo: Path):
    vscode_dir = temp_repo / ".vscode"
    vscode_dir.mkdir()
    config = {
        "servers": {
            "fs": {"command": "npx", "args": ["-y", "server-filesystem", "."]},
        },
    }
    (vscode_dir / "mcp.json").write_text(json.dumps(config), encoding="utf-8")

    result = configure_vscode_mcp(temp_repo)
    assert result["proxied"] is True
    data = json.loads((vscode_dir / "mcp.json").read_text(encoding="utf-8"))
    assert data["servers"]["fs"]["args"][0] == "mcp-proxy"


def test_configure_all_ides(temp_repo: Path):
    cursor_dir = temp_repo / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text(
        json.dumps({"mcpServers": {"x": {"command": "echo", "args": []}}}),
        encoding="utf-8",
    )
    result = configure_all_ides(temp_repo)
    assert "claude" in result["skipped"]
    assert result.get("gpc_snippet")
    names: list[str] = []
    for item in result["configured"]:
        names.extend(item.keys())
    assert "cursor" in names


def test_write_gpc_agent_snippet(temp_repo: Path):
    path = write_gpc_agent_snippet(temp_repo)
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "GpcClient" in text
    assert str(temp_repo) in text
