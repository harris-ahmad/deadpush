"""Tests for protect auto-configuring IDE MCP proxy."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from deadpush.bootstrap import BOOTSTRAP_MANIFEST
from deadpush.cli import main
from deadpush.configure import PROXY_MARKER


def test_protect_calls_configure_all_by_default(temp_repo: Path):
    cursor_dir = temp_repo / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text(
        json.dumps({
            "mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "server-filesystem", "."]},
            },
        }),
        encoding="utf-8",
    )

    runner = CliRunner()
    with patch("deadpush.hooks.install_hook"), \
         patch("deadpush.hooks.install_precommit_hook"), \
         patch("deadpush.hooks.install_postcommit_hook"), \
         patch("deadpush.hooks.verify_hooks_installed", return_value=[]), \
         patch("deadpush.config.write_install_marker"), \
         patch("deadpush.hooks.merge_guardian_ignore_files"), \
         patch("deadpush.hooks.setup_github_guard_action", return_value=None):
        result = runner.invoke(
            main, ["protect", "--repo", str(temp_repo)], catch_exceptions=False,
        )

    assert result.exit_code == 0
    data = json.loads((cursor_dir / "mcp.json").read_text(encoding="utf-8"))
    entry = data["mcpServers"]["fs"]
    assert entry.get(PROXY_MARKER) is True
    assert "mcp-proxy" in entry["args"]


def test_protect_no_configure_skips_proxy_wrap(temp_repo: Path):
    cursor_dir = temp_repo / ".cursor"
    cursor_dir.mkdir()
    original = {
        "mcpServers": {
            "fs": {"command": "npx", "args": ["-y", "server-filesystem", "."]},
        },
    }
    (cursor_dir / "mcp.json").write_text(json.dumps(original), encoding="utf-8")

    runner = CliRunner()
    with patch("deadpush.hooks.install_hook"), \
         patch("deadpush.hooks.install_precommit_hook"), \
         patch("deadpush.hooks.install_postcommit_hook"), \
         patch("deadpush.hooks.verify_hooks_installed", return_value=[]), \
         patch("deadpush.config.write_install_marker"), \
         patch("deadpush.hooks.merge_guardian_ignore_files"), \
         patch("deadpush.hooks.setup_github_guard_action", return_value=None):
        result = runner.invoke(
            main, ["protect", "--repo", str(temp_repo), "--no-configure"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    data = json.loads((cursor_dir / "mcp.json").read_text(encoding="utf-8"))
    assert "fs" in data["mcpServers"]
    assert data["mcpServers"]["fs"]["command"] == "npx"
    assert "deadpush" in data["mcpServers"]


def test_protect_records_bootstrap_manifest(temp_repo: Path):
    runner = CliRunner()
    with patch("deadpush.hooks.install_hook"), \
         patch("deadpush.hooks.install_precommit_hook"), \
         patch("deadpush.hooks.install_postcommit_hook"), \
         patch("deadpush.hooks.verify_hooks_installed", return_value=[]), \
         patch("deadpush.config.write_install_marker"), \
         patch("deadpush.hooks.merge_guardian_ignore_files"), \
         patch("deadpush.hooks.setup_github_guard_action", return_value=None), \
         patch("deadpush.configure.configure_all_ides", return_value={"configured": [], "skipped": []}):
        result = runner.invoke(
            main, ["protect", "--repo", str(temp_repo)], catch_exceptions=False,
        )

    assert result.exit_code == 0
    manifest = temp_repo / BOOTSTRAP_MANIFEST
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert ".cursorignore" in data["paths"]
    assert ".github/workflows/deadpush-guard.yml" in data["paths"]
