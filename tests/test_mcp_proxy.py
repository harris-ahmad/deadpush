"""Tests for deadpush mcp-proxy tool-call interception."""

from __future__ import annotations

from pathlib import Path

from deadpush.mcp_proxy import scan_tool_call, _tool_needs_scan, _extract_path_and_content


def test_tool_needs_scan_write_file():
    assert _tool_needs_scan("write_file", {"path": "a.py", "content": "x"})
    assert _tool_needs_scan("edit_file", {"path": "a.py"})
    assert not _tool_needs_scan("read_file", {"path": "a.py"})


def test_tool_needs_scan_shell_git():
    assert _tool_needs_scan("Bash", {"command": "git push origin main"})
    assert _tool_needs_scan("run_terminal_cmd", {"command": "echo foo > bar.txt"})


def test_extract_path_and_content():
    path, content = _extract_path_and_content({"path": "src/x.py", "content": "eval(1)"})
    assert path == "src/x.py"
    assert content == "eval(1)"


def test_scan_tool_call_blocks_blocked_file(temp_repo: Path):
    block = scan_tool_call(
        "write_file",
        {"path": "CLAUDE.md", "content": "# bad instructions\n"},
        temp_repo,
    )
    assert block is not None
    assert block.get("isError") is True
    text = block["content"][0]["text"]
    assert "blocked_by" in text or "Blocked" in text


def test_scan_tool_call_allows_clean(temp_repo: Path):
    block = scan_tool_call(
        "write_file",
        {"path": "good.py", "content": "def hello():\n    return 1\n"},
        temp_repo,
    )
    assert block is None


def test_scan_tool_call_allows_read(temp_repo: Path):
    block = scan_tool_call("read_file", {"path": "hello.py"}, temp_repo)
    assert block is None


def test_scan_tool_call_blocks_destructive_shell(temp_repo: Path):
    block = scan_tool_call(
        "run_terminal_cmd",
        {"command": "rm -rf /"},
        temp_repo,
    )
    assert block is not None
    assert block.get("isError") is True


def test_scan_tool_call_blocks_git_hookspath_shell(temp_repo: Path):
    block = scan_tool_call(
        "Bash",
        {"command": "git -c core.hooksPath=/tmp/evil commit -m x"},
        temp_repo,
    )
    assert block is not None

