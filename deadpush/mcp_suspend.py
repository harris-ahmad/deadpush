"""Shared MCP suspension state (guardian SESSION_PAUSE → block tool calls)."""

from __future__ import annotations

from pathlib import Path


def is_mcp_hardened(repo_root: Path) -> bool:
    """True when guardian state for this repo lives in hardened paths."""
    from .config import is_hardened_install

    repo = Path(repo_root).resolve()
    if is_hardened_install(repo):
        return True
    return (repo / ".guardian" / "guardian.control.port").exists()


def suspend_file_path(repo_root: Path, *, hardened: bool | None = None) -> Path:
    from .guard import _scoped_suspend_file

    if hardened is None:
        hardened = is_mcp_hardened(repo_root)
    return _scoped_suspend_file(repo_root, hardened)


def mcp_suspend_reason(repo_root: Path, *, hardened: bool | None = None) -> str | None:
    """Return suspension reason text if MCP is paused, else None."""
    path = suspend_file_path(repo_root, hardened=hardened)
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
        return text or "MCP suspended by guardian (SESSION_PAUSE)"
    except OSError:
        return "MCP suspended by guardian (SESSION_PAUSE)"
