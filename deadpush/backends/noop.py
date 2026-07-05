"""No-op enforcement backend — git/MCP wrapper only, no OS sandbox."""

from __future__ import annotations

from pathlib import Path

from .base import EnforcementBackend


class NoopEnforcementBackend(EnforcementBackend):
    name = "noop"

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()

    def available(self) -> bool:
        return True

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        return cmd

    def start(self, repo_root: Path) -> None:
        pass

    def stop(self) -> None:
        pass
