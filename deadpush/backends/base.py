"""EnforcementBackend protocol — pluggable OS sandbox backends."""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class EnforcementBackend(ABC):
    """Platform-specific sandbox wrapper for agent subprocesses."""

    name: str = "base"

    @abstractmethod
    def available(self) -> bool:
        """True when this backend can run on the current platform."""

    @abstractmethod
    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        """Return argv prefix/wrapper to sandbox *cmd*."""

    @abstractmethod
    def start(self, repo_root: Path) -> None:
        """Start backend monitoring (e.g. fanotify listener)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop backend monitoring."""

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "available": self.available()}


def get_backend(repo_root: Path, *, prefer: str | None = None) -> EnforcementBackend:
    """Select the best available backend for the current platform."""
    from .linux import LinuxEnforcementBackend
    from .noop import NoopEnforcementBackend
    from .seatbelt import SeatbeltEnforcementBackend

    candidates: list[EnforcementBackend] = []
    if prefer == "seatbelt":
        candidates = [SeatbeltEnforcementBackend(repo_root)]
    elif prefer == "linux":
        candidates = [LinuxEnforcementBackend(repo_root)]
    elif prefer == "noop":
        candidates = [NoopEnforcementBackend(repo_root)]
    else:
        if sys.platform == "darwin":
            candidates = [SeatbeltEnforcementBackend(repo_root), NoopEnforcementBackend(repo_root)]
        elif sys.platform.startswith("linux"):
            candidates = [LinuxEnforcementBackend(repo_root), NoopEnforcementBackend(repo_root)]
        else:
            candidates = [NoopEnforcementBackend(repo_root)]

    for backend in candidates:
        if backend.available():
            return backend
    return NoopEnforcementBackend(repo_root)
