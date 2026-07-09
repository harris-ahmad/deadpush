"""EnforcementBackend protocol — pluggable OS sandbox backends."""

from __future__ import annotations

import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger("deadpush.backends")


class EnforcementBackend(ABC):
    """Platform-specific sandbox wrapper for agent subprocesses."""

    name: str = "base"
    tier: str = "T2"

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self._started = False
        self._last_error: str | None = None

    @abstractmethod
    def available(self) -> bool:
        """True when this backend can run on the current platform."""

    @abstractmethod
    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        """Return argv to execute *cmd* under this backend's confinement."""

    @abstractmethod
    def start(self, repo_root: Path) -> None:
        """Start backend monitoring (e.g. fanotify listener)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop backend monitoring and release resources."""

    def preflight(self, cmd: list[str]) -> tuple[bool, str]:
        """Validate that *cmd* can run under this backend. Returns (ok, reason)."""
        if not cmd:
            return False, "empty command"
        if not cmd[0]:
            return False, "missing executable"
        return True, ""

    def apply_env_markers(self, env: dict[str, str]) -> None:
        """Stamp sandbox metadata into *env* for child processes."""
        env["DEADPUSH_BACKEND"] = self.name
        env["DEADPUSH_TIER"] = self.tier
        env["DEADPUSH_REPO_ROOT"] = str(self.repo_root)
        if self._last_error:
            env["DEADPUSH_BACKEND_WARNING"] = self._last_error

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier,
            "available": self.available(),
            "started": self._started,
            "repo_root": str(self.repo_root),
            "last_error": self._last_error,
        }


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
            if prefer and backend.name != prefer and prefer != "noop":
                logger.warning(
                    "Preferred backend %r unavailable; using %r",
                    prefer,
                    backend.name,
                )
            return backend

    fallback = NoopEnforcementBackend(repo_root)
    fallback._last_error = "no platform backend available; using git/MCP gates only"
    logger.warning(fallback._last_error)
    return fallback
