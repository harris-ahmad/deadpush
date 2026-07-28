"""EnforcementBackend protocol — pluggable OS sandbox backends."""

from __future__ import annotations

import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger("deadpush.backends")


class SandboxUnavailableError(RuntimeError):
    """Raised when ``run --sandbox`` needs OS confinement but none is available.

    Explicit ``--backend noop`` opts into gates-only (T2-partial) and must not
    raise this error. Silent fallback to noop is intentionally not supported.
    """


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
    """Select a confining sandbox backend for the current platform.

    Returns ``NoopEnforcementBackend`` only when ``prefer="noop"`` (explicit
    gates-only opt-in). Otherwise raises ``SandboxUnavailableError`` when no
    OS confinement backend is available — never silently falls back to noop.
    """
    from .linux import LinuxEnforcementBackend
    from .noop import NoopEnforcementBackend
    from .seatbelt import SeatbeltEnforcementBackend

    if prefer == "noop":
        return NoopEnforcementBackend(repo_root)

    candidates: list[EnforcementBackend] = []
    if prefer == "seatbelt":
        candidates = [SeatbeltEnforcementBackend(repo_root)]
    elif prefer == "linux":
        candidates = [LinuxEnforcementBackend(repo_root)]
    elif prefer is not None:
        raise SandboxUnavailableError(
            f"Unknown sandbox backend {prefer!r}. "
            "Choose seatbelt, linux, or noop."
        )
    elif sys.platform == "darwin":
        candidates = [SeatbeltEnforcementBackend(repo_root)]
    elif sys.platform.startswith("linux"):
        candidates = [LinuxEnforcementBackend(repo_root)]
    else:
        raise SandboxUnavailableError(
            f"No OS sandbox backend for platform {sys.platform!r}. "
            "Pass --backend noop for gates-only (not a real sandbox)."
        )

    for backend in candidates:
        if backend.available():
            return backend

    if prefer:
        raise SandboxUnavailableError(
            f"Requested sandbox backend {prefer!r} is unavailable. "
            "Pass --backend noop for gates-only (not a real sandbox)."
        )
    raise SandboxUnavailableError(
        "No OS sandbox backend available on this host. "
        "Need Seatbelt (macOS sandbox-exec) or Linux fanotify with CAP_SYS_ADMIN. "
        "Pass --backend noop for gates-only (not a real sandbox)."
    )
