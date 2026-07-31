"""EnforcementBackend protocol — pluggable OS sandbox backends."""

from __future__ import annotations

import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("deadpush.backends")


@dataclass(frozen=True)
class SandboxCapabilities:
    """Explicit guarantees for a sandbox enforcement backend.

    * ``os_confinement`` — wrapped child runs under an OS sandbox (Seatbelt, bwrap).
    * ``write_allowlist`` — child writes limited to approved paths (Seatbelt-style).
    * ``content_deny`` — pre-write content policy deny (fanotify on repo tree).
    """

    os_confinement: bool = False
    write_allowlist: bool = False
    content_deny: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {
            "os_confinement": self.os_confinement,
            "write_allowlist": self.write_allowlist,
            "content_deny": self.content_deny,
        }

    @property
    def has_os_enforcement(self) -> bool:
        """True when any OS-level mechanism is active (process jail or content deny)."""
        return self.os_confinement or self.content_deny


def format_capabilities_summary(caps: SandboxCapabilities | dict[str, bool]) -> str:
    """Human-readable one-line summary for CLI/doctor."""
    if isinstance(caps, SandboxCapabilities):
        caps = caps.as_dict()
    parts: list[str] = []
    if caps.get("os_confinement"):
        parts.append("process confinement")
    if caps.get("write_allowlist"):
        parts.append("write allowlist")
    if caps.get("content_deny"):
        parts.append("content deny")
    return ", ".join(parts) if parts else "gates only"


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

    @property
    def capabilities(self) -> SandboxCapabilities:
        """Capability contract for this backend (override in subclasses)."""
        return SandboxCapabilities()

    def preflight(self, cmd: list[str]) -> tuple[bool, str]:
        """Validate that *cmd* can run under this backend. Returns (ok, reason)."""
        if not cmd:
            return False, "empty command"
        if not cmd[0]:
            return False, "missing executable"
        return True, ""

    def apply_env_markers(self, env: dict[str, str]) -> None:
        """Stamp sandbox metadata into *env* for child processes."""
        caps = self.capabilities
        env["DEADPUSH_BACKEND"] = self.name
        env["DEADPUSH_TIER"] = self.tier
        env["DEADPUSH_REPO_ROOT"] = str(self.repo_root)
        env["DEADPUSH_SANDBOX_OS_CONFINEMENT"] = "1" if caps.os_confinement else "0"
        env["DEADPUSH_SANDBOX_WRITE_ALLOWLIST"] = "1" if caps.write_allowlist else "0"
        env["DEADPUSH_SANDBOX_CONTENT_DENY"] = "1" if caps.content_deny else "0"
        if self._last_error:
            env["DEADPUSH_BACKEND_WARNING"] = self._last_error

    def describe(self) -> dict[str, Any]:
        caps = self.capabilities
        return {
            "name": self.name,
            "tier": self.tier,
            "available": self.available(),
            "started": self._started,
            "repo_root": str(self.repo_root),
            "last_error": self._last_error,
            "capabilities": caps.as_dict(),
            "capabilities_summary": format_capabilities_summary(caps),
            # Backward-compatible alias: any OS-level enforcement mechanism.
            "os_sandbox": caps.has_os_enforcement,
        }


def get_backend(repo_root: Path, *, prefer: str | None = None) -> EnforcementBackend:
    """Select a confining sandbox backend for the current platform.

    Returns ``NoopEnforcementBackend`` only when ``prefer="noop"`` (explicit
    gates-only opt-in). Otherwise raises ``SandboxUnavailableError`` when no
    OS confinement backend is available — never silently falls back to noop.
    """
    from .bubblewrap import BubblewrapEnforcementBackend
    from .linux import LinuxEnforcementBackend
    from .linux_sandbox import LinuxSandboxBackend
    from .noop import NoopEnforcementBackend
    from .seatbelt import SeatbeltEnforcementBackend

    if prefer == "noop":
        return NoopEnforcementBackend(repo_root)

    candidates: list[EnforcementBackend] = []
    if prefer == "seatbelt":
        candidates = [SeatbeltEnforcementBackend(repo_root)]
    elif prefer == "bubblewrap":
        candidates = [BubblewrapEnforcementBackend(repo_root)]
    elif prefer in ("linux-sandbox", "linux"):
        if prefer == "linux-sandbox":
            candidates = [LinuxSandboxBackend(repo_root)]
        else:
            # Explicit fanotify-only (legacy ``--backend linux``).
            candidates = [LinuxEnforcementBackend(repo_root)]
    elif prefer is not None:
        raise SandboxUnavailableError(
            f"Unknown sandbox backend {prefer!r}. "
            "Choose seatbelt, bubblewrap, linux-sandbox, linux, or noop."
        )
    elif sys.platform == "darwin":
        candidates = [SeatbeltEnforcementBackend(repo_root)]
    elif sys.platform.startswith("linux"):
        candidates = [
            LinuxSandboxBackend(repo_root),
            LinuxEnforcementBackend(repo_root),
        ]
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
        "Need Seatbelt (macOS), bubblewrap (Linux), or fanotify with CAP_SYS_ADMIN. "
        "Pass --backend noop for gates-only (not a real sandbox)."
    )
