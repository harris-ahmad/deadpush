"""Linux composite sandbox: bubblewrap write jail + fanotify content deny."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from .base import EnforcementBackend, SandboxCapabilities, logger
from .bubblewrap import BubblewrapEnforcementBackend
from .linux import LinuxEnforcementBackend


class LinuxSandboxBackend(EnforcementBackend):
    """Full Linux T2: bwrap process jail plus optional fanotify content deny."""

    name = "linux-sandbox"
    tier = "T2-max"

    def __init__(
        self,
        repo_root: Path,
        *,
        hardened: bool = False,
        on_deny: Callable[[str, str, str], None] | None = None,
    ):
        super().__init__(repo_root)
        self.hardened = hardened
        self._bwrap = BubblewrapEnforcementBackend(repo_root, hardened=hardened)
        self._fanotify = LinuxEnforcementBackend(repo_root, on_deny=on_deny)
        self._fanotify_active = False

    @property
    def capabilities(self) -> SandboxCapabilities:
        content_deny = (
            self._fanotify_active if self._started else self._fanotify.available()
        )
        return SandboxCapabilities(
            os_confinement=True,
            write_allowlist=True,
            content_deny=content_deny,
        )

    def attach_on_deny(self, callback: Callable[[str, str, str], None] | None) -> None:
        """Wire fanotify deny events to GPC (called from run_sandbox)."""
        self._fanotify._on_deny = callback

    def available(self) -> bool:
        return self._bwrap.available()

    def start(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self._bwrap.start(repo_root)
        self._fanotify_active = False
        if self._fanotify.available():
            try:
                self._fanotify.start(repo_root)
                self._fanotify_active = self._fanotify.is_active
                if not self._fanotify_active and self._fanotify._last_error:
                    self._last_error = (
                        f"fanotify listener inactive: {self._fanotify._last_error}"
                    )
                    logger.warning(self._last_error)
            except RuntimeError as e:
                self._last_error = f"fanotify listener failed: {e}"
                logger.warning(self._last_error)
        else:
            self._last_error = (
                "fanotify unavailable (needs Linux 5.13+ and CAP_SYS_ADMIN); "
                "write allowlist only via bubblewrap"
            )
            logger.warning(self._last_error)
        self._started = True
        logger.info(
            "linux-sandbox ready (bwrap=%s, fanotify=%s)",
            self._bwrap._bwrap_bin,
            "active" if self._fanotify_active else "off",
        )

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        wrapped = self._bwrap.wrap_command(cmd, repo_root=repo_root, env=env)
        self.apply_env_markers(env)
        if self._fanotify_active:
            env["DEADPUSH_LINUX_SANDBOX"] = "1"
        return wrapped

    def stop(self) -> None:
        self._fanotify.stop()
        self._bwrap.stop()
        self._fanotify_active = False
        self._started = False

    def describe(self) -> dict:
        d = super().describe()
        d.update({
            "bwrap": self._bwrap.describe(),
            "fanotify": self._fanotify.describe(),
            "fanotify_active": self._fanotify_active,
            "hardened": self.hardened,
            "gates": [
                "bubblewrap",
                "fanotify",
                "git-wrapper",
                "mcp-proxy",
                "guardian-quarantine",
            ],
            "note": (
                "bubblewrap jails the wrapped child; fanotify adds in-repo content deny "
                "when CAP_SYS_ADMIN is available."
            ),
        })
        return d
