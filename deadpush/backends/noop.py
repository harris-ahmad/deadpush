"""Fallback enforcement backend — git/MCP wrapper gates without OS sandbox."""

from __future__ import annotations

from pathlib import Path

from .base import EnforcementBackend, logger

# Re-export module logger alias for tests
__all__ = ["NoopEnforcementBackend"]


class NoopEnforcementBackend(EnforcementBackend):
    """Deliberate fallback when OS-level sandboxing is unavailable.

    T2 session semantics still apply via:
    - ``deadpush-git`` on PATH (commit/push guardrails)
    - ``DEADPUSH_SANDBOX`` env marker
    - Guardian watchdog quarantine for non-wrapped writes

    This is not a no-op for repo integrity — only for syscall-level confinement.
    """

    name = "noop"
    tier = "T2-partial"

    def available(self) -> bool:
        return True

    def preflight(self, cmd: list[str]) -> tuple[bool, str]:
        ok, reason = super().preflight(cmd)
        if not ok:
            self._last_error = reason
        return ok, reason

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        ok, reason = self.preflight(cmd)
        if not ok:
            raise ValueError(f"noop backend preflight failed: {reason}")
        self.apply_env_markers(env)
        env["DEADPUSH_NOOP_SANDBOX"] = "1"
        logger.info(
            "noop backend active for %s — OS sandbox unavailable; git/MCP/guardian gates apply",
            repo_root,
        )
        return cmd

    def start(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self._started = True
        self._last_error = (
            "OS sandbox backend unavailable on this platform; "
            "relying on git wrapper, MCP proxy, and guardian quarantine"
        )
        logger.debug("noop backend started for %s", self.repo_root)

    def stop(self) -> None:
        self._started = False

    def describe(self) -> dict:
        d = super().describe()
        d.update({
            "os_sandbox": False,
            "gates": ["git-wrapper", "mcp-proxy", "guardian-quarantine"],
            "note": (
                "No syscall-level confinement. Agent subprocess has normal filesystem "
                "access; repo integrity enforced by git/MCP paths and watchdog."
            ),
        })
        return d
