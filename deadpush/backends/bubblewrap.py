"""Linux bubblewrap sandbox backend for deadpush run --sandbox."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .base import EnforcementBackend, SandboxCapabilities, logger
from .sandbox_paths import collect_writable_sandbox_paths

_BWRAP_CANDIDATES = ("bwrap", "bubblewrap")


def bubblewrap_binary() -> str | None:
    """Return the bubblewrap executable path, if any."""
    for name in _BWRAP_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def bubblewrap_available() -> bool:
    return sys.platform.startswith("linux") and bubblewrap_binary() is not None


def build_bwrap_argv(
    cmd: list[str],
    repo_root: Path,
    *,
    hardened: bool = False,
    bwrap_bin: str | None = None,
) -> list[str]:
    """Build a bubblewrap argv that jails *cmd* with a write allowlist."""
    bwrap = bwrap_bin or bubblewrap_binary()
    if not bwrap:
        raise RuntimeError("bubblewrap not found on PATH")

    writable = collect_writable_sandbox_paths(repo_root, hardened=hardened, platform="linux")
    # Apply --dev / --proc before writable binds. --dev recreates /dev as a fresh
    # tmpfs and would shadow an earlier --bind /dev/shm; binding writable paths
    # (including /dev/shm) after --dev restores host shared memory.
    # Only bind paths that still exist — bwrap exits if a --bind source is missing.
    argv: list[str] = [
        bwrap,
        "--ro-bind", "/", "/",
        "--proc", "/proc",
        "--dev", "/dev",
    ]
    for path in writable:
        if not path.exists():
            logger.debug("skipping missing writable bind path: %s", path)
            continue
        argv.extend(["--bind", str(path), str(path)])
    argv.extend(["--die-with-parent", "--", *cmd])
    return argv


class BubblewrapEnforcementBackend(EnforcementBackend):
    """Process jail via bubblewrap with Seatbelt-equivalent write allowlist."""

    name = "bubblewrap"
    tier = "T2"

    _CAPABILITIES = SandboxCapabilities(
        os_confinement=True,
        write_allowlist=True,
        content_deny=False,
    )

    def __init__(self, repo_root: Path, *, hardened: bool = False):
        super().__init__(repo_root)
        self.hardened = hardened
        self._bwrap_bin: str | None = None

    @property
    def capabilities(self) -> SandboxCapabilities:
        return self._CAPABILITIES

    def available(self) -> bool:
        return bubblewrap_available()

    def start(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self._bwrap_bin = bubblewrap_binary()
        if not self._bwrap_bin:
            self._last_error = "bubblewrap not found on PATH (install bubblewrap / bwrap)"
            raise RuntimeError(self._last_error)
        try:
            subprocess.run(
                [self._bwrap_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            self._last_error = f"bubblewrap validation failed: {e}"
            raise RuntimeError(self._last_error) from e
        self._started = True
        logger.info("bubblewrap backend ready: %s", self._bwrap_bin)

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        ok, reason = self.preflight(cmd)
        if not ok:
            raise ValueError(f"bubblewrap preflight failed: {reason}")
        if not self._bwrap_bin:
            self.start(repo_root)
        wrapped = build_bwrap_argv(
            cmd, repo_root, hardened=self.hardened, bwrap_bin=self._bwrap_bin,
        )
        self.apply_env_markers(env)
        env["DEADPUSH_BUBBLEWRAP"] = "1"
        return wrapped

    def stop(self) -> None:
        self._started = False

    def describe(self) -> dict:
        d = super().describe()
        d.update({
            "bwrap_bin": self._bwrap_bin,
            "hardened": self.hardened,
            "gates": ["bubblewrap", "git-wrapper", "mcp-proxy", "guardian-quarantine"],
            "note": (
                "bubblewrap jails the wrapped subprocess with a write allowlist "
                "(repo, ~/.deadpush, temp). Outside-repo writes are blocked."
            ),
        })
        return d
