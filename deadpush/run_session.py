"""Agent session wrapper — deadpush run --sandbox."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .backends.base import EnforcementBackend, SandboxUnavailableError, get_backend
from .config import is_hardened_install, load_config
from .gpc_session import GpcMandatoryError, GpcSession, apply_gpc_env, start_gpc_session, stop_gpc_session

logger = logging.getLogger("deadpush.run_session")


def _make_git_wrapper_bin(repo_root: Path) -> Path:
    """Create a temp bin dir with a `git` shim pointing to deadpush git-wrapper."""
    bindir = Path(tempfile.mkdtemp(prefix="deadpush-bin-"))
    git_shim = bindir / "git"
    deadpush = shutil.which("deadpush") or sys.executable
    repo_s = str(repo_root.resolve())
    if deadpush.endswith("python") or deadpush.endswith("python3"):
        wrapper = f'''#!/bin/sh
export DEADPUSH_REPO_ROOT="{repo_s}"
exec "{sys.executable}" -m deadpush.git_wrapper "$@"
'''
    else:
        wrapper = f'''#!/bin/sh
export DEADPUSH_REPO_ROOT="{repo_s}"
exec "{deadpush}" git-wrapper "$@"
'''
    git_shim.write_text(wrapper, encoding="utf-8")
    git_shim.chmod(0o755)
    return bindir


def prepare_sandbox_env(
    repo_root: Path,
    *,
    hardened: bool = False,
    backend: EnforcementBackend | None = None,
    gpc_session: GpcSession | None = None,
) -> dict[str, str]:
    """Build environment for a sandboxed agent session."""
    env = dict(os.environ)
    env["DEADPUSH_REPO_ROOT"] = str(repo_root.resolve())
    env["DEADPUSH_SANDBOX"] = "1"
    if hardened:
        env["DEADPUSH_HARDENED"] = "1"

    bindir = _make_git_wrapper_bin(repo_root)
    env["DEADPUSH_BIN_DIR"] = str(bindir)
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"

    real_git = shutil.which("git")
    if real_git and bindir / "git" != Path(real_git):
        env["DEADPUSH_REAL_GIT"] = real_git

    if backend is not None:
        backend.apply_env_markers(env)

    if gpc_session is not None:
        apply_gpc_env(env, gpc_session)

    return env


def _backend_on_deny(gpc_session: GpcSession | None):
    def _on_deny(rel: str, reason: str, source: str) -> None:
        if gpc_session is None:
            return
        try:
            gpc_session.emit_incident(
                category=source,
                description=reason,
                file=rel,
                source=source,
            )
        except Exception as e:
            logger.debug("GPC incident emit failed: %s", e)
    return _on_deny


def run_sandbox(
    cmd: list[str],
    *,
    repo_root: Path | None = None,
    hardened: bool = False,
    backend_prefer: str | None = None,
    require_gpc: bool = True,
) -> int:
    """Run *cmd* inside a deadpush sandbox session."""
    config = load_config(explicit_root=repo_root)
    repo = config.repo_root.resolve()
    use_hardened = hardened or is_hardened_install(repo)

    gpc_session: GpcSession | None = None
    bindir: str | None = None

    if require_gpc:
        try:
            gpc_session = start_gpc_session(repo, hardened=use_hardened, mandatory=True)
        except GpcMandatoryError as e:
            logger.error("Mandatory GPC unavailable for T2 sandbox: %s", e)
            return 2

    from .backends.linux import LinuxEnforcementBackend

    on_deny = _backend_on_deny(gpc_session)
    try:
        backend = get_backend(repo, prefer=backend_prefer)
    except SandboxUnavailableError as e:
        logger.error("%s", e)
        stop_gpc_session(gpc_session)
        return 2

    if isinstance(backend, LinuxEnforcementBackend):
        backend._on_deny = on_deny

    try:
        backend.start(repo)
    except RuntimeError as e:
        # Fail loud: never soft-fallback to noop. Explicit --backend noop is
        # the only gates-only path, and it is selected before start().
        logger.error("Sandbox backend %r failed to start: %s", backend.name, e)
        stop_gpc_session(gpc_session)
        return 2

    env = prepare_sandbox_env(
        repo, hardened=use_hardened, backend=backend, gpc_session=gpc_session,
    )
    bindir = env.get("DEADPUSH_BIN_DIR")

    try:
        wrapped = backend.wrap_command(cmd, repo_root=repo, env=env)
    except (ValueError, RuntimeError) as e:
        logger.error("Cannot wrap command: %s", e)
        backend.stop()
        stop_gpc_session(gpc_session)
        if bindir:
            shutil.rmtree(bindir, ignore_errors=True)
        return 2

    try:
        result = subprocess.run(wrapped, env=env, cwd=repo)
        return result.returncode
    finally:
        backend.stop()
        stop_gpc_session(gpc_session)
        if bindir:
            shutil.rmtree(bindir, ignore_errors=True)


def describe_backends(repo_root: Path | None = None) -> dict[str, Any]:
    """Report available enforcement backends and the selected default."""
    from .backends.linux import LinuxEnforcementBackend
    from .backends.noop import NoopEnforcementBackend
    from .backends.seatbelt import SeatbeltEnforcementBackend

    config = load_config(explicit_root=repo_root)
    repo = config.repo_root.resolve()
    candidates = [
        SeatbeltEnforcementBackend(repo),
        LinuxEnforcementBackend(repo),
        NoopEnforcementBackend(repo),
    ]
    try:
        selected: dict[str, Any] = get_backend(repo).describe()
    except SandboxUnavailableError as e:
        selected = {
            "name": None,
            "tier": None,
            "available": False,
            "os_sandbox": False,
            "error": str(e),
        }
    return {
        "selected": selected,
        "available": [b.describe() for b in candidates],
    }


def describe_session(repo_root: Path | None = None, *, backend_prefer: str | None = None) -> dict[str, Any]:
    """Return metadata about what a sandbox session would use.

    Raises ``SandboxUnavailableError`` when no confining backend is available
    and ``backend_prefer`` is not ``\"noop\"``.
    """
    config = load_config(explicit_root=repo_root)
    repo = config.repo_root.resolve()
    backend = get_backend(repo, prefer=backend_prefer)
    from .gpc import gpc_socket_path

    return {
        "repo_root": str(repo),
        "backend": backend.describe(),
        "tier": backend.tier,
        "gpc": {
            "mandatory": True,
            "socket": str(gpc_socket_path(repo, hardened=is_hardened_install(repo))),
        },
        "features": ["git-wrapper", "gpc-mandatory", "enforcement-backend"],
    }
