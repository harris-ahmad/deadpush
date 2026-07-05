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

from .backends.base import EnforcementBackend, get_backend
from .config import is_hardened_install, load_config
from .gpc import GpcServer

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

    return env


def run_sandbox(
    cmd: list[str],
    *,
    repo_root: Path | None = None,
    hardened: bool = False,
    backend_prefer: str | None = None,
    start_gpc: bool = True,
) -> int:
    """Run *cmd* inside a deadpush sandbox session."""
    config = load_config(explicit_root=repo_root)
    repo = config.repo_root.resolve()
    use_hardened = hardened or is_hardened_install(repo)

    backend = get_backend(repo, prefer=backend_prefer)
    gpc: GpcServer | None = None
    bindir: str | None = None

    if start_gpc:
        gpc = GpcServer(repo, hardened=use_hardened)
        try:
            gpc.start()
        except OSError as e:
            logger.warning("GPC unavailable for sandbox session: %s", e)
            gpc = None

    try:
        backend.start(repo)
    except RuntimeError as e:
        logger.error("Backend start failed: %s", e)
        if backend_prefer == "seatbelt":
            raise
        from .backends.noop import NoopEnforcementBackend
        logger.warning(
            "Falling back to T2-partial (noop): OS sandbox unavailable — "
            "git/MCP/guardian gates only, not syscall confinement"
        )
        backend = NoopEnforcementBackend(repo)
        backend.start(repo)

    env = prepare_sandbox_env(repo, hardened=use_hardened, backend=backend)
    bindir = env.get("DEADPUSH_BIN_DIR")

    try:
        wrapped = backend.wrap_command(cmd, repo_root=repo, env=env)
    except (ValueError, RuntimeError) as e:
        logger.error("Cannot wrap command: %s", e)
        return 2

    try:
        result = subprocess.run(wrapped, env=env, cwd=repo)
        return result.returncode
    finally:
        backend.stop()
        if gpc:
            gpc.stop()
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
    selected = get_backend(repo)
    return {
        "selected": selected.describe(),
        "available": [b.describe() for b in candidates],
    }


def describe_session(repo_root: Path | None = None, *, backend_prefer: str | None = None) -> dict[str, Any]:
    """Return metadata about what a sandbox session would use."""
    config = load_config(explicit_root=repo_root)
    repo = config.repo_root.resolve()
    backend = get_backend(repo, prefer=backend_prefer)
    return {
        "repo_root": str(repo),
        "backend": backend.describe(),
        "tier": backend.tier,
        "features": ["git-wrapper", "gpc", "enforcement-backend"],
    }
