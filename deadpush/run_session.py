"""Agent session wrapper — deadpush run --sandbox."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .backends.base import get_backend
from .config import is_hardened_install, load_config
from .gpc import GpcServer


def _make_git_wrapper_bin(repo_root: Path) -> Path:
    """Create a temp bin dir with a `git` shim pointing to deadpush git-wrapper."""
    bindir = Path(tempfile.mkdtemp(prefix="deadpush-bin-"))
    git_shim = bindir / "git"
    # Resolve deadpush executable
    deadpush = shutil.which("deadpush") or sys.executable
    if deadpush.endswith("python") or deadpush.endswith("python3"):
        wrapper = f'''#!/bin/sh
export DEADPUSH_REPO_ROOT="{repo_root}"
exec "{sys.executable}" -m deadpush.git_wrapper "$@"
'''
    else:
        wrapper = f'''#!/bin/sh
export DEADPUSH_REPO_ROOT="{repo_root}"
exec "{deadpush}" git-wrapper "$@"
'''
    git_shim.write_text(wrapper, encoding="utf-8")
    git_shim.chmod(0o755)
    return bindir


def prepare_sandbox_env(repo_root: Path, *, hardened: bool = False) -> dict[str, str]:
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

    if start_gpc:
        gpc = GpcServer(repo, hardened=use_hardened)
        try:
            gpc.start()
        except OSError:
            gpc = None

    backend.start(repo)
    env = prepare_sandbox_env(repo, hardened=use_hardened)
    wrapped = backend.wrap_command(cmd, repo_root=repo, env=env)

    try:
        result = subprocess.run(wrapped, env=env, cwd=repo)
        return result.returncode
    finally:
        backend.stop()
        if gpc:
            gpc.stop()
        bindir = env.get("DEADPUSH_BIN_DIR")
        if bindir:
            shutil.rmtree(bindir, ignore_errors=True)


def describe_session(repo_root: Path | None = None, *, backend_prefer: str | None = None) -> dict[str, Any]:
    """Return metadata about what a sandbox session would use."""
    config = load_config(explicit_root=repo_root)
    repo = config.repo_root.resolve()
    backend = get_backend(repo, prefer=backend_prefer)
    return {
        "repo_root": str(repo),
        "backend": backend.describe(),
        "tier": "T2",
        "features": ["git-wrapper", "gpc", "enforcement-backend"],
    }
