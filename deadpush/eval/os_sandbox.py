"""OS-confined execution helpers for thesis eval (§9).

Prefers write-jail backends (Seatbelt / bubblewrap) so the harness can run
without CAP_SYS_ADMIN fanotify. Raises when no ``os_confinement`` backend
is available — never silently falls back to in-process gates.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from deadpush.backends.base import (
    EnforcementBackend,
    SandboxUnavailableError,
)


def select_eval_os_backend(
    repo_root: Path,
    *,
    prefer: str | None = None,
) -> EnforcementBackend:
    """Pick a backend with ``os_confinement=True`` for eval runs."""
    from deadpush.backends.base import get_backend
    from deadpush.backends.bubblewrap import BubblewrapEnforcementBackend
    from deadpush.backends.linux_sandbox import LinuxSandboxBackend
    from deadpush.backends.seatbelt import SeatbeltEnforcementBackend

    repo = repo_root.resolve()
    if prefer:
        backend = get_backend(repo, prefer=prefer)
        if not backend.capabilities.os_confinement:
            raise SandboxUnavailableError(
                f"Backend {backend.name!r} is available but lacks os_confinement "
                "(need Seatbelt or bubblewrap write jail)."
            )
        return backend

    # Eval order: pure write jails first, then composite linux-sandbox.
    for factory in (
        SeatbeltEnforcementBackend,
        BubblewrapEnforcementBackend,
        LinuxSandboxBackend,
    ):
        candidate = factory(repo)
        if candidate.available() and candidate.capabilities.os_confinement:
            return candidate

    raise SandboxUnavailableError(
        "No OS confinement backend for eval. Need Seatbelt (macOS) or "
        "bubblewrap / linux-sandbox (Linux)."
    )


def os_confinement_status(repo_root: Path) -> dict[str, object]:
    """Describe whether this host can run OS-confined eval."""
    try:
        backend = select_eval_os_backend(repo_root)
    except SandboxUnavailableError as e:
        return {
            "available": False,
            "backend": None,
            "capabilities": {},
            "error": str(e),
        }
    return {
        "available": True,
        "backend": backend.name,
        "capabilities": backend.capabilities.as_dict(),
        "error": None,
    }


def run_under_os_sandbox(
    repo_root: Path,
    cmd: list[str],
    *,
    prefer: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Start backend, wrap *cmd*, run, stop. Caller inspects returncode."""
    import deadpush

    repo = repo_root.resolve()
    backend = select_eval_os_backend(repo, prefer=prefer)
    try:
        backend.start(repo)
        env = dict(os.environ)
        env["DEADPUSH_REPO_ROOT"] = str(repo)
        env["DEADPUSH_SANDBOX"] = "1"
        env.pop("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", None)
        # Child cwd is the temp eval repo; ensure ``import deadpush`` still works.
        pkg_root = str(Path(deadpush.__file__).resolve().parent.parent)
        prev_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            pkg_root if not prev_pp else f"{pkg_root}{os.pathsep}{prev_pp}"
        )
        backend.apply_env_markers(env)
        if extra_env:
            env.update(extra_env)
        wrapped = backend.wrap_command(cmd, repo_root=repo, env=env)
        return subprocess.run(wrapped, cwd=repo, env=env, capture_output=True)
    finally:
        backend.stop()


def outside_probe_dir(repo_root: Path) -> Path:
    """Directory that must *not* be writable under the OS write allowlist.

    Temp dirs (``/var/folders``, ``/tmp``) are intentionally writable for agent
    caches, so probes next to a tempfile repo would falsely pass. Prefer a
    path under ``$HOME`` outside ``~/.deadpush`` (and outside the repo).
    """
    repo = repo_root.resolve()
    home = Path.home().resolve()
    # Hyphen after "deadpush" so this is not under ~/.deadpush/.
    candidate = home / f".deadpush-eval-outside-{os.getpid()}"
    if candidate == repo or repo in candidate.parents:
        candidate = home / "Library" / f".deadpush-eval-outside-{os.getpid()}"
    return candidate


def probe_outside_write_blocked(
    repo_root: Path,
    outside_dir: Path | None = None,
) -> bool:
    """True when OS jail blocks creating a file under *outside_dir*."""
    repo = repo_root.resolve()
    outside = (outside_dir or outside_probe_dir(repo)).resolve()
    outside.mkdir(parents=True, exist_ok=True)
    probe = outside / f".deadpush_eval_probe_{os.getpid()}"
    if probe.exists():
        probe.unlink()
    # Portable: python one-liner under the jail.
    script = (
        "import pathlib,sys;"
        f"p=pathlib.Path({str(probe)!r});"
        "p.write_text('x',encoding='utf-8')"
    )
    proc = run_under_os_sandbox(repo, [sys.executable, "-c", script])
    blocked = proc.returncode != 0 or not probe.exists()
    if probe.exists():
        try:
            probe.unlink()
        except OSError:
            pass
    try:
        if outside_dir is None and outside.exists() and not any(outside.iterdir()):
            outside.rmdir()
    except OSError:
        pass
    return blocked
