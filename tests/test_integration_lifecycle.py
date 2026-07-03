"""End-to-end lifecycle integration test (deterministic, no background daemon).

This is the CI-facing "does a real install actually work" test. It drives the
installed CLI as a user would, then executes the *real* generated git hook
file — which is what catches interpreter/bootstrap regressions that in-process
unit tests miss (e.g. the hook using `-m deadpush.cli` and failing to import
deadpush from a non-source working directory).

Runs in --soft mode with no daemon so it is fully deterministic and leaves no
launchd/systemd state behind.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = Path(__file__).resolve().parent.parent


def _cli() -> list[str]:
    """Resolve how to invoke the deadpush CLI, preferring the console script."""
    console = Path(sys.executable).parent / "deadpush"
    if console.is_file():
        return [str(console)]
    on_path = shutil.which("deadpush")
    if on_path:
        return [on_path]
    return [sys.executable, "-m", "deadpush_bootstrap"]


def _env() -> dict:
    env = os.environ.copy()
    root = str(REPO_ROOT)
    parts = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    if root not in parts:
        parts.insert(0, root)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env


def _run(args: list[str], cwd: Path, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(
        _cli() + args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=_env(),
        timeout=120,
        **kw,
    )


@pytest.fixture
def cli_available() -> bool:
    try:
        r = subprocess.run(
            _cli() + ["--version"], capture_output=True, text=True, env=_env(), timeout=60
        )
    except Exception:
        pytest.skip("deadpush CLI not runnable in this environment")
    if r.returncode != 0:
        pytest.skip(f"deadpush CLI not runnable: {r.stderr.strip()[:200]}")
    return True


class TestProtectLifecycle:
    def test_protect_soft_no_daemon_succeeds(self, temp_repo: Path, cli_available):
        r = _run(["protect", "--soft"], cwd=temp_repo)
        assert r.returncode == 0, f"protect failed:\n{r.stdout}\n{r.stderr}"

        # Marker written, hooks installed and verified.
        assert (temp_repo / ".deadpush" / "installed").exists()
        for hook in ("pre-push", "pre-commit", "post-commit"):
            assert (temp_repo / ".git" / "hooks" / hook).exists(), f"{hook} missing"

    def test_installed_pre_push_hook_blocks_dangerous_push(self, temp_repo: Path, cli_available):
        """Execute the REAL generated hook file end-to-end.

        This is the regression guard for the hook interpreter/bootstrap path:
        the hook must be able to import deadpush and run guardrails from a
        working directory that is not the deadpush source tree.
        """
        r = _run(["protect", "--soft"], cwd=temp_repo)
        assert r.returncode == 0, f"protect failed:\n{r.stdout}\n{r.stderr}"

        hook = temp_repo / ".git" / "hooks" / "pre-push"
        assert hook.exists()

        # A security violation in a normal source file (not an ignored debris name).
        parent = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=temp_repo, capture_output=True, text=True
        ).stdout.strip()
        (temp_repo / "runner.py").write_text(
            "import subprocess\nsubprocess.run('ls', shell=True)\n"
        )
        subprocess.run(["git", "add", "runner.py"], cwd=temp_repo, capture_output=True)
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "danger", "--no-verify"],
            cwd=temp_repo, capture_output=True,
        )
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=temp_repo, capture_output=True, text=True
        ).stdout.strip()

        # Normal push to an existing branch: range = parent..head.
        stdin = f"refs/heads/main {head} refs/heads/main {parent}\n"
        result = subprocess.run(
            [str(hook), "origin", str(temp_repo)],
            cwd=str(temp_repo),
            input=stdin,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 1, (
            "pre-push hook did not block a dangerous push.\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
        assert "blocked" in result.stdout.lower()

    def test_uninstall_removes_hooks_and_marker(self, temp_repo: Path, cli_available):
        r = _run(["protect", "--soft"], cwd=temp_repo)
        assert r.returncode == 0, f"protect failed:\n{r.stdout}\n{r.stderr}"
        assert (temp_repo / ".deadpush" / "installed").exists()

        u = _run(["uninstall", "--force"], cwd=temp_repo)
        assert u.returncode == 0, f"uninstall failed:\n{u.stdout}\n{u.stderr}"
        assert not (temp_repo / ".deadpush" / "installed").exists()
        for hook in ("pre-push", "pre-commit", "post-commit"):
            assert not (temp_repo / ".git" / "hooks" / hook).exists(), f"{hook} lingering"
