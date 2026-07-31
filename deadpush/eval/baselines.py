"""Baseline adapters for thesis eval (B0–B4 + ablation)."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from deadpush.git_wrapper import main as git_wrapper_main
from deadpush.intercept import enforce_content
from deadpush.savepoints import SavePointStore


class Baseline(Protocol):
    id: str

    def setup(self, repo: Path) -> None: ...

    def write_file(self, repo: Path, rel: str, content: str) -> bool:
        """Write *rel*; return True if the write was allowed to stick."""
        ...

    def run_git(self, repo: Path, args: list[str]) -> int: ...

    def checkpoint(self, repo: Path, label: str = "eval") -> str | None:
        """Optional pre-risk save point; return id or None."""
        ...

    def recover(self, repo: Path, savepoint_id: str | None) -> float:
        """Restore if supported; return time-to-recover ms."""
        ...


def _real_git(repo: Path, args: list[str], *, env: dict[str, str] | None = None) -> int:
    merged = dict(os.environ)
    if env:
        merged.update(env)
    # Prefer system git, not a deadpush shim on PATH.
    cmd = ["git", *args]
    proc = subprocess.run(cmd, cwd=repo, env=merged, capture_output=True)
    return int(proc.returncode)


def _plain_write(repo: Path, rel: str, content: str) -> bool:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


@dataclass
class B0NoGuardian:
    """No guardian — all writes and git commands go through."""

    id: str = "B0"

    def setup(self, repo: Path) -> None:
        return None

    def write_file(self, repo: Path, rel: str, content: str) -> bool:
        return _plain_write(repo, rel, content)

    def run_git(self, repo: Path, args: list[str]) -> int:
        return _real_git(repo, args)

    def checkpoint(self, repo: Path, label: str = "eval") -> str | None:
        return None

    def recover(self, repo: Path, savepoint_id: str | None) -> float:
        return 0.0


@dataclass
class B1IgnoreOnly(B0NoGuardian):
    """``.gitignore`` / ignore files only — does not block agent writes."""

    id: str = "B1"

    def setup(self, repo: Path) -> None:
        gitignore = repo / ".gitignore"
        rules = "\n".join([".env", ".env.*", "CLAUDE.md", "*.scratch.md", ""])
        gitignore.write_text(rules, encoding="utf-8")


@dataclass
class B2HooksOnly(B0NoGuardian):
    """Pre-commit / pre-push guardrails only (no staged git intercept)."""

    id: str = "B2"

    def setup(self, repo: Path) -> None:
        from deadpush.hooks import install_hook, install_precommit_hook

        install_precommit_hook(repo, system=False)
        install_hook(repo, system=False)

    def run_git(self, repo: Path, args: list[str]) -> int:
        # Use wrapper outside sandbox so staged deny is off, but commit/push
        # guardrails still run.
        prev = {k: os.environ.get(k) for k in (
            "DEADPUSH_REPO_ROOT",
            "DEADPUSH_SANDBOX",
            "DEADPUSH_ALLOW_DESTRUCTIVE_GIT",
        )}
        try:
            os.environ["DEADPUSH_REPO_ROOT"] = str(repo.resolve())
            os.environ.pop("DEADPUSH_SANDBOX", None)
            os.environ["DEADPUSH_ALLOW_DESTRUCTIVE_GIT"] = "1"
            cwd = Path.cwd()
            try:
                os.chdir(repo)
                return int(git_wrapper_main(args))
            finally:
                os.chdir(cwd)
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


@dataclass
class B3QuarantineOnly(B0NoGuardian):
    """Content enforcement on writes; destructive git still allowed."""

    id: str = "B3"

    def write_file(self, repo: Path, rel: str, content: str) -> bool:
        from deadpush.config import Config
        from deadpush.rules import RuntimeConfig

        config = Config(repo_root=repo)
        runtime = RuntimeConfig(repo)
        result = enforce_content(rel, content, config, runtime)
        if not result.allowed:
            # Quarantine-only: refuse to leave the payload in-tree.
            return False
        return _plain_write(repo, rel, content)

    def run_git(self, repo: Path, args: list[str]) -> int:
        # Explicitly allow destructive git (no staged deny).
        return _real_git(repo, args, env={"DEADPUSH_ALLOW_DESTRUCTIVE_GIT": "1"})


@dataclass
class B4StagedRecovery:
    """Journal + save points + sandbox staged git deny (system under test)."""

    id: str = "B4"

    def setup(self, repo: Path) -> None:
        SavePointStore(repo)  # ensure layout

    def write_file(self, repo: Path, rel: str, content: str) -> bool:
        from deadpush.config import Config
        from deadpush.rules import RuntimeConfig

        config = Config(repo_root=repo)
        runtime = RuntimeConfig(repo)
        result = enforce_content(rel, content, config, runtime)
        if not result.allowed:
            return False
        return _plain_write(repo, rel, content)

    def run_git(self, repo: Path, args: list[str]) -> int:
        prev = {k: os.environ.get(k) for k in (
            "DEADPUSH_REPO_ROOT",
            "DEADPUSH_SANDBOX",
            "DEADPUSH_ALLOW_DESTRUCTIVE_GIT",
        )}
        try:
            os.environ["DEADPUSH_REPO_ROOT"] = str(repo.resolve())
            os.environ["DEADPUSH_SANDBOX"] = "1"
            os.environ.pop("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", None)
            cwd = Path.cwd()
            try:
                os.chdir(repo)
                return int(git_wrapper_main(args))
            finally:
                os.chdir(cwd)
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def checkpoint(self, repo: Path, label: str = "eval") -> str | None:
        sp = SavePointStore(repo).create(label=label, validate=True)
        return sp.id

    def recover(self, repo: Path, savepoint_id: str | None) -> float:
        import time

        if not savepoint_id:
            return 0.0
        t0 = time.perf_counter()
        SavePointStore(repo).restore(savepoint_id)
        return (time.perf_counter() - t0) * 1000.0


@dataclass
class B4JournalNoStagedGit(B4StagedRecovery):
    """Ablation: journal/save points without staged git deny."""

    id: str = "B4-ablation"

    def run_git(self, repo: Path, args: list[str]) -> int:
        return _real_git(repo, args, env={"DEADPUSH_ALLOW_DESTRUCTIVE_GIT": "1"})


ALL_BASELINES: dict[str, Baseline] = {
    "B0": B0NoGuardian(),
    "B1": B1IgnoreOnly(),
    "B2": B2HooksOnly(),
    "B3": B3QuarantineOnly(),
    "B4": B4StagedRecovery(),
    "B4-ablation": B4JournalNoStagedGit(),
}
