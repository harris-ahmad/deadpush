"""Staged intercept for high-risk git commands (thesis Phase 3).

Wrapper-path first: classify ``reset --hard`` / force-push, create a save point,
then deny the command so the agent process is not killed and work is not lost.
GPC negotiate / human-in-the-loop comes later.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .savepoints import SavePointStore

# Flags that make ``git push`` a force-style update.
_FORCE_PUSH_FLAGS = frozenset(
    {
        "--force",
        "-f",
        "--force-with-lease",
        "--force-if-includes",
    }
)


@dataclass(frozen=True)
class DestructiveGit:
    """A classified high-risk git invocation."""

    kind: str  # "reset_hard" | "force_push"
    reason: str
    label: str


def classify_destructive_git(args: list[str]) -> DestructiveGit | None:
    """Return a classification if *args* are high-risk, else ``None``."""
    rest = _args_after_globals(args)
    if not rest:
        return None
    subcmd = rest[0]
    trailing = rest[1:]

    if subcmd == "reset" and "--hard" in trailing:
        return DestructiveGit(
            kind="reset_hard",
            reason="git reset --hard discards uncommitted work",
            label="pre-reset-hard",
        )

    if subcmd == "push" and _is_force_push(trailing):
        return DestructiveGit(
            kind="force_push",
            reason="git push --force (or lease) can rewrite remote history",
            label="pre-force-push",
        )

    return None


def stage_and_deny(repo_root: Path, hit: DestructiveGit) -> int:
    """Checkpoint via save point, print structured deny, return exit code 1.

    Fail closed: if the save point cannot be created, still deny the command.
    """
    savepoint_id = ""
    sp_error = ""
    try:
        sp = SavePointStore(repo_root).create(label=hit.label, validate=True)
        savepoint_id = sp.id
    except Exception as e:  # noqa: BLE001 — deny path must not raise into wrapper
        sp_error = str(e)

    print(f"deadpush: staged deny: {hit.reason}", file=sys.stderr)
    if savepoint_id:
        print(f"deadpush: savepoint created: {savepoint_id} (label={hit.label})", file=sys.stderr)
    else:
        print(
            f"deadpush: savepoint create failed (command still denied): {sp_error or 'unknown'}",
            file=sys.stderr,
        )
    for line in _safer_alternatives(hit.kind):
        print(f"deadpush: safer: {line}", file=sys.stderr)
    return 1


def _safer_alternatives(kind: str) -> list[str]:
    if kind == "reset_hard":
        return [
            "git reset --soft <commit>  (keeps working tree)",
            "git revert <commit>        (adds an inverse commit)",
            "restore a save point via SavePointStore.restore(<id>) if needed",
        ]
    if kind == "force_push":
        return [
            "git push                  (fast-forward only)",
            "git push --force-with-lease is also denied; ask a human if rewrite is required",
        ]
    return []


def _is_force_push(trailing: list[str]) -> bool:
    for arg in trailing:
        if arg in _FORCE_PUSH_FLAGS:
            return True
        # --force-with-lease=<ref>
        if arg.startswith("--force-with-lease="):
            return True
    return False


def _args_after_globals(args: list[str]) -> list[str]:
    """Skip git global options; return [subcommand, ...]."""
    i = 0
    n = len(args)
    while i < n:
        arg = args[i]
        if arg == "--":
            return args[i + 1 :]
        if arg == "-C" and i + 1 < n:
            i += 2
            continue
        if arg in ("-c", "--config") and i + 1 < n:
            i += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            i += 1
            continue
        if arg.startswith("--git-dir=") or arg.startswith("--work-tree=") or arg.startswith(
            "--namespace="
        ) or arg.startswith("--exec-path="):
            i += 1
            continue
        if arg in ("--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < n:
            i += 2
            continue
        if arg == "--exec-path":
            i += 1
            continue
        if arg in (
            "--bare",
            "--no-replace-objects",
            "--literal-pathspecs",
            "--glob-pathspecs",
            "--noglob-pathspecs",
            "--icase-pathspecs",
            "--no-optional-locks",
        ):
            i += 1
            continue
        # First non-global token is the subcommand (or a path that isn't a global).
        break
    return args[i:]
