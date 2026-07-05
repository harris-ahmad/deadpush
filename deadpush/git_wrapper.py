"""Git wrapper for deadpush run --sandbox — enforces guardrails on commit/push."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def find_real_git() -> str:
    """Locate the real git binary, skipping deadpush wrappers."""
    override = os.environ.get("DEADPUSH_REAL_GIT")
    if override and Path(override).exists():
        return override
    for candidate in ("/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git"):
        if Path(candidate).exists():
            return candidate
    found = shutil.which("git")
    if found:
        # Avoid calling ourselves if we're named git on PATH
        if "deadpush" not in found.lower():
            return found
    return "git"


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    repo_root = os.environ.get("DEADPUSH_REPO_ROOT")
    if not repo_root:
        repo_root = str(Path.cwd())
    repo = Path(repo_root).resolve()

    subcmd = args[0] if args else ""
    no_verify = "--no-verify" in args or "-n" in args

    if subcmd in ("commit", "push") and not no_verify:
        from .hooks import run_precommit_guardrails, run_prepush_guardrails

        if subcmd == "commit":
            ok, violations = run_precommit_guardrails(repo)
            if not ok:
                print("deadpush: commit blocked by guardrails:", file=sys.stderr)
                for v in violations[:5]:
                    print(f"  - {v.get('category', '?')}: {v.get('description', v)}", file=sys.stderr)
                return 1
        elif subcmd == "push":
            ok, violations = run_prepush_guardrails(repo)
            if not ok:
                print("deadpush: push blocked by guardrails:", file=sys.stderr)
                for v in violations[:5]:
                    print(f"  - {v.get('category', '?')}: {v.get('description', v)}", file=sys.stderr)
                return 1

    real_git = find_real_git()
    return os.spawnv(os.P_WAIT, real_git, ["git", *args])


if __name__ == "__main__":
    raise SystemExit(main())
