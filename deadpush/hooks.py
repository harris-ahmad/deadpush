"""
Extension Hooks for deadpush AI Agent Guardian.

This module provides clean extension points for future integrations with
Cursor, Claude Code, Windsurf, and other AI coding environments.

Currently a foundation. Future versions can expose:
- Pre-file-creation hooks
- Pre-git-commit hooks (beyond current pre-push)
- Custom rule engines
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


class HookRegistry:
    """Simple hook registry for extensibility."""

    def __init__(self):
        self._hooks: dict[str, list[Callable]] = {}

    def register(self, event: str, func: Callable):
        if event not in self._hooks:
            self._hooks[event] = []
        self._hooks[event].append(func)

    def trigger(self, event: str, *args, **kwargs) -> list[Any]:
        results = []
        for func in self._hooks.get(event, []):
            try:
                results.append(func(*args, **kwargs))
            except Exception as e:
                print(f"Hook {event} failed: {e}")
        return results


hooks = HookRegistry()

def _make_immutable(path: Path, *, system: bool = False) -> bool:
    """Set the OS-level immutable flag on `path`.

    - Soft mode (``system=False``): USER-immutable — `chflags uchg` (macOS) /
      `chattr +i` (Linux). The file *owner* can still clear it, so a same-UID
      agent can undo it; this only deters casual/accidental removal.
    - Hardened mode (``system=True``): ROOT-immutable — `sudo chflags schg`
      (macOS) / `sudo chattr +i` (Linux). Only root can clear the flag, so a
      same-UID agent cannot delete, rename, or overwrite the hook at all.

    Returns True if the flag was set, False if it could not be (unsupported OS/fs
    or missing privileges). Callers treat False as non-fatal.
    """
    try:
        if sys.platform == "darwin":
            flag = "schg" if system else "uchg"
            cmd = (["sudo"] if system else []) + ["chflags", flag, str(path)]
        elif sys.platform.startswith("linux"):
            cmd = (["sudo"] if system else []) + ["chattr", "+i", str(path)]
        else:
            return False
        result = subprocess.run(cmd, capture_output=True, timeout=15)
        return result.returncode == 0
    except Exception:
        return False


def _make_mutable(path: Path, *, system: bool = False) -> bool:
    """Remove the OS-level immutable flag from `path` (reverse of `_make_immutable`).

    Must succeed before the file can be updated or removed. With ``system=True``
    this uses sudo and clears BOTH the system- and user-immutable flags, since a
    hardened hook may carry either (e.g. after a sudo->non-sudo fallback).
    """
    try:
        if sys.platform == "darwin":
            if system:
                cmd = ["sudo", "chflags", "noschg,nouchg", str(path)]
            else:
                cmd = ["chflags", "nouchg", str(path)]
        elif sys.platform.startswith("linux"):
            cmd = (["sudo"] if system else []) + ["chattr", "-i", str(path)]
        else:
            return True
        subprocess.run(cmd, capture_output=True, timeout=15)
        return True
    except Exception:
        return False


def _is_immutable(path: Path) -> bool:
    """Check whether a USER- or SYSTEM-immutable flag is set on `path`.

    Only supported on macOS (checks both UF_IMMUTABLE/uchg and SF_IMMUTABLE/schg).
    On other platforms returns False. Recognising schg here is essential: without
    it the daemon would treat a root-immutable hook as "not immutable" and loop
    trying to repair a file it cannot rewrite.
    """
    try:
        if sys.platform == "darwin":
            st = path.stat()
            mask = stat.UF_IMMUTABLE | getattr(stat, "SF_IMMUTABLE", 0x00020000)
            return bool(st.st_flags & mask)
        return False
    except Exception:
        return False


# Core patterns merged into ignore files during setup
GUARDIAN_IGNORE_PATTERNS = {
    "claude.md", ".cursorrules", ".claude_instructions", ".copilot-instructions.md",
    "windsurf_rules.md", "agents.md", "llm_context.txt", "ai_prompt.md",
    # deadpush's own state must never be committed — otherwise `git add -A` sweeps in
    # feedback records (which quote the secrets deadpush caught) and the hooks then
    # flag deadpush's own logs instead of the real payload.
    ".deadpush/", ".deadpush-autoignore", ".deadpush-quarantine/", ".deadpush-archive/",
    ".deadpush-config-backups/",
    "**/scratch*.md", "**/temp*.py", "**/tmp*.go", "**/playground.*",
    "node_modules/", "__pycache__/", ".venv/", "venv/", "target/", "dist/",
}


def merge_guardian_ignore_files(repo_root: Path, extra: set[str] | None = None) -> int:
    """Merge guardian ignore patterns into .cursorignore, .claudeignore, .gitignore."""
    patterns = set(GUARDIAN_IGNORE_PATTERNS)
    if extra:
        patterns |= extra
    added = 0
    for ignore_name in (".cursorignore", ".claudeignore", ".gitignore"):
        ignore_path = repo_root / ignore_name
        existing: set[str] = set()
        if ignore_path.exists():
            try:
                existing = {
                    line.strip()
                    for line in ignore_path.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")
                }
            except Exception:
                continue
        to_add = patterns - existing
        if not to_add:
            continue
        with ignore_path.open("a", encoding="utf-8") as f:
            f.write("\n# Added by deadpush\n")
            for pattern in sorted(to_add):
                f.write(f"{pattern}\n")
        added += len(to_add)
        print(f"  → Updated {ignore_name} with {len(to_add)} patterns")
    return added


def _print_violations(header: str, violations: list[dict[str, Any]], footer: str) -> None:
    print(f"\n{header}\n")
    for v in violations:
        icon = {"critical": "🔴", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(v["severity"], "⚡")
        print(f"  {icon} {v['file']}:{v['line']}  [{v['category']}] {v['description'][:100]}")
    print("")
    print(footer)


def _enforce_git_paths(
    repo_root: Path,
    paths: list[str],
    *,
    git_ref: str = "HEAD",
) -> list[dict[str, Any]]:
    """Run unified enforcement on files at a git ref."""
    import subprocess
    from .config import load_config
    from .intercept import enforce_content, violations_from_result, is_enforceable_path
    from .rules import RuntimeConfig

    config = load_config(explicit_root=repo_root)
    runtime = RuntimeConfig(repo_root)
    violations: list[dict[str, Any]] = []

    for rel_path in paths:
        if not is_enforceable_path(rel_path):
            continue
        try:
            show_ref = f":{rel_path}" if git_ref == ":" else f"{git_ref}:{rel_path}"
            content = subprocess.run(
                ["git", "show", show_ref],
                capture_output=True, text=True, check=False, timeout=5,
                cwd=repo_root,
            )
            if content.returncode != 0:
                continue
            source = content.stdout
        except Exception:
            continue

        result = enforce_content(rel_path, source, config, runtime)
        violations.extend(violations_from_result(rel_path, result))

    return violations


def run_precommit_guardrails(repo_root: Path) -> tuple[bool, list[dict[str, Any]]]:
    """Run guardrails on staged files. Returns (passed, violations)."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True, text=True, check=False, timeout=10,
            cwd=repo_root,
        )
        if result.returncode != 0:
            return True, []
        staged = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return True, []

    violations = _enforce_git_paths(repo_root, staged, git_ref=":")

    if violations:
        _print_violations(
            f"deadpush — Pre-commit guardrails found {len(violations)} violation(s):",
            violations,
            "Commit blocked. Fix the violations above or use `git commit --no-verify` to skip.",
        )
        return False, violations

    return True, []


def install_hook(repo_root: Path, *, system: bool = False) -> None:
    """
    Install a cross-platform pre-push git hook.

    The hook runs `deadpush hooks run-prepush` (via the current Python
    to avoid PATH/venv issues) and blocks the push if guardrail violations
    are found in outgoing commits.

    This version uses a Python script instead of Bash so it works on:
    - Windows (PowerShell, CMD, Git for Windows without Git Bash)
    - macOS / Linux
    - Any environment where Python can run the deadpush module.

    ``system=True`` (hardened mode) locks the hook root-immutable (schg/sudo).
    Idempotent.
    """
    _write_hook_file(repo_root, "pre-push", system=system)


# Shared prelude embedded into every generated hook. It decides what to do
# when the pinned deadpush interpreter cannot be launched at all
# (FileNotFoundError). Policy:
#   - If this repo was protected (a `.deadpush/installed` marker exists) OR
#     DEADPUSH_STRICT is set, FAIL CLOSED (block the git operation).
#   - Otherwise (repo was never protected), fail open so unrelated repos are
#     not disrupted by a stale global hook path.
_HOOK_FAILCLOSED_PRELUDE = '''import hashlib
import os
import subprocess
import sys


def _deadpush_strict():
    val = os.environ.get("DEADPUSH_STRICT", "").strip().lower()
    return val not in ("", "0", "false", "no", "off")


def _deadpush_repo_protected():
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return False
        root = r.stdout.strip()
        if not root:
            return False
        if os.path.exists(os.path.join(root, ".deadpush", "installed")):
            return True
        # Hardened installs also record a root-owned marker the same-UID agent
        # cannot delete, so fail-closed holds even if the in-repo marker is gone.
        rid = hashlib.sha256(root.encode()).hexdigest()[:12]
        return os.path.exists(os.path.join("/var/db/deadpush", "policy", rid, "installed"))
    except Exception:
        return False


def _deadpush_handle_missing(op):
    """Called when the deadpush interpreter itself cannot be launched."""
    if _deadpush_strict() or _deadpush_repo_protected():
        print("deadpush cannot run but this repo is protected by deadpush.")
        print("Refusing to " + op + " (fail-closed). Run `deadpush doctor` to diagnose,")
        print("or `deadpush uninstall` to remove protection from this repo.")
        sys.exit(1)
    print("deadpush not installed for this repo — skipping hook.")
    sys.exit(0)
'''

def _get_hook_script(hook_name: str, python_exe: str) -> str:
    """Return the script content for a given hook name."""
    if hook_name == "pre-push":
        return f'''#!/usr/bin/env python3
"""
deadpush pre-push git hook (installed by deadpush protect).

Scans outgoing commits for guardrail violations and blocks the push
if dangerous code is found. Reads stdin for the commit range.
"""
{_HOOK_FAILCLOSED_PRELUDE}

def main():
    try:
        cmd = [r"{python_exe}", "-m", "deadpush_bootstrap", "hooks", "run-prepush"]
        result = subprocess.run(cmd, capture_output=False, text=True, check=False)
        if result.returncode != 0:
            print("deadpush guardrails blocked this push.")
            print("Fix the violations above or use --no-verify (not recommended).")
            sys.exit(1)
    except FileNotFoundError:
        _deadpush_handle_missing("push")

if __name__ == "__main__":
    main()
'''
    if hook_name == "pre-commit":
        return f'''#!/usr/bin/env python3
"""
deadpush pre-commit guardrails (installed by deadpush hook install-precommit).

Blocks commits with prompt injection, hardcoded secrets,
security violations, and architecture layer violations.
"""
{_HOOK_FAILCLOSED_PRELUDE}

def main():
    try:
        cmd = [r"{python_exe}", "-m", "deadpush_bootstrap", "hooks", "run-precommit"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        if result.returncode != 0:
            print("deadpush guardrails blocked this commit.")
            sys.exit(1)
    except FileNotFoundError:
        _deadpush_handle_missing("commit")

if __name__ == "__main__":
    main()
'''
    if hook_name == "post-commit":
        return f'''#!/usr/bin/env python3
"""
deadpush post-commit guardrails (installed by deadpush protect).
Reverts commits containing dangerous code even if --no-verify was used.
"""
{_HOOK_FAILCLOSED_PRELUDE}

def main():
    try:
        cmd = [r"{python_exe}", "-m", "deadpush_bootstrap", "hooks", "run-postcommit"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.stdout:
            for line in result.stdout.splitlines():
                print(line)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        if result.returncode != 0:
            print("deadpush guardrails reverted this commit due to dangerous code.")
            print("The changes are still staged (git reset --soft HEAD~1).")
            print("Review and fix the issues above, then commit again.")
            sys.exit(1)
    except FileNotFoundError:
        # post-commit runs after the commit exists; blocking here cannot undo it,
        # so surface the failure loudly but do not hard-exit the commit flow.
        print("deadpush cannot run post-commit checks (interpreter missing).")
        print("Run `deadpush doctor` — this commit was NOT scanned.")
        sys.exit(0)

if __name__ == "__main__":
    main()
'''
    raise ValueError(f"Unknown hook: {hook_name}")


def _save_hook_checksum(repo_root: Path, hook_name: str, script: str) -> None:
    """Compute and save SHA256 checksum for a hook script."""
    checksums_dir = repo_root / ".deadpush" / "hooks"
    checksums_dir.mkdir(parents=True, exist_ok=True)
    sha256_hash = hashlib.sha256(script.encode("utf-8")).hexdigest()
    checksum_file = checksums_dir / f"{hook_name}.sha256"
    checksum_file.write_text(sha256_hash, encoding="utf-8")


def _write_hook_file(repo_root: Path, hook_name: str, *, system: bool = False) -> None:
    """Write a git hook script to .git/hooks/{hook_name} and save its checksum.

    Used by both the CLI installer and the guardian's auto-restore. The file is
    made immutable to prevent the agent from silently moving or deleting it:
    root-immutable (`schg`/sudo) when ``system=True`` (hardened mode), otherwise
    user-immutable (`uchg`).
    """
    hooks_dir = repo_root / ".git" / "hooks"
    if not hooks_dir.exists():
        hooks_dir.mkdir(parents=True, exist_ok=True)
    if not hooks_dir.exists():
        raise RuntimeError(f"No .git/hooks directory in {repo_root}")

    hook_path = hooks_dir / hook_name
    # In hardened mode the hook must run the root/_deadpush-owned interpreter
    # (and its immutable deadpush package), NOT the user's interpreter — a
    # same-UID agent can edit a user-writable package to no-op the guardrails,
    # which would defeat even a root-immutable hook file. The hardened venv
    # interpreter and package are owned by _deadpush and not user-writable.
    from .config import hardened_python
    python_exe = str(hardened_python()) if system else sys.executable
    script = _get_hook_script(hook_name, python_exe)

    # Remove immutable flag if set (needed for overwrite/update). Clear at the
    # requested privilege level so a previously root-immutable hook can be rewritten.
    _make_mutable(hook_path, system=system)

    hook_path.write_text(script, encoding="utf-8")
    try:
        hook_path.chmod(0o755)
    except Exception:
        pass

    _save_hook_checksum(repo_root, hook_name, script)

    # Set immutable flag — the hook file can no longer be renamed, deleted,
    # or overwritten without an explicit `_make_mutable` call.
    made = _make_immutable(hook_path, system=system)
    if system and not made:
        # Root-immutable couldn't be set (no cached sudo / unsupported fs). Fall
        # back to user-immutable so the hook is still deletion-protected, and make
        # the downgrade loud so the operator can fix privileges and re-run.
        made = _make_immutable(hook_path, system=False)
        if made:
            print(f"  ⚠ Could not set ROOT-immutable (schg) flag on {hook_path}; "
                  f"fell back to user-immutable. Re-run `deadpush protect` with sudo "
                  f"available to lock it against a same-UID agent.")
    if not made:
        print(f"  ⚠ Could not set immutable flag on {hook_path} "
              f"(OS/fs may not support it; hook is still checksum-protected)")

    if os.name == "nt":
        cmd_shim = hooks_dir / f"{hook_name}.cmd"
        shim_content = f'''@echo off
"{python_exe}" "{hook_path}" %*
'''
        cmd_shim.write_text(shim_content, encoding="utf-8")

    print(f"Installed {hook_name} guardrail hook at {hook_path}")


def install_precommit_hook(repo_root: Path, *, system: bool = False) -> None:
    """
    Install a pre-commit git hook that runs guardrails on staged files.

    Blocks commits containing:
    - Prompt injection / AI override attempts
    - Hardcoded secrets (API keys, tokens, passwords)
    - Security violations (eval, exec, subprocess)
    - Architecture layer violations

    Uses a Python script for cross-platform support.
    ``system=True`` (hardened mode) locks the hook root-immutable (schg/sudo).
    """
    _write_hook_file(repo_root, "pre-commit", system=system)


def install_postcommit_hook(repo_root: Path, *, system: bool = False) -> None:
    """
    Install a post-commit git hook that reverts commits containing
    guardrail violations (catches --no-verify bypasses).

    Runs guardrails on every file in the last commit. If violations are
    found, the commit is undone via `git reset --soft HEAD~1` so the
    changes remain staged but uncommitted.
    ``system=True`` (hardened mode) locks the hook root-immutable (schg/sudo).
    """
    _write_hook_file(repo_root, "post-commit", system=system)


def run_postcommit_guardrails(repo_root: Path) -> tuple[bool, list[dict[str, Any]]]:
    """Run guardrails on files in the last commit. Reverts if violations found."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            capture_output=True, text=True, check=False, timeout=10,
            cwd=repo_root,
        )
        if result.returncode != 0:
            return True, []
        files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return True, []

    violations = _enforce_git_paths(repo_root, files, git_ref="HEAD")

    if violations:
        _print_violations(
            f"deadpush — Post-commit guardrails found {len(violations)} violation(s) in last commit:",
            violations,
            "",
        )
        try:
            subprocess.run(
                ["git", "reset", "--soft", "HEAD~1"],
                capture_output=True, text=True, check=True, timeout=10,
                cwd=repo_root,
            )
            print("Commit reverted (git reset --soft HEAD~1). Changes are still staged.")
        except Exception as e:
            print(f"Failed to revert commit: {e}")
        return False, violations

    return True, []


# All-zeros object id git uses on the "other" side of a create/delete ref update.
_ZERO_SHA = "0000000000000000000000000000000000000000"
# Git's canonical empty tree. Diffing a commit against it yields every file in
# that commit's tree, which is what we want when a new ref shares no history with
# anything already on the remote (e.g. the very first push).
_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _git_name_only(repo_root: Path, *args: str) -> list[str]:
    """`git diff --name-only <args>` -> list of paths (empty list on any error)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", *args],
            capture_output=True, text=True, check=False, timeout=15,
            cwd=repo_root,
        )
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def _prepush_changed_paths(repo_root: Path, local_sha: str, remote_sha: str) -> list[str]:
    """Resolve the files a single pre-push ref update introduces.

    - Update to an existing branch: diff ``remote_sha..local_sha``. ``remote_sha``
      comes from git's own push negotiation with the real remote (delivered on the
      hook's stdin), so it is a trustworthy boundary.
    - New branch/ref (remote all-zeros): scan the ENTIRE pushed tree
      (``empty-tree..local_sha``).

    Why the whole tree for a new ref: git offers no trustworthy boundary
    (``remote_sha`` is all-zeros), and we must NOT derive one from local
    remote-tracking refs (``refs/remotes/*``). Those are writable by a same-UID
    agent, so a forged ``refs/remotes/x/y`` pointing at the payload commit would
    make git treat the dangerous content as "already on the remote" and shrink the
    scanned diff to exclude it — while ``git push`` still ships those commits. A
    whole-tree scan cannot be poisoned this way. (Costs a full-tree scan on the
    first push of a branch; subsequent updates use the cheap ``remote_sha`` range.)
    """
    if remote_sha != _ZERO_SHA:
        return _git_name_only(repo_root, f"{remote_sha}..{local_sha}")
    return _git_name_only(repo_root, _EMPTY_TREE_SHA, local_sha)


def run_prepush_guardrails(repo_root: Path) -> tuple[bool, list[dict[str, Any]]]:
    """Run guardrails on commits being pushed.

    Reads the pre-push hook stdin to determine the commit range,
    then runs unified enforcement on all files in those commits.
    """
    import sys

    violations: list[dict[str, Any]] = []
    lines = sys.stdin.read().strip().splitlines()
    if not lines:
        return True, []

    seen: set[tuple[str, str]] = set()
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        local_sha, remote_sha = parts[1], parts[3]
        # Deleting a remote ref pushes an all-zeros local sha: nothing to scan.
        if local_sha == _ZERO_SHA:
            continue

        changed = _prepush_changed_paths(repo_root, local_sha, remote_sha)

        for rel_path in changed:
            key = (local_sha, rel_path)
            if key in seen:
                continue
            seen.add(key)
            file_violations = _enforce_git_paths(repo_root, [rel_path], git_ref=local_sha)
            violations.extend(file_violations)

    if violations:
        _print_violations(
            f"deadpush — Pre-push guardrails found {len(violations)} violation(s) in outgoing commits:",
            violations,
            "Use 'git push --no-verify' to bypass (not recommended).",
        )
        return False, violations

    return True, []


# =============================================================================
# Shared scan engine — used by `deadpush scan` (CI / GitHub Actions) and the
# server-side pre-receive hook. Both are enforcement layers that run OFF the
# agent's machine, so `--no-verify`, git plumbing, or killing the local daemon
# cannot bypass them. They reuse the exact same kernel as the local hooks.
# =============================================================================

def scan_range(repo_root: Path, base_sha: str, head_sha: str) -> list[dict[str, Any]]:
    """Block-level violations for the files a `base_sha..head_sha` range introduces.

    A zero/empty ``base_sha`` (or the empty-tree sha) means "no trustworthy
    boundary" (e.g. a brand-new branch), so the entire pushed tree at ``head_sha``
    is scanned — the same poison-proof behaviour as the D4 pre-push fix.
    """
    changed = scan_range_paths(repo_root, base_sha, head_sha)
    return _enforce_git_paths(repo_root, changed, git_ref=head_sha)


def scan_tree(repo_root: Path, ref: str = "HEAD") -> list[dict[str, Any]]:
    """Block-level violations for every enforceable file in ``ref``'s tree."""
    changed = _git_name_only(repo_root, _EMPTY_TREE_SHA, ref)
    return _enforce_git_paths(repo_root, changed, git_ref=ref)


def run_prereceive_guardrails(repo_root: Path) -> tuple[bool, list[dict[str, Any]]]:
    """Server-side enforcement, called by a git ``pre-receive`` hook.

    Reads pre-receive stdin (``<old-value> SP <new-value> SP <ref-name>`` per ref)
    — note this differs from pre-push's stdin format and ordering — and rejects the
    whole push if any incoming commit carries block-level violations.

    ``old-value`` is the server's current tip for the ref (a trustworthy boundary
    the pushing client cannot forge, unlike local ``refs/remotes/*``), so we diff
    ``old..new``. A new ref has an all-zeros ``old-value`` and is whole-tree scanned.
    At pre-receive time the incoming objects are already in the repo's quarantine
    and reachable by sha, so ``git show <new>:<path>`` works in the bare repo.
    """
    import sys

    violations: list[dict[str, Any]] = []
    lines = sys.stdin.read().strip().splitlines()
    if not lines:
        return True, []

    seen: set[tuple[str, str]] = set()
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        old_sha, new_sha = parts[0], parts[1]
        # Deleting a ref pushes an all-zeros new-value: nothing to scan.
        if new_sha == _ZERO_SHA:
            continue

        for rel_path in scan_range_paths(repo_root, old_sha, new_sha):
            key = (new_sha, rel_path)
            if key in seen:
                continue
            seen.add(key)
            violations.extend(_enforce_git_paths(repo_root, [rel_path], git_ref=new_sha))

    if violations:
        _print_violations(
            f"deadpush — Pre-receive guardrails REJECTED this push: {len(violations)} violation(s) in incoming commits:",
            violations,
            "The push was rejected by the server. Remove the flagged content and push again.",
        )
        return False, violations

    return True, []


def scan_range_paths(repo_root: Path, base_sha: str, head_sha: str) -> list[str]:
    """The enforceable paths a `base_sha..head_sha` range introduces (no scanning)."""
    base = (base_sha or "").strip()
    if not base or base == _ZERO_SHA:
        base = _ZERO_SHA
    return _prepush_changed_paths(repo_root, head_sha, base)


def _hookspath_value(repo_root: Path) -> str | None:
    """Return the effective `core.hooksPath` git setting, or None if unset."""
    try:
        r = subprocess.run(
            ["git", "config", "--get", "core.hooksPath"],
            capture_output=True, text=True, timeout=5, cwd=repo_root,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip() or None
    except Exception:
        return None


def detect_hookspath_hijack(repo_root: Path) -> str | None:
    """Detect a `core.hooksPath` that redirects git away from `.git/hooks`.

    deadpush installs its hooks into `.git/hooks`. Setting `core.hooksPath` to
    anything else (a classic bypass is `git config core.hooksPath /dev/null`)
    silently disables every deadpush hook without touching the hook files, so the
    checksum/immutability checks below would still report "OK". This catches that.

    Returns the offending value if the hooks dir is hijacked, else None.
    """
    val = _hookspath_value(repo_root)
    if not val:
        return None
    default_hooks = repo_root / ".git" / "hooks"
    try:
        configured = Path(val)
        if not configured.is_absolute():
            configured = repo_root / configured
        if configured.resolve() == default_hooks.resolve():
            return None  # explicitly set to the real hooks dir — not a hijack
    except Exception:
        pass
    return val


def restore_hookspath(repo_root: Path) -> bool:
    """Undo a `core.hooksPath` hijack so the `.git/hooks` deadpush hooks run again.

    Removes any repo-local override first; if a global/system hijack still shadows
    the default, pins the repo-local `core.hooksPath` back to the real hooks dir
    (repo-local wins over global). Only touches repo-local config — never global.
    """
    changed = False
    try:
        subprocess.run(
            ["git", "config", "--local", "--unset-all", "core.hooksPath"],
            capture_output=True, text=True, timeout=5, cwd=repo_root,
        )
        changed = True
    except Exception:
        pass
    # A global/system hijack survives the local unset; override it locally.
    if detect_hookspath_hijack(repo_root):
        try:
            default_hooks = (repo_root / ".git" / "hooks").resolve()
            subprocess.run(
                ["git", "config", "--local", "core.hooksPath", str(default_hooks)],
                capture_output=True, text=True, timeout=5, cwd=repo_root,
            )
            changed = True
        except Exception:
            pass
    return changed and detect_hookspath_hijack(repo_root) is None


def _hook_checksum_matches(repo_root: Path, hook_name: str, hook_path: Path) -> bool:
    """Return True when on-disk hook content matches the saved checksum."""
    checksum_file = repo_root / ".deadpush" / "hooks" / f"{hook_name}.sha256"
    if not checksum_file.exists() or not hook_path.is_file():
        return False
    try:
        expected = checksum_file.read_text(encoding="utf-8").strip()
        actual = hashlib.sha256(hook_path.read_text(encoding="utf-8").encode()).hexdigest()
        return actual == expected
    except Exception:
        return False


def verify_hooks_installed(repo_root: Path) -> list[str]:
    """Return hook names that are missing, checksum-mismatched, or not immutable."""
    from .config import is_hardened_install

    problems: list[str] = []
    hijack = detect_hookspath_hijack(repo_root)
    if hijack:
        problems.append(f"core.hooksPath (hijacked -> {hijack})")
    hooks_dir = repo_root / ".git" / "hooks"
    hardened = is_hardened_install(repo_root)
    for name in ("pre-push", "pre-commit", "post-commit"):
        hook_path = hooks_dir / name
        if not hook_path.exists():
            problems.append(f"{name} (missing)")
            continue
        checksum_file = repo_root / ".deadpush" / "hooks" / f"{name}.sha256"
        if checksum_file.exists():
            try:
                expected = checksum_file.read_text(encoding="utf-8").strip()
                actual = hashlib.sha256(hook_path.read_text(encoding="utf-8").encode()).hexdigest()
                if actual != expected:
                    problems.append(f"{name} (tampered)")
            except Exception:
                problems.append(f"{name} (checksum unreadable)")
        if not _is_immutable(hook_path):
            # macOS only: immutability is required in hardened mode. In soft mode a
            # checksum-valid hook is acceptable — re-installing in a loop when
            # chflags uchg fails (or was cleared by `deadpush stop`) wastes CPU and
            # spams logs without improving security.
            if sys.platform == "darwin" and hardened:
                problems.append(f"{name} (not immutable)")
            elif sys.platform == "darwin" and not _hook_checksum_matches(repo_root, name, hook_path):
                problems.append(f"{name} (not immutable)")
    return problems


def relock_deadpush_hooks(repo_root: Path, *, system: bool | None = None) -> list[str]:
    """Re-apply immutable flags without rewriting hook scripts."""
    from .config import is_hardened_install

    if system is None:
        system = is_hardened_install(repo_root)
    hooks_dir = repo_root / ".git" / "hooks"
    relocked: list[str] = []
    for name in ("pre-push", "pre-commit", "post-commit"):
        hook_path = hooks_dir / name
        if hook_path.exists() and not _is_immutable(hook_path):
            if _make_immutable(hook_path, system=system):
                relocked.append(name)
    return relocked


def uninstall_deadpush_hooks(repo_root: Path, *, system: bool = False) -> list[str]:
    """Remove deadpush-installed hooks (checksum-verified). Returns removed hook names.

    ``system=True`` clears root-immutable (schg) locks via sudo. Even when called
    without it, a lingering schg lock triggers a sudo escalation retry so hardened
    hooks can still be removed rather than silently blocking uninstall.
    """
    removed: list[str] = []
    hooks_dir = repo_root / ".git" / "hooks"
    checksums_dir = repo_root / ".deadpush" / "hooks"
    for name in ("pre-push", "pre-commit", "post-commit"):
        hook_path = hooks_dir / name
        checksum_file = checksums_dir / f"{name}.sha256"
        if not hook_path.exists():
            continue
        if checksum_file.exists():
            try:
                expected = checksum_file.read_text(encoding="utf-8").strip()
                actual = hashlib.sha256(hook_path.read_text(encoding="utf-8").encode()).hexdigest()
                if actual != expected:
                    continue  # don't remove user-owned hooks
            except Exception:
                continue
        elif "deadpush" not in hook_path.read_text(encoding="utf-8", errors="ignore"):
            continue
        _make_mutable(hook_path, system=system)
        try:
            hook_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # Still locked — likely root-immutable (schg). Escalate to sudo and retry.
            _make_mutable(hook_path, system=True)
            try:
                hook_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                continue  # sudo unavailable; leave the hook rather than crash
        checksum_file.unlink(missing_ok=True)
        cmd_shim = hooks_dir / f"{name}.cmd"
        cmd_shim.unlink(missing_ok=True)
        removed.append(name)
    if checksums_dir.exists() and not any(checksums_dir.iterdir()):
        checksums_dir.rmdir()
    return removed


def repair_deadpush_hooks(repo_root: Path, *, system: bool | None = None) -> list[str]:
    """Re-install deadpush hooks that are missing or tampered. Returns repaired names.

    ``system`` controls the lock level of the re-installed hooks. When left as
    ``None`` it is auto-detected from whether this is a hardened install, so the
    guardian's own auto-repair re-locks hardened hooks root-immutable (schg) and
    re-pins the hardened interpreter instead of silently downgrading them to
    user-immutable (uchg) + the user interpreter.
    """
    from .config import is_hardened_install
    if system is None:
        system = is_hardened_install(repo_root)
    problems = verify_hooks_installed(repo_root)
    if not problems:
        return []
    repaired: list[str] = []
    # A hijacked core.hooksPath disables every hook, so undo it first.
    if any(p.startswith("core.hooksPath") for p in problems) and restore_hookspath(repo_root):
        repaired.append("core.hooksPath")
    for name in ("pre-push", "pre-commit", "post-commit"):
        hook_problems = [p for p in problems if p.startswith(name)]
        if not hook_problems:
            continue
        needs_reinstall = any(
            "(not immutable)" not in p for p in hook_problems
        )
        if needs_reinstall:
            if name == "pre-push":
                install_hook(repo_root, system=system)
            elif name == "pre-commit":
                install_precommit_hook(repo_root, system=system)
            elif name == "post-commit":
                install_postcommit_hook(repo_root, system=system)
            repaired.append(name)
        elif any("(not immutable)" in p for p in hook_problems):
            hook_path = repo_root / ".git" / "hooks" / name
            if hook_path.exists() and _make_immutable(hook_path, system=system):
                repaired.append(name)
    return repaired


def setup_mcp_discovery(repo_root: Path) -> None:
    deadpush_cmd = str(Path(sys.executable).parent / "deadpush")
    if not Path(deadpush_cmd).exists():
        deadpush_cmd = sys.executable.replace("python3", "deadpush").replace("python", "deadpush")
    if not Path(deadpush_cmd).exists():
        deadpush_cmd = "deadpush"

    mcp_config = {
        "mcpServers": {
            "deadpush": {
                "command": deadpush_cmd,
                "args": ["mcp"],
            }
        }
    }

    cursor_dir = repo_root / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    cursor_path = cursor_dir / "mcp.json"
    existing = {}
    if cursor_path.exists():
        try:
            existing = json.loads(cursor_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing.update(mcp_config)
    cursor_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    print(f"  Created {cursor_path}")

    vscode_dir = repo_root / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    vscode_path = vscode_dir / "mcp.json"
    vscode_config = {"servers": {"deadpush": {"command": deadpush_cmd, "args": ["mcp"]}}}
    existing_vs = {}
    if vscode_path.exists():
        try:
            existing_vs = json.loads(vscode_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing_vs.update(vscode_config)
    vscode_path.write_text(json.dumps(existing_vs, indent=2), encoding="utf-8")
    print(f"  Created {vscode_path}")


def setup_github_guard_action(repo_root: Path) -> Path | None:
    """Write the GitHub Actions workflow file for server-side push protection.

    The workflow runs on every push: it installs deadpush, checks outgoing
    commits for guardrail violations, and force-pushes a revert if violations
    are found.

    The file must be committed to the repo for the action to take effect.
    Returns the path to the written file, or None on failure.
    """
    workflows_dir = repo_root / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    guard_path = workflows_dir / "deadpush-guard.yml"

    content = """name: deadpush Guard
on: push

permissions:
  contents: write

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install deadpush
        run: pip install deadpush

      - name: Check pushed commits
        id: guard
        continue-on-error: true
        run: |
          BEFORE="${{ github.event.before }}"
          AFTER="${{ github.event.after }}"
          # Handle first push to a new branch (before == 0000)
          if [ "$BEFORE" = "0000000000000000000000000000000000000000" ]; then
            # Scan all commits in the branch
            echo "refs/heads/${{ github.ref_name }} $AFTER refs/heads/${{ github.ref_name }} 0000000000000000000000000000000000000000" \\
              | deadpush hooks run-prepush
          else
            echo "refs/heads/${{ github.ref_name }} $AFTER refs/heads/${{ github.ref_name }} $BEFORE" \\
              | deadpush hooks run-prepush
          fi

      - name: Revert on violation
        if: steps.guard.outcome == 'failure'
        run: |
          git config user.name "deadpush Guard"
          git config user.email "guard@deadpush.dev"
          # Force-push with lease: only revert if the ref hasn't changed since our push
          git push --force-with-lease="${{ github.ref_name }}:${{ github.event.after }}" \\
            origin ${{ github.event.before }}:${{ github.ref_name }}
          echo "Reverted push — found guardrail violations in outgoing commits."
"""
    try:
        guard_path.write_text(content, encoding="utf-8")
        print(f"  Created {guard_path} (commit this file to enable server-side push protection)")
        return guard_path
    except Exception as e:
        print(f"  ⚠ Could not write guard action: {e}")
        return None
