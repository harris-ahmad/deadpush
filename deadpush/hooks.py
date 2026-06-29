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

def _make_immutable(path: Path) -> bool:
    """Set the OS-level immutable flag on `path`.

    On macOS this uses `chflags uchg` — the file cannot be renamed, deleted,
    or overwritten until the flag is removed (via `_make_mutable`).

    On Linux this uses `chattr +i` (may require sudo/capability on some distros).

    Returns True if the flag was set, False if the OS/fs doesn't support it.
    On failure the caller should log a warning but treat it as non-fatal.
    """
    try:
        if sys.platform == "darwin":
            result = subprocess.run(
                ["chflags", "uchg", str(path)],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        elif sys.platform.startswith("linux"):
            result = subprocess.run(
                ["chattr", "+i", str(path)],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        return False
    except Exception:
        return False


def _make_mutable(path: Path) -> bool:
    """Remove the OS-level immutable flag from `path`.

    The reverse of `_make_immutable`. Must succeed before the file can be
    updated or overwritten.
    """
    try:
        if sys.platform == "darwin":
            subprocess.run(
                ["chflags", "nouchg", str(path)],
                capture_output=True, timeout=5,
            )
            return True
        elif sys.platform.startswith("linux"):
            subprocess.run(
                ["chattr", "-i", str(path)],
                capture_output=True, timeout=5,
            )
            return True
        return True
    except Exception:
        return False


def _is_immutable(path: Path) -> bool:
    """Check whether the OS-level immutable flag is set on `path`.

    Only supported on macOS. On other platforms returns False.
    """
    try:
        if sys.platform == "darwin":
            st = path.stat()
            return bool(st.st_flags & stat.UF_IMMUTABLE)
        return False
    except Exception:
        return False


# Core patterns merged into ignore files during setup
GUARDIAN_IGNORE_PATTERNS = {
    "claude.md", ".cursorrules", ".claude_instructions", ".copilot-instructions.md",
    "windsurf_rules.md", "agents.md", "llm_context.txt", "ai_prompt.md",
    ".deadpush-autoignore", ".deadpush-quarantine/", ".deadpush-archive/",
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
    from .intercept import enforce_content, violations_from_result, _ENFORCEABLE_EXTENSIONS
    from .rules import RuntimeConfig

    config = load_config(explicit_root=repo_root)
    runtime = RuntimeConfig(repo_root)
    violations: list[dict[str, Any]] = []

    for rel_path in paths:
        ext = Path(rel_path).suffix.lower()
        if ext not in _ENFORCEABLE_EXTENSIONS:
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
        staged = [l.strip() for l in result.stdout.splitlines() if l.strip()]
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


def install_hook(repo_root: Path) -> None:
    """
    Install a cross-platform pre-push git hook.

    The hook runs `deadpush hooks run-prepush` (via the current Python
    to avoid PATH/venv issues) and blocks the push if guardrail violations
    are found in outgoing commits.

    This version uses a Python script instead of Bash so it works on:
    - Windows (PowerShell, CMD, Git for Windows without Git Bash)
    - macOS / Linux
    - Any environment where Python can run the deadpush module.

    Idempotent.
    """
    _write_hook_file(repo_root, "pre-push")


def _get_hook_script(hook_name: str, python_exe: str) -> str:
    """Return the script content for a given hook name."""
    if hook_name == "pre-push":
        return f'''#!/usr/bin/env python3
"""
deadpush pre-push git hook (installed by deadpush protect).

Scans outgoing commits for guardrail violations and blocks the push
if dangerous code is found. Reads stdin for the commit range.
"""
import subprocess
import sys

def main():
    try:
        cmd = [r"{python_exe}", "-m", "deadpush.cli", "hooks", "run-prepush"]
        result = subprocess.run(cmd, capture_output=False, text=True, check=False)
        if result.returncode != 0:
            print("deadpush guardrails blocked this push.")
            print("Fix the violations above or use --no-verify (not recommended).")
            sys.exit(1)
    except FileNotFoundError:
        print("deadpush not available (Python module could not be found).")
        print("Skipping hook (install with pip install -e . in the deadpush source).")
        sys.exit(0)

if __name__ == "__main__":
    main()
'''
    elif hook_name == "pre-commit":
        return f'''#!/usr/bin/env python3
"""
deadpush pre-commit guardrails (installed by deadpush hook install-precommit).

Blocks commits with prompt injection, hardcoded secrets,
security violations, and architecture layer violations.
"""
import subprocess
import sys

def main():
    try:
        cmd = [r"{python_exe}", "-m", "deadpush.cli", "hooks", "run-precommit"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        if result.returncode != 0:
            print("deadpush guardrails blocked this commit.")
            sys.exit(1)
    except FileNotFoundError:
        print("deadpush not available (Python module could not be found).")
        sys.exit(0)

if __name__ == "__main__":
    main()
'''
    elif hook_name == "post-commit":
        return f'''#!/usr/bin/env python3
"""
deadpush post-commit guardrails (installed by deadpush protect).
Reverts commits containing dangerous code even if --no-verify was used.
"""
import subprocess
import sys

def main():
    try:
        cmd = [r"{python_exe}", "-m", "deadpush.cli", "hooks", "run-postcommit"]
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
        print("deadpush not available (Python module could not be found).")
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


def _write_hook_file(repo_root: Path, hook_name: str) -> None:
    """Write a git hook script to .git/hooks/{hook_name} and save its checksum.

    Used by both the CLI installer and the guardian's auto-restore.
    The file is made immutable (chflags uchg on macOS, chattr +i on Linux)
    to prevent the agent from silently moving or deleting it.
    """
    hooks_dir = repo_root / ".git" / "hooks"
    if not hooks_dir.exists():
        hooks_dir.mkdir(parents=True, exist_ok=True)
    if not hooks_dir.exists():
        raise RuntimeError(f"No .git/hooks directory in {repo_root}")

    hook_path = hooks_dir / hook_name
    python_exe = sys.executable
    script = _get_hook_script(hook_name, python_exe)

    # Remove immutable flag if set (needed for overwrite/update)
    _make_mutable(hook_path)

    hook_path.write_text(script, encoding="utf-8")
    try:
        hook_path.chmod(0o755)
    except Exception:
        pass

    _save_hook_checksum(repo_root, hook_name, script)

    # Set immutable flag — the hook file can no longer be renamed, deleted,
    # or overwritten without an explicit `_make_mutable` call.
    if not _make_immutable(hook_path):
        print(f"  ⚠ Could not set immutable flag on {hook_path} "
              f"(OS/fs may not support it; hook is still checksum-protected)")

    if os.name == "nt":
        cmd_shim = hooks_dir / f"{hook_name}.cmd"
        shim_content = f'''@echo off
"{python_exe}" "{hook_path}" %*
'''
        cmd_shim.write_text(shim_content, encoding="utf-8")

    print(f"Installed {hook_name} guardrail hook at {hook_path}")


def install_precommit_hook(repo_root: Path) -> None:
    """
    Install a pre-commit git hook that runs guardrails on staged files.

    Blocks commits containing:
    - Prompt injection / AI override attempts
    - Hardcoded secrets (API keys, tokens, passwords)
    - Security violations (eval, exec, subprocess)
    - Architecture layer violations

    Uses a Python script for cross-platform support.
    """
    _write_hook_file(repo_root, "pre-commit")


def install_postcommit_hook(repo_root: Path) -> None:
    """
    Install a post-commit git hook that reverts commits containing
    guardrail violations (catches --no-verify bypasses).

    Runs guardrails on every file in the last commit. If violations are
    found, the commit is undone via `git reset --soft HEAD~1` so the
    changes remain staged but uncommitted.
    """
    _write_hook_file(repo_root, "post-commit")


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
        files = [l.strip() for l in result.stdout.splitlines() if l.strip()]
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


def run_prepush_guardrails(repo_root: Path) -> tuple[bool, list[dict[str, Any]]]:
    """Run guardrails on commits being pushed.

    Reads the pre-push hook stdin to determine the commit range,
    then runs unified enforcement on all files in those commits.
    """
    import subprocess
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
        if remote_sha == "0000000000000000000000000000000000000000":
            range_spec = local_sha
        else:
            range_spec = f"{remote_sha}..{local_sha}"

        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", range_spec],
                capture_output=True, text=True, check=False, timeout=10,
                cwd=repo_root,
            )
            if result.returncode != 0:
                continue
            changed = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        except Exception:
            continue

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


def verify_hooks_installed(repo_root: Path) -> list[str]:
    """Return hook names that are missing, checksum-mismatched, or not immutable."""
    problems: list[str] = []
    hooks_dir = repo_root / ".git" / "hooks"
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
            # Only flag on macOS where we expect this to work; Linux might lack chattr access
            if sys.platform == "darwin":
                problems.append(f"{name} (not immutable)")
    return problems


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

    The workflow runs on every push: it installs deadpush, scans the outgoing
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
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install deadpush
        run: pip install deadpush

      - name: Scan pushed commits
        id: scan
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
        if: steps.scan.outcome == 'failure'
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
