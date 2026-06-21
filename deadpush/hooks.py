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

import json
import os
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


# Global registry instance
hooks = HookRegistry()

# Example usage in future:
# hooks.register("before_create_file", my_custom_check)
# hooks.trigger("before_create_file", filepath)


def run_precommit_guardrails(repo_root: Path) -> tuple[bool, list[dict[str, Any]]]:
    """Run guardrails on staged files. Returns (passed, violations)."""
    import subprocess
    from .intercept import (
        _check_prompt_injection,
        _check_hardcoded_secrets,
        _check_security,
        _check_debris_patterns,
        _check_layer_violations,
        _check_dependency_integrity,
    )
    from .config import load_config
    from .rules import RuntimeConfig

    config = load_config(explicit_root=repo_root)
    runtime = RuntimeConfig(repo_root)
    violations: list[dict[str, Any]] = []

    # Get staged files
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

    for rel_path in staged:
        # Only check text files we understand
        ext = Path(rel_path).suffix.lower()
        if ext not in (".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".go", ".java", ".rb", ".php", ".sh", ".bash", ".yaml", ".yml", ".json", ".toml", ".md"):
            continue

        # Get staged content
        try:
            content = subprocess.run(
                ["git", "show", f":{rel_path}"],
                capture_output=True, text=True, check=False, timeout=5,
                cwd=repo_root,
            )
            if content.returncode != 0:
                continue
            source = content.stdout
        except Exception:
            continue

        # Run guardrails
        for check_fn, category in [
            (_check_prompt_injection, "prompt_injection"),
            (_check_hardcoded_secrets, "secret"),
            (_check_security, "security"),
        ]:
            for v in check_fn(source, runtime):
                violations.append({
                    "file": rel_path,
                    "line": v.line,
                    "category": category,
                    "description": v.description,
                    "severity": v.severity,
                })

        for v in _check_debris_patterns(source, ext, runtime):
            violations.append({
                "file": rel_path,
                "line": v.line,
                "category": "debris",
                "description": v.description,
                "severity": v.severity,
            })

        try:
            for v in _check_layer_violations(source, rel_path, config, runtime):
                violations.append({
                    "file": rel_path,
                    "line": v.line,
                    "category": "layer",
                    "description": v.description,
                    "severity": v.severity,
                })
        except Exception:
            pass

        try:
            for v in _check_dependency_integrity(source, rel_path, repo_root, runtime):
                violations.append({
                    "file": rel_path,
                    "line": v.line,
                    "category": "dependency",
                    "description": v.description,
                    "severity": v.severity,
                })
        except Exception:
            pass

    if violations:
        print(f"\ndeadpush — Pre-commit guardrails found {len(violations)} violation(s):\n")
        for v in violations:
            icon = {"critical": "🔴", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(v["severity"], "⚡")
            print(f"  {icon} {v['file']}:{v['line']}  [{v['category']}] {v['description'][:100]}")
        print("")
        print("Commit blocked. Fix the violations above or use `git commit --no-verify` to skip.")
        return False, violations

    return True, []


def install_hook(repo_root: Path) -> None:
    """
    Install a cross-platform pre-push git hook.

    The hook runs `deadpush scan --format summary` (via the current Python
    to avoid PATH/venv issues) and blocks the push if blocking debris or
    dead symbols are found.

    This version uses a Python script instead of Bash so it works on:
    - Windows (PowerShell, CMD, Git for Windows without Git Bash)
    - macOS / Linux
    - Any environment where Python can run the deadpush module.

    Idempotent.
    """
    hooks_dir = repo_root / ".git" / "hooks"
    if not hooks_dir.exists():
        # Not a git repo or hooks dir missing
        raise RuntimeError(f"No .git/hooks directory in {repo_root}")

    hook_path = hooks_dir / "pre-push"

    # Capture the exact Python at install time. This is crucial for venvs on
    # Windows (PowerShell/CMD) where the "deadpush" entrypoint may not be in
    # PATH for the shell that Git uses to invoke hooks.
    python_exe = sys.executable

    # Cross-platform Python hook.
    # We hardcode the python we were installed with + -m deadpush.cli.
    script = f'''#!/usr/bin/env python3
"""
deadpush pre-push git hook (installed by deadpush protect).

Cross-platform (Windows PowerShell/CMD + Git for Windows, macOS, Linux).
Runs the scan via the Python that was used to run "deadpush protect".
"""
import subprocess
import sys

def main():
    try:
        # Hardcoded at install time for maximum reliability across shells
        cmd = [r"{python_exe}", "-m", "deadpush.cli", "scan", "--format", "summary"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        output = (result.stdout or "") + (result.stderr or "")
        print(output)

        # Block if we see debris or dead symbols (unless the count is explicitly 0)
        has_debris = "debris" in output and "0 debris" not in output
        has_dead = "dead symbols" in output and "0 dead symbols" not in output

        if has_debris or has_dead:
            print("deadpush check found blocking issues.")
            print("Run 'deadpush scan' for details. Use --force to override (not recommended).")
            sys.exit(1)

    except FileNotFoundError:
        print("deadpush not available (Python module could not be found).")
        print("Skipping hook (install with pip install -e . in the deadpush source).")
        sys.exit(0)  # Do not block the push on hook setup problems
    except Exception as e:
        print(f"deadpush hook encountered an error: {{e}}")
        sys.exit(0)  # Never block the push because the hook itself is broken

if __name__ == "__main__":
    main()
'''

    hook_path.write_text(script, encoding="utf-8")

    # Make it executable on Unix-like systems (harmless on Windows)
    try:
        hook_path.chmod(0o755)
    except Exception:
        pass

    print(f"Installed cross-platform pre-push hook at {hook_path}")
    print("  (Works in PowerShell, CMD, Git Bash, macOS, Linux, etc. — uses the exact Python from when you ran 'deadpush protect')")

    # On Windows, also install a tiny .cmd shim.
    # Git for Windows will often execute .cmd hooks preferentially when
    # the user is in PowerShell or CMD, avoiding any shebang/execution issues.
    if os.name == "nt":
        cmd_shim = hooks_dir / "pre-push.cmd"
        # Use the exact python that was used to install deadpush (works great with venvs)
        shim_content = f'''@echo off
"{python_exe}" "{hook_path}" %*
'''
        cmd_shim.write_text(shim_content, encoding="utf-8")
        print(f"  Also installed Windows shim at {cmd_shim}")


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
    hooks_dir = repo_root / ".git" / "hooks"
    if not hooks_dir.exists():
        raise RuntimeError(f"No .git/hooks directory in {repo_root}")

    hook_path = hooks_dir / "pre-commit"
    python_exe = sys.executable

    script = f'''#!/usr/bin/env python3
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

    hook_path.write_text(script, encoding="utf-8")
    try:
        hook_path.chmod(0o755)
    except Exception:
        pass

    print(f"Installed pre-commit guardrail hook at {hook_path}")

    if os.name == "nt":
        cmd_shim = hooks_dir / "pre-commit.cmd"
        shim_content = f'''@echo off
"{python_exe}" "{hook_path}" %*
'''
        cmd_shim.write_text(shim_content, encoding="utf-8")
        print(f"  Also installed Windows shim at {cmd_shim}")


def setup_mcp_discovery(repo_root: Path) -> None:
    """Create MCP config files so agents discover deadpush automatically.

    Creates .cursor/mcp.json and .vscode/mcp.json so Cursor, VS Code,
    and other MCP-compatible agents discover deadpush automatically.
    """
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
