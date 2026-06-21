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

import os
import sys
from pathlib import Path
from typing import Callable, Any


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
