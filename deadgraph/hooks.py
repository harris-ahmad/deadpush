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
    Install a simple pre-push git hook that runs `deadpush scan --format summary`
    and blocks the push on blocking debris or high-severity dead code.
    Idempotent.
    """
    hooks_dir = repo_root / ".git" / "hooks"
    if not hooks_dir.exists():
        # Not a git repo or hooks dir missing
        raise RuntimeError(f"No .git/hooks directory in {repo_root}")

    hook_path = hooks_dir / "pre-push"
    script = '''#!/usr/bin/env bash
# deadpush pre-push hook (installed by deadpush protect)
set -e
echo "→ Running deadpush pre-push check..."
if command -v deadpush >/dev/null 2>&1; then
    deadpush scan --format summary || {
        echo "deadpush check failed or found blocking issues."
        echo "Run 'deadpush scan' for details. Use --force to override (not recommended)."
        exit 1
    }
else
    echo "deadpush not on PATH; skipping (install with pip install deadpush)"
fi
'''

    hook_path.write_text(script)
    hook_path.chmod(0o755)
    print(f"Installed pre-push hook at {hook_path}")
