"""Tests for the install marker and fail-closed git hook behavior.

Production requirement: once a repo is protected, its git hooks must refuse
to run (fail closed) if the deadpush interpreter later goes missing, rather
than silently allowing the operation.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.config import (
    install_marker_path,
    read_install_marker,
    remove_install_marker,
    write_install_marker,
)
from deadpush.hooks import _get_hook_script


class TestInstallMarker:
    def test_write_and_read_marker(self, temp_repo: Path):
        assert read_install_marker(temp_repo) is None
        marker = write_install_marker(temp_repo, hardened=False)
        assert marker == install_marker_path(temp_repo)
        assert marker.exists()
        data = read_install_marker(temp_repo)
        assert data is not None
        assert data["python"] == sys.executable
        assert data["mode"] == "default"

    def test_marker_is_gitignored(self, temp_repo: Path):
        write_install_marker(temp_repo, hardened=False)
        gitignore = (temp_repo / ".gitignore").read_text(encoding="utf-8")
        assert ".deadpush/installed" in gitignore

    def test_gitignore_entry_not_duplicated(self, temp_repo: Path):
        write_install_marker(temp_repo, hardened=False)
        write_install_marker(temp_repo, hardened=True)
        gitignore = (temp_repo / ".gitignore").read_text(encoding="utf-8")
        assert gitignore.count(".deadpush/installed") == 1

    def test_remove_marker(self, temp_repo: Path):
        write_install_marker(temp_repo, hardened=False)
        remove_install_marker(temp_repo)
        assert read_install_marker(temp_repo) is None

    def test_unreadable_marker_still_counts_as_protected(self, temp_repo: Path):
        marker = install_marker_path(temp_repo)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("not-json{{{", encoding="utf-8")
        # Present-but-corrupt marker must still be treated as "protected".
        assert read_install_marker(temp_repo) == {}


class TestGeneratedHookScripts:
    @pytest.mark.parametrize("hook", ["pre-push", "pre-commit", "post-commit"])
    def test_scripts_are_valid_python(self, hook: str):
        script = _get_hook_script(hook, sys.executable)
        ast.parse(script)  # raises on syntax error

    @pytest.mark.parametrize("hook", ["pre-push", "pre-commit"])
    def test_blocking_hooks_fail_closed_helper_present(self, hook: str):
        script = _get_hook_script(hook, sys.executable)
        assert "_deadpush_handle_missing" in script
        assert "DEADPUSH_STRICT" in script


def _run_hook_script(script: str, cwd: Path, env: dict) -> subprocess.CompletedProcess:
    hook_file = cwd / "_hook_under_test.py"
    hook_file.write_text(script, encoding="utf-8")
    try:
        return subprocess.run(
            [sys.executable, str(hook_file)],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            input="",
            env=env,
            timeout=30,
        )
    finally:
        hook_file.unlink(missing_ok=True)


class TestFailClosedRuntime:
    """Exercise the generated hook with a deliberately broken interpreter path."""

    def _script_with_broken_interpreter(self, hook: str) -> str:
        # A path that cannot exist -> subprocess.run raises FileNotFoundError,
        # which is exactly the "deadpush interpreter went missing" case.
        return _get_hook_script(hook, "/nonexistent/deadpush/python-DOES-NOT-EXIST")

    def test_prepush_fails_open_when_repo_unprotected(self, temp_repo: Path):
        script = self._script_with_broken_interpreter("pre-push")
        env = {k: v for k, v in os.environ.items() if k != "DEADPUSH_STRICT"}
        result = _run_hook_script(script, temp_repo, env)
        assert result.returncode == 0
        assert "skipping hook" in result.stdout.lower()

    def test_prepush_fails_closed_when_repo_protected(self, temp_repo: Path):
        write_install_marker(temp_repo, hardened=False)
        script = self._script_with_broken_interpreter("pre-push")
        env = {k: v for k, v in os.environ.items() if k != "DEADPUSH_STRICT"}
        result = _run_hook_script(script, temp_repo, env)
        assert result.returncode == 1
        assert "fail-closed" in result.stdout.lower()

    def test_prepush_fails_closed_under_strict_env(self, temp_repo: Path):
        # No marker, but DEADPUSH_STRICT forces fail-closed everywhere.
        script = self._script_with_broken_interpreter("pre-push")
        env = dict(os.environ)
        env["DEADPUSH_STRICT"] = "1"
        result = _run_hook_script(script, temp_repo, env)
        assert result.returncode == 1

    def test_precommit_fails_closed_when_repo_protected(self, temp_repo: Path):
        write_install_marker(temp_repo, hardened=False)
        script = self._script_with_broken_interpreter("pre-commit")
        env = {k: v for k, v in os.environ.items() if k != "DEADPUSH_STRICT"}
        result = _run_hook_script(script, temp_repo, env)
        assert result.returncode == 1
