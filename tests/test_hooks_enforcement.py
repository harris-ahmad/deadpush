"""Tests for unified git hook enforcement."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.hooks import (
    run_precommit_guardrails,
    run_postcommit_guardrails,
    verify_hooks_installed,
    install_precommit_hook,
    install_postcommit_hook,
    install_hook,
)


class TestPrecommitEnforcement:
    def test_blocks_dangerous_staged_file(self, temp_repo: Path):
        (temp_repo / "debug.py").write_text(
            "import subprocess\nsubprocess.run('ls', shell=True)\n"
        )
        subprocess.run(["git", "add", "debug.py"], capture_output=True, cwd=temp_repo)
        passed, violations = run_precommit_guardrails(temp_repo)
        assert passed is False
        assert any(v["file"] == "debug.py" for v in violations)

    def test_blocks_claude_md_case_insensitive(self, temp_repo: Path):
        (temp_repo / "CLAUDE.md").write_text("# AI instructions\n")
        subprocess.run(["git", "add", "CLAUDE.md"], capture_output=True, cwd=temp_repo)
        passed, violations = run_precommit_guardrails(temp_repo)
        assert passed is False
        assert violations


class TestPostcommitEnforcement:
    def test_reverts_bad_commit(self, temp_repo: Path):
        install_postcommit_hook(temp_repo)
        (temp_repo / "debug.py").write_text(
            "import subprocess\nsubprocess.run('ls', shell=True)\n"
        )
        subprocess.run(["git", "add", "debug.py"], capture_output=True, cwd=temp_repo)
        # Bypass pre-commit and post-commit hooks so we can test run_postcommit_guardrails directly
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "bad", "--no-verify"],
            capture_output=True, cwd=temp_repo,
        )
        head_before = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=temp_repo,
        ).stdout.strip()
        passed, violations = run_postcommit_guardrails(temp_repo)
        assert passed is False
        head_after = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=temp_repo,
        ).stdout.strip()
        assert head_before != head_after


class TestHookVerification:
    def test_verify_all_hooks(self, temp_repo: Path):
        install_hook(temp_repo)
        install_precommit_hook(temp_repo)
        install_postcommit_hook(temp_repo)
        problems = verify_hooks_installed(temp_repo)
        assert problems == []
