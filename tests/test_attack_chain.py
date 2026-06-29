"""Integration test simulating the AuthenticationSystem attack chain."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.config import Config
from deadpush.guard import GuardianHandler
from deadpush.hooks import run_postcommit_guardrails, run_precommit_guardrails
from deadpush.intercept import enforce_content


@pytest.fixture
def guardian(temp_repo: Path) -> GuardianHandler:
    config = Config(repo_root=temp_repo)
    handler = GuardianHandler(config, intervention=True, daemon=False)
    handler.safety_score.score = 50
    return handler


class TestAttackChain:
    """Simulates: native write bypass → guardian → git race."""

    def test_mcp_kernel_blocks_claude_md(self, temp_repo: Path):
        config = Config(repo_root=temp_repo)
        result = enforce_content("CLAUDE.md", "# agent rules\n", config)
        assert not result.allowed

    def test_mcp_kernel_blocks_debug_py(self, temp_repo: Path):
        config = Config(repo_root=temp_repo)
        bad = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        result = enforce_content("debug.py", bad, config)
        assert not result.allowed

    def test_native_write_quarantined(self, guardian: GuardianHandler, temp_repo: Path):
        """Agent writes debug.py directly (bypassing MCP)."""
        target = temp_repo / "debug.py"
        target.write_text("import subprocess\nsubprocess.run('ls', shell=True)\n")
        guardian._process_event(target, "modified")
        assert not target.exists() or target.read_text() == "x = 1\n"
        assert guardian.quarantine.quarantine_dir.exists()

    def test_precommit_blocks_staged_violation(self, temp_repo: Path):
        (temp_repo / "debug.py").write_text(
            "import subprocess\nsubprocess.run('ls', shell=True)\n"
        )
        subprocess.run(["git", "add", "debug.py"], capture_output=True, cwd=temp_repo)
        passed, violations = run_precommit_guardrails(temp_repo)
        assert passed is False
        assert violations

    def test_postcommit_reverts_no_verify_commit(self, temp_repo: Path):
        (temp_repo / "debug.py").write_text(
            "import subprocess\nsubprocess.run('ls', shell=True)\n"
        )
        subprocess.run(["git", "add", "debug.py"], capture_output=True, cwd=temp_repo)
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "bad", "--no-verify"],
            capture_output=True, cwd=temp_repo,
        )
        head_before = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=temp_repo,
        ).stdout.strip()
        passed, _ = run_postcommit_guardrails(temp_repo)
        head_after = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=temp_repo,
        ).stdout.strip()
        assert passed is False
        assert head_before != head_after

    def test_unstage_after_quarantine(self, guardian: GuardianHandler, temp_repo: Path):
        target = temp_repo / "agents.md"
        target.write_text("# agent context\n")
        subprocess.run(["git", "add", "agents.md"], capture_output=True, cwd=temp_repo)
        from deadpush.intercept import GuardrailResult, Violation

        result = GuardrailResult()
        result.reject(Violation("blocked_file", "blocked", 0, "critical"))
        guardian._quarantine_and_restore(target, "agents.md", result)
        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True, cwd=temp_repo,
        ).stdout
        assert "agents.md" not in staged

    def test_no_restore_when_head_also_bad(self, guardian: GuardianHandler, temp_repo: Path):
        bad = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        (temp_repo / "debug.py").write_text(bad)
        subprocess.run(["git", "add", "debug.py"], capture_output=True, cwd=temp_repo)
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "bad head"],
            capture_output=True, cwd=temp_repo,
        )
        (temp_repo / "debug.py").write_text("eval('worse')\n")
        from deadpush.intercept import GuardrailResult, Violation

        result = GuardrailResult()
        result.reject(Violation("security", "eval", 1, "high"))
        guardian._quarantine_and_restore(temp_repo / "debug.py", "debug.py", result)
        assert not (temp_repo / "debug.py").exists()
