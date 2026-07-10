"""Tests for guardian closed-loop hardening (quarantine, git restore, unstaging)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.config import Config
from deadpush.guard import GuardianHandler, QuarantineManager


@pytest.fixture
def guardian(temp_repo: Path) -> GuardianHandler:
    config = Config(repo_root=temp_repo)
    handler = GuardianHandler(config, intervention=True, daemon=False)
    handler.safety_score.score = 50  # avoid lockdown unless test sets score=0
    return handler


class TestSafeGitSource:
    def test_returns_safe_head_content(self, guardian: GuardianHandler, temp_repo: Path):
        assert guardian._safe_git_source("hello.py") == "x = 1\n"

    def test_refuses_head_that_violates_guardrails(self, guardian: GuardianHandler, temp_repo: Path):
        (temp_repo / "CLAUDE.md").write_text("# bad instructions\n")
        subprocess.run(["git", "add", "CLAUDE.md"], capture_output=True, cwd=temp_repo)
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "bad head"],
            capture_output=True, cwd=temp_repo,
        )
        assert guardian._safe_git_source("CLAUDE.md") is None

    def test_missing_file_returns_none(self, guardian: GuardianHandler):
        assert guardian._safe_git_source("nonexistent.py") is None


class TestUnstageIfStaged:
    def test_unstages_staged_file(self, guardian: GuardianHandler, temp_repo: Path):
        (temp_repo / "staged.py").write_text("x = 1\n")
        subprocess.run(["git", "add", "staged.py"], capture_output=True, cwd=temp_repo)
        guardian._unstage_if_staged("staged.py")
        status = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True, cwd=temp_repo,
        )
        assert "staged.py" not in status.stdout


class TestQuarantineAndRestore:
    def test_quarantine_removes_bad_file_and_restores_safe_git(self, guardian: GuardianHandler, temp_repo: Path):
        from deadpush.intercept import GuardrailResult, Violation

        target = temp_repo / "hello.py"
        target.write_text("eval('bad')\n")
        result = GuardrailResult()
        result.reject(Violation("security", "eval", 1, "high"))

        guardian._quarantine_and_restore(target, "hello.py", result)

        assert target.read_text() == "x = 1\n"
        assert guardian.quarantine.quarantine_dir.exists()
        assert any("hello.py" in f.name for f in guardian.quarantine.quarantine_dir.iterdir())

    def test_no_restore_when_head_also_bad(self, guardian: GuardianHandler, temp_repo: Path):
        from deadpush.intercept import GuardrailResult, Violation

        (temp_repo / "CLAUDE.md").write_text("# bad instructions\n")
        subprocess.run(["git", "add", "CLAUDE.md"], capture_output=True, cwd=temp_repo)
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "bad"],
            capture_output=True, cwd=temp_repo,
        )
        (temp_repo / "CLAUDE.md").write_text("# worse instructions\n")

        result = GuardrailResult()
        result.reject(Violation("blocked_file", "CLAUDE.md is blocked", 0, "critical"))
        guardian._quarantine_and_restore(temp_repo / "CLAUDE.md", "CLAUDE.md", result)

        assert not (temp_repo / "CLAUDE.md").exists()


class TestBlockingDebrisIntervention:
    def test_quarantines_llm_context_file(self, guardian: GuardianHandler, temp_repo: Path):
        from deadpush.types import DebrisFile

        path = temp_repo / "CLAUDE.md"
        path.write_text("# agent instructions\n")
        debris = DebrisFile(
            path="CLAUDE.md",
            category="llm_context_file",
            confidence=0.99,
            reasons=["Known LLM context file"],
            block_push=True,
        )
        guardian._intervene_blocking_debris(path, [debris], "created")

        assert not path.exists()
        qm = QuarantineManager(temp_repo)
        assert any("CLAUDE" in e["name"] for e in qm.list_quarantined())


class TestLockdown:
    def test_score_zero_quarantines_any_write(self, guardian: GuardianHandler, temp_repo: Path):
        guardian.safety_score.score = 0
        safe = temp_repo / "notes.txt"
        safe.write_text("benign notes\n")

        guardian._process_event(safe, "modified")

        assert not safe.exists()
        assert any("notes.txt" in f.name for f in guardian.quarantine.quarantine_dir.iterdir())
