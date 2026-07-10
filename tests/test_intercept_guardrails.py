"""Tests for the intercept guardrail checkers and pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

import json


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.intercept import (
    Violation,
    GuardrailResult,
    _run_guardrails,
    enforce_content,
    FEEDBACK_DIR,
    QUARANTINE_DIR,
    _write_feedback,
)
from deadpush.config import Config


# ======================================================================
# Violation & GuardrailResult
# ======================================================================

class TestViolation:
    def test_defaults(self):
        v = Violation("test", "desc")
        assert v.category == "test"
        assert v.description == "desc"
        assert v.line == 0
        assert v.severity == "medium"

    def test_to_dict(self):
        v = Violation("sec", "bad eval", 42, "high")
        d = v.to_dict()
        assert d["category"] == "sec"
        assert d["description"] == "bad eval"
        assert d["line"] == 42
        assert d["severity"] == "high"


class TestGuardrailResult:
    def test_default_allowed(self):
        r = GuardrailResult()
        assert r.allowed is True
        assert r.violations == []

    def test_reject(self):
        r = GuardrailResult()
        v = Violation("sec", "bad")
        r.reject(v)
        assert r.allowed is False
        assert len(r.violations) == 1

    def test_to_dict(self):
        r = GuardrailResult()
        r.reject(Violation("sec", "bad", 1))
        d = r.to_dict()
        assert d["allowed"] is False
        assert len(d["violations"]) == 1


# ======================================================================
# _run_guardrails pipeline
# ======================================================================

class TestRunGuardrails:
    def test_clean_file_allowed(self, temp_dir):
        f = temp_dir / "hello.py"
        f.write_text("x = 1\n")
        config = Config(repo_root=temp_dir)
        result = _run_guardrails(f, temp_dir, config)
        assert result.allowed is True

    def test_unreadable_file_blocked(self, temp_dir):
        f = temp_dir / "test.py"
        f.write_text("")
        config = Config(repo_root=temp_dir)
        result = _run_guardrails(f, temp_dir, config)
        assert result.allowed is True


class TestEnforceContent:
    def test_blocked_file_case_insensitive(self, temp_dir):
        config = Config(repo_root=temp_dir)
        result = enforce_content("CLAUDE.md", "# instructions\n", config)
        assert result.allowed is False
        assert any(v.category == "blocked_file" for v in result.violations)

    def test_llm_context_filename_blocked(self, temp_dir):
        config = Config(repo_root=temp_dir)
        result = enforce_content("agents.md", "# agent rules\n", config)
        assert result.allowed is False


# ======================================================================
# Feedback writer
# ======================================================================

class TestWriteFeedback:
    def test_writes_json_and_md(self, temp_dir):
        feedback_dir = temp_dir / FEEDBACK_DIR
        result = GuardrailResult()
        result.reject(Violation("sec", "bad eval", 1, "high"))
        _write_feedback(feedback_dir, "src/bad.py", result)

        safe_name = "src__bad.py"
        json_path = feedback_dir / f"{safe_name}.json"
        md_path = feedback_dir / f"{safe_name}.md"

        assert json_path.exists()
        assert md_path.exists()

        data = json.loads(json_path.read_text())
        assert data["file"] == "src/bad.py"
        assert data["status"] == "blocked"
        assert len(data["violations"]) == 1

    def test_approved_feedback(self, temp_dir):
        feedback_dir = temp_dir / FEEDBACK_DIR
        result = GuardrailResult()
        _write_feedback(feedback_dir, "ok.py", result)

        safe_name = "ok.py"
        json_path = feedback_dir / f"{safe_name}.json"
        data = json.loads(json_path.read_text())
        assert data["status"] == "approved"


# ======================================================================
# InterceptDaemon — integration smoke test
# ======================================================================

class TestInterceptDaemon:
    def test_write_file_clean(self, temp_repo):
        from deadpush.intercept import InterceptDaemon
        config = Config(repo_root=temp_repo)
        d = InterceptDaemon(str(temp_repo), config)
        result = d.write_file("src/hello.py", "x = 1\n")
        assert result.allowed is True
        assert (temp_repo / "src" / "hello.py").exists()

    def test_write_file_blocked(self, temp_repo):
        from deadpush.intercept import InterceptDaemon
        config = Config(repo_root=temp_repo)
        d = InterceptDaemon(str(temp_repo), config)
        result = d.write_file("CLAUDE.md", "# agent override\n")
        assert result.allowed is False
        # File was quarantined — should not exist at project root
        assert not (temp_repo / "CLAUDE.md").exists()
        # Should be in quarantine
        qdir = temp_repo / QUARANTINE_DIR
        assert qdir.exists()
        assert any(qdir.iterdir())



