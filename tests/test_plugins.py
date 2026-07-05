"""Tests for guardrail plugin SDK."""

from __future__ import annotations

from pathlib import Path

from deadpush.intercept import Violation, enforce_content
from deadpush.config import load_config
from deadpush.plugins import CheckContext, register_plugin, run_plugins


class _NoEvalPlugin:
    name = "no_eval_test"
    category = "plugin_test"

    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        if "FORBIDDEN_PLUGIN_MARKER" in source:
            return [Violation("plugin_test", "plugin blocked this content", 1, "high")]
        return []


def test_run_plugins(temp_repo: Path):
    register_plugin(_NoEvalPlugin())
    config = load_config(explicit_root=temp_repo)
    found = run_plugins("x.py", "FORBIDDEN_PLUGIN_MARKER here", config, None)
    assert len(found) == 1
    assert found[0].category == "plugin_test"


def test_enforce_content_runs_plugins(temp_repo: Path):
    register_plugin(_NoEvalPlugin())
    config = load_config(explicit_root=temp_repo)
    result = enforce_content("x.py", "FORBIDDEN_PLUGIN_MARKER", config, None)
    assert not result.allowed
    assert any(v.category == "plugin_test" for v in result.violations)
