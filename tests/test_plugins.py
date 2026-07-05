"""Tests for guardrail plugin SDK."""

from __future__ import annotations

from pathlib import Path

import pytest

from deadpush.intercept import Violation, enforce_content
from deadpush.config import load_config
from deadpush.plugins import (
    BaseGuardrailPlugin,
    CheckContext,
    clear_plugins,
    register_plugin,
    run_plugin,
    run_plugins,
    validate_plugin,
)


class _NoEvalPlugin:
    name = "no_eval_test"
    category = "plugin_test"

    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        if "FORBIDDEN_PLUGIN_MARKER" in source:
            return [Violation("plugin_test", "plugin blocked this content", 1, "high")]
        return []


class _BrokenReturnPlugin:
    name = "broken"
    category = "plugin_test"

    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        return "not a list"  # type: ignore[return-value]


class _ConcretePlugin(BaseGuardrailPlugin):
    def __init__(self):
        super().__init__(name="concrete", category="plugin_test")

    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        if "CONCRETE_MARKER" in source:
            return [Violation("plugin_test", "concrete plugin hit", 1, "medium")]
        return []


@pytest.fixture(autouse=True)
def _reset_plugins():
    clear_plugins()
    yield
    clear_plugins()


def test_validate_plugin_rejects_invalid():
    class Bad:
        name = ""
        category = "x"

        def check(self, rel_path, source, ctx):
            return []

    assert validate_plugin(Bad()) is not None


def test_base_guardrail_plugin():
    p = _ConcretePlugin()
    assert p.name == "concrete"
    ctx = CheckContext(repo_root=Path("/tmp"), config=None, runtime=None)  # type: ignore[arg-type]
    assert p.check("a.py", "ok", ctx) == []


def test_run_plugins(temp_repo: Path):
    register_plugin(_NoEvalPlugin())
    config = load_config(explicit_root=temp_repo)
    found = run_plugins("x.py", "FORBIDDEN_PLUGIN_MARKER here", config, None)
    assert len(found) == 1
    assert found[0].category == "plugin_test"


def test_run_plugin_isolates_broken_return(temp_repo: Path):
    register_plugin(_BrokenReturnPlugin())
    config = load_config(explicit_root=temp_repo)
    ctx = CheckContext(repo_root=temp_repo, config=config, runtime=None)
    report = run_plugin(_BrokenReturnPlugin(), "x.py", "x", ctx)
    assert report.error is not None


def test_enforce_content_runs_plugins(temp_repo: Path):
    register_plugin(_NoEvalPlugin())
    config = load_config(explicit_root=temp_repo)
    result = enforce_content("x.py", "FORBIDDEN_PLUGIN_MARKER", config, None)
    assert not result.allowed
    assert any(v.category == "plugin_test" for v in result.violations)


def test_register_plugin_rejects_invalid():
    class Bad:
        name = "bad"
        category = ""

        def check(self, rel_path, source, ctx):
            return []

    with pytest.raises(ValueError):
        register_plugin(Bad())  # type: ignore[arg-type]
