"""Tests for the reference guardrail plugin package."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "packages" / "deadpush-guardrails-example"
if str(PKG) not in sys.path:
    sys.path.insert(0, str(PKG))

from deadpush.plugins import CheckContext, clear_plugins, register_plugin  # noqa: E402
from deadpush_guardrails_example.plugin import NoTodoInSrcPlugin  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_plugins():
    clear_plugins()
    yield
    clear_plugins()


def test_no_todo_in_src_blocks(temp_repo):
    from deadpush.config import load_config

    plugin = NoTodoInSrcPlugin()
    register_plugin(plugin)
    config = load_config(explicit_root=temp_repo)
    ctx = CheckContext(repo_root=temp_repo, config=config, runtime=None)
    hits = plugin.check("src/app.py", "# TODO: fix me\n", ctx)
    assert len(hits) == 1
    assert hits[0].category == "debris"


def test_no_todo_in_src_ignores_non_src(temp_repo):
    from deadpush.config import load_config

    plugin = NoTodoInSrcPlugin()
    config = load_config(explicit_root=temp_repo)
    ctx = CheckContext(repo_root=temp_repo, config=config, runtime=None)
    assert plugin.check("docs/readme.md", "# TODO\n", ctx) == []
