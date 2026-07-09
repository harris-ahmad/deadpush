"""Tests for v1 OS hardening: per-repo state and hook repair."""

from __future__ import annotations

from pathlib import Path


from deadpush.guard import (
    _repo_id,
    _scoped_log_file,
    _scoped_safety_score_file,
)
from deadpush.hooks import install_precommit_hook, repair_deadpush_hooks, uninstall_deadpush_hooks, verify_hooks_installed


def test_scoped_state_paths_are_per_repo(temp_repo: Path):
    rid = _repo_id(str(temp_repo))
    soft_score = _scoped_safety_score_file(temp_repo, hardened=False)
    soft_log = _scoped_log_file(temp_repo, hardened=False)
    assert soft_score.parent.name == rid
    assert soft_log.parent.name == rid
    assert soft_score.name == "safety_score.json"
    assert soft_log.name == "guardian.log"
    other = temp_repo.parent / "other"
    assert soft_score != _scoped_safety_score_file(other, hardened=False)


def test_repair_deadpush_hooks(temp_repo: Path):
    from deadpush.hooks import _make_mutable

    install_precommit_hook(temp_repo)
    hook = temp_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    _make_mutable(hook)
    hook.write_text("# tampered\n", encoding="utf-8")
    problems = verify_hooks_installed(temp_repo)
    assert any("pre-commit" in p for p in problems)
    repaired = repair_deadpush_hooks(temp_repo)
    assert "pre-commit" in repaired
    assert verify_hooks_installed(temp_repo) == []


def test_uninstall_deadpush_hooks(temp_repo: Path):
    install_precommit_hook(temp_repo)
    removed = uninstall_deadpush_hooks(temp_repo)
    assert "pre-commit" in removed
    assert not (temp_repo / ".git" / "hooks" / "pre-commit").exists()
