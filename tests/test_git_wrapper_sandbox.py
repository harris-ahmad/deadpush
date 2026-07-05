"""Tests for git-wrapper sandbox escapes."""

from __future__ import annotations

from deadpush.git_wrapper import main


def test_git_wrapper_blocks_hookspath_in_sandbox(temp_repo, monkeypatch):
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.setenv("DEADPUSH_SANDBOX", "1")
    monkeypatch.chdir(temp_repo)
    code = main(["-c", "core.hooksPath=/tmp/evil", "status"])
    assert code == 1


def test_git_wrapper_allows_hookspath_outside_sandbox(temp_repo, monkeypatch):
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.delenv("DEADPUSH_SANDBOX", raising=False)
    monkeypatch.chdir(temp_repo)
    code = main(["status"])
    assert code == 0
