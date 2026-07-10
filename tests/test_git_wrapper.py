"""Tests for deadpush git-wrapper."""

from __future__ import annotations

import subprocess
from pathlib import Path

from deadpush.git_wrapper import find_real_git, main


def test_find_real_git():
    git = find_real_git()
    assert git
    assert Path(git).exists() or git == "git"


def test_git_wrapper_version(temp_repo: Path, monkeypatch):
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.chdir(temp_repo)
    code = main(["--version"])
    assert code == 0


def test_git_wrapper_blocks_bad_commit(temp_repo: Path, monkeypatch):
    bad = temp_repo / "CLAUDE.md"
    bad.write_text("# bad\n")
    subprocess.run(["git", "add", "CLAUDE.md"], cwd=temp_repo, capture_output=True)
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.chdir(temp_repo)
    code = main(["commit", "-m", "bad"])
    assert code != 0
