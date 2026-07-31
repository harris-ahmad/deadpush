"""Tests for staged git intercept (thesis Phase 3)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from deadpush.git_wrapper import main
from deadpush.savepoints import SavePointStore
from deadpush.staged_git import classify_destructive_git


def test_classify_reset_hard():
    hit = classify_destructive_git(["reset", "--hard", "HEAD~1"])
    assert hit is not None
    assert hit.kind == "reset_hard"
    assert hit.label == "pre-reset-hard"


def test_classify_reset_soft_allowed():
    assert classify_destructive_git(["reset", "--soft", "HEAD~1"]) is None
    assert classify_destructive_git(["reset", "HEAD~1"]) is None


def test_classify_force_push_variants():
    for args in (
        ["push", "--force"],
        ["push", "-f", "origin", "main"],
        ["push", "--force-with-lease"],
        ["push", "--force-with-lease=refs/heads/main"],
        ["push", "--force-if-includes", "origin", "HEAD"],
    ):
        hit = classify_destructive_git(args)
        assert hit is not None, args
        assert hit.kind == "force_push"
        assert hit.label == "pre-force-push"


def test_classify_plain_push_allowed():
    assert classify_destructive_git(["push", "origin", "main"]) is None
    assert classify_destructive_git(["push"]) is None


def test_classify_skips_globals():
    hit = classify_destructive_git(["-C", "/tmp/repo", "-c", "user.name=x", "reset", "--hard"])
    assert hit is not None
    assert hit.kind == "reset_hard"

    hit = classify_destructive_git(["--git-dir=.git", "push", "--force"])
    assert hit is not None
    assert hit.kind == "force_push"


def test_wrapper_denies_reset_hard_and_creates_savepoint(temp_repo: Path, monkeypatch):
    tracked = temp_repo / "work.txt"
    tracked.write_text("precious\n", encoding="utf-8")
    subprocess.run(["git", "add", "work.txt"], cwd=temp_repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "work"],
        cwd=temp_repo,
        check=True,
        capture_output=True,
    )
    head_before = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=temp_repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.delenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", raising=False)
    monkeypatch.chdir(temp_repo)

    code = main(["reset", "--hard", "HEAD~1"])
    assert code == 1

    head_after = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=temp_repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == head_before
    assert tracked.read_text(encoding="utf-8") == "precious\n"

    points = SavePointStore(temp_repo).list()
    assert points
    assert any(p.label == "pre-reset-hard" for p in points)


def test_wrapper_denies_force_push_and_creates_savepoint(temp_repo: Path, monkeypatch):
    (temp_repo / "f.txt").write_text("x\n", encoding="utf-8")
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.delenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", raising=False)
    monkeypatch.chdir(temp_repo)

    code = main(["push", "--force", "origin", "HEAD"])
    assert code == 1

    points = SavePointStore(temp_repo).list()
    assert any(p.label == "pre-force-push" for p in points)


def test_wrapper_escape_hatch_allows_reset_soft_path(temp_repo: Path, monkeypatch):
    """With allow env set, destructive classifier is skipped (status still works)."""
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.setenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", "1")
    monkeypatch.chdir(temp_repo)
    code = main(["status", "--porcelain"])
    assert code == 0
    assert SavePointStore(temp_repo).list() == []
