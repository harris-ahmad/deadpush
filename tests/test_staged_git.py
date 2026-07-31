"""Tests for staged git intercept (thesis Phase 3)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from deadpush.git_wrapper import main
from deadpush.savepoints import SavePointStore
from deadpush.staged_git import classify_destructive_git


def _chdir(path: Path) -> None:
    # Avoid monkeypatch.chdir: prior tests can leave cwd on a deleted tmpdir,
    # which makes monkeypatch.chdir's os.getcwd() raise FileNotFoundError.
    try:
        Path.cwd()
    except FileNotFoundError:
        os.chdir(Path(__file__).resolve().parents[1])
    os.chdir(path)


def _restore_cwd() -> None:
    """Leave temp repos so later tests are not stuck on a deleted cwd."""
    os.chdir(Path(__file__).resolve().parents[1])


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


def test_classify_bare_exec_path_does_not_swallow_subcommand():
    # Regression: bare --exec-path must not consume the next token as a value.
    hit = classify_destructive_git(["--exec-path", "-C", "/tmp/repo", "push", "--force"])
    assert hit is not None
    assert hit.kind == "force_push"

    hit = classify_destructive_git(["--exec-path=/usr/lib/git-core", "reset", "--hard"])
    assert hit is not None
    assert hit.kind == "reset_hard"


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
    monkeypatch.setenv("DEADPUSH_SANDBOX", "1")
    monkeypatch.delenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", raising=False)
    _chdir(temp_repo)

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
    _restore_cwd()


def test_wrapper_denies_force_push_and_creates_savepoint(temp_repo: Path, monkeypatch):
    (temp_repo / "f.txt").write_text("x\n", encoding="utf-8")
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.setenv("DEADPUSH_SANDBOX", "1")
    monkeypatch.delenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", raising=False)
    _chdir(temp_repo)

    code = main(["push", "--force", "origin", "HEAD"])
    assert code == 1

    points = SavePointStore(temp_repo).list()
    assert any(p.label == "pre-force-push" for p in points)
    _restore_cwd()


def test_wrapper_allows_destructive_outside_sandbox(temp_repo: Path, monkeypatch):
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.delenv("DEADPUSH_SANDBOX", raising=False)
    monkeypatch.delenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", raising=False)
    _chdir(temp_repo)
    code = main(["reset", "--hard", "HEAD"])
    assert code == 0
    assert SavePointStore(temp_repo).list() == []
    _restore_cwd()


def test_wrapper_escape_hatch_allows_destructive_in_sandbox(temp_repo: Path, monkeypatch):
    """DEADPUSH_ALLOW_DESTRUCTIVE_GIT=1 must skip staged deny for real destructive cmds."""
    monkeypatch.setenv("DEADPUSH_REPO_ROOT", str(temp_repo))
    monkeypatch.setenv("DEADPUSH_SANDBOX", "1")
    monkeypatch.setenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", "1")
    _chdir(temp_repo)
    code = main(["reset", "--hard", "HEAD"])
    assert code == 0
    assert SavePointStore(temp_repo).list() == []
    _restore_cwd()
