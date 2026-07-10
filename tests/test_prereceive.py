"""Tests for the server-side pre-receive enforcement.

`run_prereceive_guardrails` parses git's pre-receive stdin (`<old> <new> <ref>` per
ref — a different order/semantics than pre-push) and rejects the whole push if any
incoming commit carries block-level violations. New refs (zero `old`) are whole-tree
scanned so the boundary cannot be poisoned; deletions (zero `new`) are skipped.
"""

from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.hooks import run_prereceive_guardrails, _ZERO_SHA  # noqa: E402

_DANGEROUS = "# bad instructions\n"
_CLEAN = "def add(a, b):\n    return a + b\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=repo
    ).stdout.strip()


def _commit(repo: Path, name: str, content: str) -> str:
    (repo / name).write_text(content)
    _git(repo, "add", name)
    _git(repo, "commit", "-m", f"add {name}")
    return _git(repo, "rev-parse", "HEAD")


def _feed(monkeypatch, text: str) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


class TestPreReceive:
    def test_rejects_dangerous_update(self, temp_repo: Path, monkeypatch):
        old = _git(temp_repo, "rev-parse", "HEAD")
        new = _commit(temp_repo, "CLAUDE.md", _DANGEROUS)
        _feed(monkeypatch, f"{old} {new} refs/heads/main\n")
        passed, violations = run_prereceive_guardrails(temp_repo)
        assert passed is False
        assert any(v["file"] == "CLAUDE.md" for v in violations)

    def test_allows_benign_update(self, temp_repo: Path, monkeypatch):
        old = _git(temp_repo, "rev-parse", "HEAD")
        new = _commit(temp_repo, "util.py", _CLEAN)
        _feed(monkeypatch, f"{old} {new} refs/heads/main\n")
        passed, violations = run_prereceive_guardrails(temp_repo)
        assert passed is True
        assert violations == []

    def test_skips_branch_deletion(self, temp_repo: Path, monkeypatch):
        old = _git(temp_repo, "rev-parse", "HEAD")
        _feed(monkeypatch, f"{old} {_ZERO_SHA} refs/heads/gone\n")
        passed, violations = run_prereceive_guardrails(temp_repo)
        assert passed is True
        assert violations == []

    def test_new_branch_whole_tree_scan(self, temp_repo: Path, monkeypatch):
        # A brand-new ref (zero old) must scan the ENTIRE pushed tree, so a payload
        # committed before the branch point is still caught.
        new = _commit(temp_repo, "CLAUDE.md", _DANGEROUS)
        _feed(monkeypatch, f"{_ZERO_SHA} {new} refs/heads/newbranch\n")
        passed, violations = run_prereceive_guardrails(temp_repo)
        assert passed is False
        assert any(v["file"] == "CLAUDE.md" for v in violations)

    def test_empty_stdin_passes(self, temp_repo: Path, monkeypatch):
        _feed(monkeypatch, "")
        passed, violations = run_prereceive_guardrails(temp_repo)
        assert passed is True
        assert violations == []
