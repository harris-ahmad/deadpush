"""Tests for out-of-band commit detection (git plumbing / --no-verify bypass).

The pre-commit/pre-push hooks only run for git *porcelain*, so `git commit-tree` +
`git update-ref` (what an adversarial agent used to slip a payload past the hooks)
advance HEAD with no hook firing. The guardian polls HEAD and independently
re-enforces every new commit: a commit that reaches HEAD with block-level violations
must have bypassed the hooks, so it is quarantined, penalized, and — for a clean
linear commit — undone via `git reset --soft` (non-destructive: changes stay staged).

These drive the handler methods directly against a real temp git repo, using the
exact write-tree/commit-tree/update-ref bypass.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.config import load_config  # noqa: E402
from deadpush.guard import GuardianHandler, QuarantineManager  # noqa: E402

_DANGEROUS = "# bad instructions\n"
_CLEAN = "def add(a, b):\n    return a + b\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=repo
    ).stdout.strip()


def _plumbing_commit(repo: Path, name: str, content: str, parent: str) -> str:
    """Create a commit that bypasses hooks entirely (write-tree/commit-tree/update-ref)."""
    (repo / name).write_text(content)
    _git(repo, "add", name)
    tree = _git(repo, "write-tree")
    commit = subprocess.run(
        ["git", "commit-tree", tree, "-p", parent, "-m", f"add {name}"],
        capture_output=True, text=True, cwd=repo,
    ).stdout.strip()
    _git(repo, "update-ref", "HEAD", commit)
    return commit


def _handler(repo: Path):
    """A real GuardianHandler instance with only the attributes these methods touch
    (skips the heavy __init__ so tests stay fast and isolated)."""
    h = object.__new__(GuardianHandler)
    h.config = load_config(explicit_root=repo)
    h.logger = logging.getLogger("deadpush.test")
    h.intervention = True
    h.quarantine = QuarantineManager(repo)
    h.safety_score = types.SimpleNamespace(report_incident=lambda *a, **k: 42)
    incidents: list[dict] = []
    h.session_mgr = types.SimpleNamespace(
        record_incident=incidents.append, update_safety_score=lambda s: None
    )
    h._last_head = None
    h._scanned_commits = set()
    h.hardened = False
    h.gpc = None
    return h, incidents


class TestOutOfBandCommit:
    def test_dangerous_plumbing_commit_is_reverted_and_quarantined(self, temp_repo: Path):
        parent = _git(temp_repo, "rev-parse", "HEAD")
        sha = _plumbing_commit(temp_repo, "CLAUDE.md", _DANGEROUS, parent)
        assert _git(temp_repo, "rev-parse", "HEAD") == sha  # the bypass landed

        h, incidents = _handler(temp_repo)
        h._last_head = parent  # guardian had last seen the clean parent
        h._check_head_commit()

        # Commit undone (HEAD back at parent), payload out of the tree and quarantined.
        assert _git(temp_repo, "rev-parse", "HEAD") == parent
        assert not (temp_repo / "CLAUDE.md").exists()
        quarantined = [
            p for p in h.quarantine.quarantine_dir.iterdir() if "CLAUDE" in p.name
        ]
        assert quarantined, "payload should be quarantined"
        assert incidents and incidents[0]["type"] == "out_of_band_commit"
        assert incidents[0]["reverted"] is True
        assert incidents[0]["files"] == ["CLAUDE.md"]

    def test_benign_plumbing_commit_is_left_untouched(self, temp_repo: Path):
        parent = _git(temp_repo, "rev-parse", "HEAD")
        sha = _plumbing_commit(temp_repo, "util.py", _CLEAN, parent)

        h, incidents = _handler(temp_repo)
        h._last_head = parent
        h._check_head_commit()

        assert _git(temp_repo, "rev-parse", "HEAD") == sha  # not reverted
        assert (temp_repo / "util.py").exists()
        assert incidents == []

    def test_first_observation_sets_baseline_without_acting(self, temp_repo: Path):
        parent = _git(temp_repo, "rev-parse", "HEAD")
        sha = _plumbing_commit(temp_repo, "config.py", _DANGEROUS, parent)

        h, incidents = _handler(temp_repo)
        assert h._last_head is None
        h._check_head_commit()  # first run: adopt baseline, never rescan pre-existing history

        assert h._last_head == sha
        assert _git(temp_repo, "rev-parse", "HEAD") == sha
        assert incidents == []

    def test_second_poll_is_a_noop_after_handling(self, temp_repo: Path):
        parent = _git(temp_repo, "rev-parse", "HEAD")
        _plumbing_commit(temp_repo, "config.py", _DANGEROUS, parent)

        h, incidents = _handler(temp_repo)
        h._last_head = parent
        h._check_head_commit()
        n = len(incidents)
        h._check_head_commit()  # HEAD is back at parent; nothing new to do
        assert len(incidents) == n


class TestLinearChild:
    def test_true_for_single_parent_on_top(self, temp_repo: Path):
        parent = _git(temp_repo, "rev-parse", "HEAD")
        sha = _plumbing_commit(temp_repo, "a.py", _CLEAN, parent)
        h, _ = _handler(temp_repo)
        assert h._is_linear_child(sha, parent) is True

    def test_false_when_prev_is_not_the_parent(self, temp_repo: Path):
        parent = _git(temp_repo, "rev-parse", "HEAD")
        sha = _plumbing_commit(temp_repo, "a.py", _CLEAN, parent)
        h, _ = _handler(temp_repo)
        assert h._is_linear_child(sha, sha) is False
