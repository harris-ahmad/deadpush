"""Regression tests for pre-push scanning of *new* branches.

Before the fix, a first push of a brand-new branch used the local sha as the
whole `git diff` spec, which made git compare the working tree against that sha.
On a clean tree that yields no files, so pushing a new branch bypassed content
enforcement completely. These tests drive `run_prepush_guardrails` with the exact
stdin git feeds a pre-push hook and assert the new commits are actually scanned.
"""

from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.hooks import run_prepush_guardrails

_ZERO = "0000000000000000000000000000000000000000"
_DANGEROUS = "import subprocess\nsubprocess.run('ls', shell=True)\n"
_CLEAN = "def add(a, b):\n    return a + b\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=repo, check=False
    ).stdout.strip()


def _commit(repo: Path, name: str, content: str) -> str:
    (repo / name).write_text(content)
    _git(repo, "add", name)
    # --no-verify: we exercise run_prepush_guardrails directly, not the hooks.
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "--no-verify", "-m", f"add {name}")
    return _git(repo, "rev-parse", "HEAD")


def _feed_stdin(monkeypatch, local_ref: str, local_sha: str, remote_sha: str) -> None:
    line = f"{local_ref} {local_sha} {local_ref} {remote_sha}\n"
    monkeypatch.setattr(sys, "stdin", io.StringIO(line))


class TestNewBranchPrePush:
    def test_new_branch_push_blocks_dangerous_file(self, temp_repo: Path, monkeypatch):
        """The core gap: a dangerous file introduced on a brand-new branch must
        be caught on first push (remote sha is all-zeros)."""
        _git(temp_repo, "checkout", "-b", "feature")
        local_sha = _commit(temp_repo, "danger.py", _DANGEROUS)

        _feed_stdin(monkeypatch, "refs/heads/feature", local_sha, _ZERO)
        passed, violations = run_prepush_guardrails(temp_repo)

        assert passed is False, "new-branch push with a dangerous file must be blocked"
        assert any(v["file"] == "danger.py" for v in violations)

    def test_new_branch_push_allows_clean_file(self, temp_repo: Path, monkeypatch):
        _git(temp_repo, "checkout", "-b", "feature")
        local_sha = _commit(temp_repo, "safe.py", _CLEAN)

        _feed_stdin(monkeypatch, "refs/heads/feature", local_sha, _ZERO)
        passed, violations = run_prepush_guardrails(temp_repo)

        assert passed is True
        assert violations == []

    def test_new_branch_push_cannot_be_poisoned_by_fake_remote_ref(self, temp_repo: Path, monkeypatch):
        """D4: a forged refs/remotes/* must not shrink the scanned range.

        History: main -> [feature] C_danger (adds danger.py) -> C_tip (adds safe2.py).
        An agent forges refs/remotes/origin/feature = C_danger to claim the payload
        is 'already on the remote'. Under the old `--not --remotes` base computation
        the scanned diff became C_danger..C_tip and skipped danger.py entirely; the
        whole-tree scan must still catch it.
        """
        _git(temp_repo, "checkout", "-b", "feature")
        danger_sha = _commit(temp_repo, "danger.py", _DANGEROUS)
        tip_sha = _commit(temp_repo, "safe2.py", _CLEAN)

        # Forge a remote-tracking ref pointing at the payload commit.
        _git(temp_repo, "update-ref", "refs/remotes/origin/feature", danger_sha)
        # Sanity: the forgery really does make the old base logic skip danger.py.
        skipped = subprocess.run(
            ["git", "diff", "--name-only", f"{danger_sha}..{tip_sha}"],
            capture_output=True, text=True, cwd=temp_repo, check=False,
        ).stdout.split()
        assert "danger.py" not in skipped

        _feed_stdin(monkeypatch, "refs/heads/feature", tip_sha, _ZERO)
        passed, violations = run_prepush_guardrails(temp_repo)

        assert passed is False, "forged remote-tracking ref must not bypass the scan"
        assert any(v["file"] == "danger.py" for v in violations)

    def test_existing_branch_update_still_blocks(self, temp_repo: Path, monkeypatch):
        """The remote_sha..local_sha path must keep working unchanged."""
        base_sha = _git(temp_repo, "rev-parse", "HEAD")
        local_sha = _commit(temp_repo, "danger.py", _DANGEROUS)

        _feed_stdin(monkeypatch, "refs/heads/main", local_sha, base_sha)
        passed, violations = run_prepush_guardrails(temp_repo)

        assert passed is False
        assert any(v["file"] == "danger.py" for v in violations)

    def test_branch_deletion_is_skipped(self, temp_repo: Path, monkeypatch):
        """Deleting a remote ref sends an all-zeros local sha; nothing to scan."""
        remote_sha = _git(temp_repo, "rev-parse", "HEAD")
        _feed_stdin(monkeypatch, "(delete)", _ZERO, remote_sha)
        passed, violations = run_prepush_guardrails(temp_repo)

        assert passed is True
        assert violations == []

    def test_empty_stdin_passes(self, temp_repo: Path, monkeypatch):
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))
        passed, violations = run_prepush_guardrails(temp_repo)
        assert passed is True
        assert violations == []
