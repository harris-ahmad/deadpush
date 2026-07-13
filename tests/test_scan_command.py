"""Tests for the shared scan engine and `deadpush scan` command.

`scan_range` / `scan_tree` back both server-side vehicles (the GitHub Actions check
and the pre-receive hook). They reuse the same enforcement kernel as the local
hooks, so a violating commit is caught off the agent's machine where `--no-verify`
and git plumbing cannot help.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.cli import main  # noqa: E402
from deadpush.hooks import scan_range, scan_tree, scan_range_paths, _ZERO_SHA  # noqa: E402

_DANGEROUS = "import subprocess\nsubprocess.run('ls', shell=True)\n"
_CLEAN = "def add(a, b):\n    return a + b\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=repo
    ).stdout.strip()


def _commit(repo: Path, name: str, content: str, *, force: bool = False) -> str:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(content)
    _git(repo, "add", *(["-f"] if force else []), name)
    _git(repo, "commit", "-m", f"add {name}")
    return _git(repo, "rev-parse", "HEAD")


class TestScanEngine:
    def test_scan_range_flags_dangerous_file(self, temp_repo: Path):
        base = _git(temp_repo, "rev-parse", "HEAD")
        head = _commit(temp_repo, "config.py", _DANGEROUS)
        violations = scan_range(temp_repo, base, head)
        assert violations, "dangerous file in the range should be flagged"
        assert any(v["file"] == "config.py" for v in violations)

    def test_scan_range_clean_for_benign(self, temp_repo: Path):
        base = _git(temp_repo, "rev-parse", "HEAD")
        head = _commit(temp_repo, "util.py", _CLEAN)
        assert scan_range(temp_repo, base, head) == []

    def test_scan_tree_flags_dangerous(self, temp_repo: Path):
        _commit(temp_repo, "config.py", _DANGEROUS)
        violations = scan_tree(temp_repo, "HEAD")
        assert any(v["file"] == "config.py" for v in violations)

    def test_scan_tree_excludes_deadpush_own_state(self, temp_repo: Path):
        # deadpush's own dir is gitignored; even force-committed, it must not be scanned
        # (its feedback records quote the very secrets it caught).
        _commit(temp_repo, ".deadpush/feedback/evil.py", _DANGEROUS, force=True)
        violations = scan_tree(temp_repo, "HEAD")
        assert not any(".deadpush" in v["file"] for v in violations)

    def test_zero_base_triggers_whole_tree_scan(self, temp_repo: Path):
        # A new branch (zero base) has no trustworthy boundary -> whole tree scanned.
        head = _commit(temp_repo, "config.py", _DANGEROUS)
        paths = scan_range_paths(temp_repo, _ZERO_SHA, head)
        assert "config.py" in paths
        assert "hello.py" in paths  # whole tree, not just the range


class TestScanCommand:
    def test_exit_nonzero_on_violation(self, temp_repo: Path):
        _commit(temp_repo, "config.py", _DANGEROUS)
        result = CliRunner().invoke(main, ["scan", "--all", "--repo", str(temp_repo)])
        assert result.exit_code == 1
        assert "violation" in result.output.lower()

    def test_exit_zero_when_clean(self, temp_repo: Path):
        _commit(temp_repo, "util.py", _CLEAN)
        result = CliRunner().invoke(main, ["scan", "--all", "--repo", str(temp_repo)])
        assert result.exit_code == 0
        assert "clean" in result.output.lower()

    def test_json_format(self, temp_repo: Path):
        _commit(temp_repo, "config.py", _DANGEROUS)
        result = CliRunner().invoke(
            main, ["scan", "--all", "--repo", str(temp_repo), "--format", "json"]
        )
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["clean"] is False
        assert payload["count"] >= 1
        assert any(v["file"] == "config.py" for v in payload["violations"])

    def test_range_scan_via_cli(self, temp_repo: Path):
        base = _git(temp_repo, "rev-parse", "HEAD")
        head = _commit(temp_repo, "config.py", _DANGEROUS)
        result = CliRunner().invoke(
            main, ["scan", "--base", base, "--head", head, "--repo", str(temp_repo)]
        )
        assert result.exit_code == 1
