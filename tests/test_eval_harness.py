"""Tests for thesis eval harness (Phase 4)."""

from __future__ import annotations

import os
from pathlib import Path

from deadpush.eval.baselines import ALL_BASELINES
from deadpush.eval.runner import run_eval_matrix, run_one, write_csv, write_summary_md
from deadpush.eval.scenarios import SCENARIOS


def test_destructive_git_b4_preserves_more_than_b0():
    b0 = run_one("destructive_git", ALL_BASELINES["B0"])
    b4 = run_one("destructive_git", ALL_BASELINES["B4"])
    assert b0.lasting_damage is True
    assert b4.blocked is True
    assert b4.lasting_damage is False
    assert b4.work_preserved >= b0.work_preserved


def test_secret_write_b3_and_b4_block():
    b0 = run_one("secret_write", ALL_BASELINES["B0"])
    b3 = run_one("secret_write", ALL_BASELINES["B3"])
    b4 = run_one("secret_write", ALL_BASELINES["B4"])
    assert b0.lasting_damage is True
    assert b3.blocked is True
    assert b4.blocked is True


def test_force_push_only_b4_policy_blocks():
    b0 = run_one("force_push", ALL_BASELINES["B0"])
    b4 = run_one("force_push", ALL_BASELINES["B4"])
    assert b0.blocked is False
    assert b4.blocked is True


def test_force_push_b4_os_credited_when_available():
    from deadpush.eval.baselines import B4OS
    from deadpush.eval.os_sandbox import os_confinement_status

    if not os_confinement_status(Path.cwd()).get("available"):
        import pytest

        pytest.skip("no OS confinement")
    b4os = run_one("force_push", B4OS())
    assert b4os.blocked is True


def test_matrix_subset_writes_csv(tmp_path: Path):
    results = run_eval_matrix(
        scenarios=["destructive_git", "benign_commit"],
        baselines=["B0", "B4"],
    )
    assert len(results) == 4
    csv_path = write_csv(results, tmp_path / "results.csv")
    md_path = write_summary_md(results, tmp_path / "summary.md")
    assert csv_path.is_file()
    assert "baseline" in csv_path.read_text(encoding="utf-8")
    assert md_path.is_file()
    assert "B4" in md_path.read_text(encoding="utf-8")


def test_all_scenario_ids_registered():
    expected = {
        "secret_write",
        "scratch_pollution",
        "destructive_git",
        "force_push",
        "hook_wipe",
        "mass_edit",
        "benign_commit",
        "outside_repo_write",
    }
    assert expected <= set(SCENARIOS)


def test_unknown_baseline_raises_helpful_keyerror():
    import pytest

    with pytest.raises(KeyError, match="unknown baseline"):
        run_eval_matrix(scenarios=["benign_commit"], baselines=["B99"])


def test_b2_run_git_restores_allow_destructive_env(temp_repo: Path, monkeypatch):
    monkeypatch.setenv("DEADPUSH_ALLOW_DESTRUCTIVE_GIT", "1")
    b2 = ALL_BASELINES["B2"]
    b2.setup(temp_repo)
    code = b2.run_git(temp_repo, ["status", "--porcelain"])
    assert code == 0
    assert os.environ.get("DEADPUSH_ALLOW_DESTRUCTIVE_GIT") == "1"


def test_seed_useful_raises_when_write_rejected(temp_repo: Path):
    import pytest
    from deadpush.eval.scenarios import _seed_useful

    class RejectAll:
        id = "reject"

        def write_file(self, repo, rel, content):
            return False

        def run_git(self, repo, args):
            return 0

    with pytest.raises(RuntimeError, match="seed write rejected"):
        _seed_useful(RejectAll(), temp_repo, {"x.py": "x = 1\n"})
