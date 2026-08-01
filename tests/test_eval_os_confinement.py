"""Tests for thesis eval OS confinement (B4-os / §9)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from deadpush.backends.base import SandboxUnavailableError
from deadpush.eval.baselines import ALL_BASELINES, B4OS
from deadpush.eval.os_sandbox import (
    os_confinement_status,
    outside_probe_dir,
    probe_outside_write_blocked,
    select_eval_os_backend,
)
from deadpush.eval.runner import run_eval_matrix, run_one
from deadpush.eval.scenarios import SCENARIOS


def _os_available(repo: Path) -> bool:
    return bool(os_confinement_status(repo).get("available"))


@pytest.fixture
def require_os_confinement(temp_repo: Path):
    if not _os_available(temp_repo):
        pytest.skip("no Seatbelt/bubblewrap OS confinement on this host")
    return temp_repo


def test_outside_repo_write_registered():
    assert "outside_repo_write" in SCENARIOS
    assert "B4-os" in ALL_BASELINES


def test_os_status_shape(temp_repo: Path):
    status = os_confinement_status(temp_repo)
    assert "available" in status
    assert "backend" in status
    assert "capabilities" in status
    assert "error" in status


def test_select_prefer_noop_raises(temp_repo: Path):
    with pytest.raises(SandboxUnavailableError, match="os_confinement"):
        select_eval_os_backend(temp_repo, prefer="noop")


def test_outside_probe_dir_not_under_temp(temp_repo: Path):
    outside = outside_probe_dir(temp_repo)
    resolved = str(outside.resolve())
    assert "/var/folders" not in resolved
    assert not resolved.startswith("/tmp")
    assert not resolved.startswith("/private/tmp")
    assert ".deadpush/" not in resolved + "/"


def test_b4_os_outside_write_blocked(require_os_confinement: Path):
    result = run_one("outside_repo_write", B4OS())
    assert result.blocked is True
    assert result.lasting_damage is False
    assert "blocked" in result.notes


def test_b0_outside_write_not_blocked():
    result = run_one("outside_repo_write", ALL_BASELINES["B0"])
    assert result.blocked is False
    assert result.lasting_damage is True


def test_b4_os_destructive_git(require_os_confinement: Path):
    result = run_one("destructive_git", B4OS())
    assert result.blocked is True
    assert result.lasting_damage is False


def test_probe_outside_write_blocked(require_os_confinement: Path):
    assert probe_outside_write_blocked(require_os_confinement) is True


def test_probe_outside_raises_when_jail_never_runs(temp_repo: Path, monkeypatch):
    """Bwrap/setup failure must not be credited as a write-deny."""
    from deadpush.eval import os_sandbox

    def fake_run(repo, cmd, *, prefer=None, extra_env=None):
        return type(
            "P",
            (),
            {
                "returncode": 1,
                "stdout": b"",
                "stderr": b"bwrap: setting up uid map: Operation not permitted",
            },
        )()

    monkeypatch.setattr(os_sandbox, "run_under_os_sandbox", fake_run)
    with pytest.raises(SandboxUnavailableError, match="canary"):
        probe_outside_write_blocked(temp_repo)


def test_probe_outside_false_when_canary_ok_and_probe_lands(temp_repo: Path, monkeypatch):
    """If the jail runs but still allows the outside write, report unblocked."""
    import os

    from deadpush.eval import os_sandbox

    def fake_run(repo, cmd, *, prefer=None, extra_env=None):
        canary = temp_repo / f".deadpush_eval_canary_{os.getpid()}"
        outside = outside_probe_dir(temp_repo)
        outside.mkdir(parents=True, exist_ok=True)
        probe = outside / f".deadpush_eval_probe_{os.getpid()}"
        canary.write_text("ok", encoding="utf-8")
        probe.write_text("x", encoding="utf-8")
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(os_sandbox, "run_under_os_sandbox", fake_run)
    assert probe_outside_write_blocked(temp_repo) is False


def test_os_confined_matrix_preflight(require_os_confinement: Path, tmp_path: Path):
    results = run_eval_matrix(
        scenarios=["outside_repo_write", "benign_commit"],
        baselines=["B0", "B4-os"],
        os_confined=True,
    )
    assert len(results) == 4
    b4os_outside = next(
        r for r in results if r.baseline == "B4-os" and r.scenario == "outside_repo_write"
    )
    assert b4os_outside.blocked is True


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt prefer path")
def test_prefer_seatbelt(require_os_confinement: Path):
    backend = select_eval_os_backend(require_os_confinement, prefer="seatbelt")
    assert backend.name == "seatbelt"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="bwrap prefer path")
def test_prefer_bubblewrap(require_os_confinement: Path):
    backend = select_eval_os_backend(require_os_confinement, prefer="bubblewrap")
    assert backend.name == "bubblewrap"
