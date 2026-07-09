"""Tests for hook integrity verify/repair (no soft-mode repair loops)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from deadpush.hooks import (
    _make_mutable,
    install_precommit_hook,
    repair_deadpush_hooks,
    verify_hooks_installed,
)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS immutability flags")
def test_soft_mode_checksum_ok_without_uchg_is_not_a_problem(temp_repo: Path):
    from deadpush.hooks import install_hook, install_postcommit_hook

    install_hook(temp_repo, system=False)
    install_precommit_hook(temp_repo, system=False)
    install_postcommit_hook(temp_repo, system=False)
    hook = temp_repo / ".git" / "hooks" / "pre-commit"
    _make_mutable(hook)
    assert not verify_hooks_installed(temp_repo)
    assert repair_deadpush_hooks(temp_repo) == []


def test_tampered_hook_still_flagged_without_immutability(temp_repo: Path):
    install_precommit_hook(temp_repo, system=False)
    hook = temp_repo / ".git" / "hooks" / "pre-commit"
    _make_mutable(hook)
    hook.write_text("# tampered\n", encoding="utf-8")
    problems = verify_hooks_installed(temp_repo)
    assert any("pre-commit" in p and "tampered" in p for p in problems)


def test_check_hook_integrity_cooldown(temp_repo: Path, monkeypatch):
    from deadpush.guard import GuardianHandler

    handler = GuardianHandler(MagicMock(repo_root=temp_repo), daemon=True)
    calls: list[int] = []

    def fake_repair(repo_root, *a, **k):
        calls.append(1)
        return []

    monkeypatch.setattr("deadpush.hooks.repair_deadpush_hooks", fake_repair)
    monkeypatch.setattr(
        "deadpush.hooks.verify_hooks_installed",
        lambda r: ["pre-commit (not immutable)"],
    )

    handler._check_hook_integrity()
    handler._check_hook_integrity()
    assert len(calls) == 1
