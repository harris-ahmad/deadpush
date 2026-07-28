"""Shared test fixtures for deadpush tests."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any, Generator

import pytest


def patch_guard_helper(monkeypatch: pytest.MonkeyPatch, attr: str, value: Any, *impl_modules: Any) -> None:
    """Patch a helper on ``deadpush.guard`` and each implementation module.

    After the ``guard.py`` split, symbols such as ``_scoped_pidfile`` are bound
    in the implementation module's globals (``guardian_lifecycle``, ``hardened``,
    …).  Functions there resolve the name from *their* namespace, not from the
    facade.  Patching only ``guard._scoped_pidfile`` leaves those call sites on
    the real path and can produce silent false greens.  Always patch both sides.
    """
    import deadpush.guard as guard

    monkeypatch.setattr(guard, attr, value)
    for mod in impl_modules:
        monkeypatch.setattr(mod, attr, value)


@pytest.fixture
def temp_repo() -> Generator[Path, None, None]:
    """Create a temporary git repository with an initial commit."""
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "testrepo"
        repo.mkdir()
        (repo / "hello.py").write_text("x = 1\n")
        subprocess.run(["git", "init"], capture_output=True, cwd=str(repo))
        subprocess.run(["git", "config", "user.email", "test@test.com"], capture_output=True, cwd=str(repo))
        subprocess.run(["git", "config", "user.name", "Test"], capture_output=True, cwd=str(repo))
        subprocess.run(["git", "add", "."], capture_output=True, cwd=str(repo))
        subprocess.run(["git", "commit", "-m", "init"], capture_output=True, cwd=str(repo))
        yield repo


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory (no git)."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)
