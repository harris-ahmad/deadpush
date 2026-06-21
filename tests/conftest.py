"""Shared test fixtures for deadpush tests."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Generator

import pytest


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
