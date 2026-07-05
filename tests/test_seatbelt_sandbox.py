"""Tests for macOS Seatbelt sandbox backend."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from deadpush.backends.seatbelt import (
    SeatbeltEnforcementBackend,
    generate_seatbelt_profile,
    seatbelt_available,
    write_seatbelt_profile,
)


def test_generate_seatbelt_profile(temp_repo: Path):
    profile = generate_seatbelt_profile(temp_repo)
    assert str(temp_repo.resolve()) in profile
    assert "(deny default)" in profile
    assert "(allow file-write*" in profile


def test_write_seatbelt_profile(temp_repo: Path):
    path = write_seatbelt_profile(temp_repo)
    assert path.exists()
    assert path.name == "sandbox.sb"


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt is macOS-only")
def test_seatbelt_backend_wrap(temp_repo: Path):
    backend = SeatbeltEnforcementBackend(temp_repo)
    if not seatbelt_available():
        pytest.skip("sandbox-exec not available")
    wrapped = backend.wrap_command(["echo", "hi"], repo_root=temp_repo, env={})
    assert wrapped[0] == "sandbox-exec"
    assert "-f" in wrapped


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_seatbelt_available_on_macos(temp_repo: Path):
    backend = SeatbeltEnforcementBackend(temp_repo)
    assert backend.available() == seatbelt_available()
