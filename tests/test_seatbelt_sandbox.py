"""Tests for macOS Seatbelt sandbox backend."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from deadpush.backends.seatbelt import (
    SeatbeltEnforcementBackend,
    generate_seatbelt_profile,
    profile_content_hash,
    seatbelt_available,
    validate_seatbelt_profile,
    verify_write_blocked_outside_repo,
    write_seatbelt_profile,
)


def test_generate_seatbelt_profile(temp_repo: Path):
    profile = generate_seatbelt_profile(temp_repo)
    assert str(temp_repo.resolve()) in profile
    assert "(deny default)" in profile
    assert "(allow file-write*" in profile
    assert "(allow network-outbound)" in profile
    assert "(allow network*)" not in profile
    assert ".ssh" in profile


def test_generate_seatbelt_profile_path_variants(temp_repo: Path):
    profile = generate_seatbelt_profile(temp_repo)
    # macOS may use /private prefix
    resolved = str(temp_repo.resolve())
    assert resolved in profile or f"/private{resolved}" in profile


def test_write_seatbelt_profile(temp_repo: Path):
    path = write_seatbelt_profile(temp_repo)
    assert path.exists()
    assert path.name == "sandbox.sb"
    meta = path.parent / "sandbox.sb.meta"
    assert meta.exists()


def test_profile_content_hash_stable(temp_repo: Path):
    content = generate_seatbelt_profile(temp_repo)
    assert profile_content_hash(content) == profile_content_hash(content)


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt is macOS-only")
def test_validate_seatbelt_profile(temp_repo: Path):
    if not seatbelt_available():
        pytest.skip("sandbox-exec not available")
    path = write_seatbelt_profile(temp_repo)
    ok, err = validate_seatbelt_profile(path)
    assert ok, err


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt is macOS-only")
def test_seatbelt_backend_wrap(temp_repo: Path):
    backend = SeatbeltEnforcementBackend(temp_repo)
    if not seatbelt_available():
        pytest.skip("sandbox-exec not available")
    backend.start(temp_repo)
    wrapped = backend.wrap_command(["echo", "hi"], repo_root=temp_repo, env={})
    assert wrapped[0] == "sandbox-exec"
    assert "-f" in wrapped
    info = backend.describe()
    assert info["os_sandbox"] is True
    assert info["profile_hash"]


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_seatbelt_available_on_macos(temp_repo: Path):
    backend = SeatbeltEnforcementBackend(temp_repo)
    assert backend.available() == seatbelt_available()


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt is macOS-only")
def test_write_blocked_outside_repo(temp_repo: Path):
    if not seatbelt_available():
        pytest.skip("sandbox-exec not available")
    # Must be outside repo AND outside Seatbelt temp allowlist (/private/tmp, /var/folders).
    outside = Path("/Users/Shared") / f".deadpush_sandbox_probe_{os.getpid()}"
    outside.mkdir(parents=True, exist_ok=True)
    try:
        assert verify_write_blocked_outside_repo(temp_repo, outside)
    finally:
        probe = outside / ".deadpush_sandbox_probe"
        probe.unlink(missing_ok=True)
        outside.rmdir()

