"""Tests for Linux bubblewrap sandbox backend."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from deadpush.backends.bubblewrap import (
    BubblewrapEnforcementBackend,
    build_bwrap_argv,
    bubblewrap_available,
)
from deadpush.backends.sandbox_paths import collect_writable_sandbox_paths


def test_collect_writable_sandbox_paths_linux(temp_repo: Path):
    paths = collect_writable_sandbox_paths(temp_repo, platform="linux")
    assert temp_repo.resolve() in paths
    assert any("/tmp" in str(p) for p in paths)
    assert all(p.exists() for p in paths)


def test_collect_skips_missing_optional_paths(temp_repo: Path, tmp_path: Path, monkeypatch):
    missing_home = tmp_path / "nohome"
    missing_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: missing_home))
    # Do not create ~/.deadpush; optional temps that do not exist must be omitted.
    paths = collect_writable_sandbox_paths(
        temp_repo, platform="linux", ensure_home_state=False,
    )
    assert temp_repo.resolve() in paths
    assert all(p.exists() for p in paths)
    assert not any(str(p).endswith("/.deadpush") for p in paths)


def test_collect_skips_missing_dev_shm(temp_repo: Path, monkeypatch):
    real_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self.as_posix().endswith("/dev/shm"):
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    paths = collect_writable_sandbox_paths(temp_repo, platform="linux")
    assert not any(str(p).endswith("/dev/shm") for p in paths)
    for p in paths:
        assert real_exists(p)


def test_build_bwrap_argv_structure(temp_repo: Path):
    argv = build_bwrap_argv(
        ["python", "-c", "print(1)"],
        temp_repo,
        bwrap_bin="/usr/bin/bwrap",
    )
    assert argv[0] == "/usr/bin/bwrap"
    assert argv[1:4] == ["--ro-bind", "/", "/"]
    # --dev must precede /dev/shm binds so the fresh /dev tmpfs does not shadow shm.
    assert argv[4:8] == ["--proc", "/proc", "--dev", "/dev"]
    repo_s = str(temp_repo.resolve())
    assert "--bind" in argv
    assert repo_s in argv
    assert argv[-4:] == ["--", "python", "-c", "print(1)"]
    assert "--die-with-parent" in argv

    # Every --bind source must exist (bwrap requirement).
    for i, arg in enumerate(argv):
        if arg == "--bind" and i + 1 < len(argv):
            assert Path(argv[i + 1]).exists(), argv[i + 1]

    dev_idx = argv.index("--dev")
    shm_bind_idxs = [
        i for i, (a, b) in enumerate(zip(argv, argv[1:]))
        if a == "--bind" and b.endswith("/dev/shm")
    ]
    if Path("/dev/shm").exists():
        assert shm_bind_idxs, "expected a --bind for /dev/shm when it exists"
        assert all(i > dev_idx for i in shm_bind_idxs)
    else:
        assert not shm_bind_idxs


def test_build_bwrap_argv_skips_vanished_paths(temp_repo: Path, monkeypatch):
    ghost = Path("/dev/shm")
    # Force collect to return a missing path; build_bwrap_argv must drop it.
    monkeypatch.setattr(
        "deadpush.backends.bubblewrap.collect_writable_sandbox_paths",
        lambda *a, **k: [temp_repo.resolve(), ghost],
    )
    argv = build_bwrap_argv(["true"], temp_repo, bwrap_bin="/usr/bin/bwrap")
    binds = [argv[i + 1] for i, a in enumerate(argv) if a == "--bind"]
    assert str(temp_repo.resolve()) in binds
    if not ghost.exists():
        assert str(ghost) not in binds


def test_bubblewrap_capabilities(temp_repo: Path):
    backend = BubblewrapEnforcementBackend(temp_repo)
    caps = backend.capabilities
    assert caps.os_confinement is True
    assert caps.write_allowlist is True
    assert caps.content_deny is False


@pytest.mark.skipif(sys.platform != "linux", reason="linux only")
def test_bubblewrap_available_matches_path():
    with patch("deadpush.backends.bubblewrap.bubblewrap_binary", return_value="/usr/bin/bwrap"):
        assert bubblewrap_available() is True
    with patch("deadpush.backends.bubblewrap.bubblewrap_binary", return_value=None):
        assert bubblewrap_available() is False


def test_build_bwrap_argv_requires_binary(temp_repo: Path):
    with patch("deadpush.backends.bubblewrap.bubblewrap_binary", return_value=None):
        with pytest.raises(RuntimeError, match="bubblewrap not found"):
            build_bwrap_argv(["true"], temp_repo)
