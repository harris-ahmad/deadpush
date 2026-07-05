"""macOS Seatbelt sandbox backend for deadpush run --sandbox."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .base import EnforcementBackend


def generate_seatbelt_profile(repo_root: Path) -> str:
    """Generate a Seatbelt profile allowing writes only under *repo_root*."""
    repo = repo_root.resolve()
    home = Path.home().resolve()
    return f"""(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow file-read*)
(allow file-write*
    (subpath "{repo}")
    (subpath "{repo}/.deadpush")
    (subpath "{repo}/.deadpush-quarantine")
    (subpath "{home}/.deadpush")
    (subpath "/private{repo}"))
(allow file-write*
    (require-all
        (path "/dev/null")
        (regex #"^/dev/")))
(allow network*)
"""


def seatbelt_profile_path(repo_root: Path) -> Path:
    return repo_root / ".deadpush" / "sandbox.sb"


def write_seatbelt_profile(repo_root: Path) -> Path:
    path = seatbelt_profile_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_seatbelt_profile(repo_root), encoding="utf-8")
    return path


class SeatbeltEnforcementBackend(EnforcementBackend):
    name = "seatbelt"

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self._profile: Path | None = None

    def available(self) -> bool:
        if sys.platform != "darwin":
            return False
        return shutil.which("sandbox-exec") is not None

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        profile = write_seatbelt_profile(repo_root)
        self._profile = profile
        return ["sandbox-exec", "-f", str(profile), *cmd]

    def start(self, repo_root: Path) -> None:
        write_seatbelt_profile(repo_root)

    def stop(self) -> None:
        pass

    def describe(self) -> dict:
        d = super().describe()
        d["profile"] = str(self._profile) if self._profile else None
        d["note"] = (
            "Seatbelt confines the wrapped subprocess tree. "
            "IDE native editor writes are not covered — watchdog quarantine applies."
        )
        return d


def seatbelt_available() -> bool:
    if sys.platform != "darwin":
        return False
    return shutil.which("sandbox-exec") is not None


def test_seatbelt_write_blocked(repo_root: Path, target: Path) -> bool:
    """Return True if sandbox-exec blocks writing *target* outside repo."""
    if not seatbelt_available():
        return False
    profile = write_seatbelt_profile(repo_root)
    outside = target.resolve()
    script = f"echo test > {outside}"
    result = subprocess.run(
        ["sandbox-exec", "-f", str(profile), "/bin/sh", "-c", script],
        capture_output=True,
        text=True,
    )
    return result.returncode != 0
