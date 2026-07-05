"""macOS Seatbelt sandbox backend for deadpush run --sandbox."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

from .base import EnforcementBackend, logger

# macOS system temp roots agents commonly need for caches/IPC
_MACOS_TEMP_PREFIXES = (
    "/private/tmp",
    "/private/var/folders",
    "/var/folders",
)


def _path_variants(path: Path) -> list[str]:
    """Return resolved path literals useful in Seatbelt profiles."""
    resolved = path.resolve()
    variants = {str(resolved)}
    # macOS often resolves /var → /private/var
    try:
        real = resolved.as_posix()
        variants.add(real)
        if real.startswith("/private"):
            variants.add(real[len("/private"):])
        else:
            variants.add(f"/private{real}")
    except (OSError, ValueError):
        pass
    return sorted(variants)


def _seatbelt_quote(path: str) -> str:
    """Escape a path for inclusion in a Seatbelt profile string literal."""
    return path.replace("\\", "\\\\").replace('"', '\\"')


def generate_seatbelt_profile(repo_root: Path, *, hardened: bool = False) -> str:
    """Generate a Seatbelt profile allowing writes only under approved paths."""
    repo_variants = _path_variants(repo_root)
    home = Path.home().resolve()
    home_deadpush = home / ".deadpush"
    state_deadpush = Path("/var/db/deadpush")

    write_allow: list[str] = []
    for rv in repo_variants:
        write_allow.append(f'    (subpath "{_seatbelt_quote(rv)}")')
    write_allow.append(f'    (subpath "{_seatbelt_quote(str(home_deadpush))}")')
    if hardened and state_deadpush.exists():
        for sv in _path_variants(state_deadpush):
            write_allow.append(f'    (subpath "{_seatbelt_quote(sv)}")')

    for tmp_prefix in _MACOS_TEMP_PREFIXES:
        write_allow.append(f'    (subpath "{_seatbelt_quote(tmp_prefix)}")')

    write_block = "\n".join(write_allow)

    # Explicit deny rules for common exfil targets (belt-and-suspenders under deny default)
    sensitive_denies = "\n".join(
        f'(deny file-write* (subpath "{_seatbelt_quote(str(home / d))}"))'
        for d in (".ssh", ".aws", ".gnupg", ".config/gcloud", ".kube")
    )

    return f"""(version 1)
; deadpush Seatbelt profile — auto-generated, do not edit
(deny default)
(allow process*)
(allow signal)
(allow sysctl-read)
(allow file-read*)
(allow file-read-metadata)
(allow file-ioctl)
(allow mach-lookup)
(allow ipc-posix*)
(allow network*)
(allow file-write*
{write_block}
    (require-all
        (path "/dev/null")
        (regex #"^/dev/")))
{ sensitive_denies}
(allow file-write*
    (require-all
        (path "/dev/null")
        (regex #"^/dev/")))
"""


def seatbelt_profile_path(repo_root: Path) -> Path:
    return repo_root / ".deadpush" / "sandbox.sb"


def profile_content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def write_seatbelt_profile(repo_root: Path, *, hardened: bool = False) -> Path:
    path = seatbelt_profile_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_seatbelt_profile(repo_root, hardened=hardened)
    path.write_text(content, encoding="utf-8")
    meta = path.parent / "sandbox.sb.meta"
    meta.write_text(
        f"hash={profile_content_hash(content)}\nrepo={repo_root.resolve()}\n",
        encoding="utf-8",
    )
    return path


def validate_seatbelt_profile(profile_path: Path) -> tuple[bool, str]:
    """Verify profile by executing a no-op under sandbox-exec."""
    if not seatbelt_available():
        return False, "sandbox-exec not found"
    if not profile_path.is_file():
        return False, f"profile missing: {profile_path}"
    for true_bin in ("/usr/bin/true", "/bin/true"):
        if Path(true_bin).exists():
            break
    else:
        true_bin = "true"
    try:
        result = subprocess.run(
            ["sandbox-exec", "-f", str(profile_path), true_bin],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "unknown error").strip()
            return False, err
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "sandbox-exec validation timed out"
    except OSError as e:
        return False, str(e)


def verify_write_blocked_outside_repo(repo_root: Path, outside: Path) -> bool:
    """Return True if sandbox-exec blocks writing *outside* the repo."""
    if not seatbelt_available():
        return False
    profile = write_seatbelt_profile(repo_root)
    ok, _ = validate_seatbelt_profile(profile)
    if not ok:
        return False
    target = outside.resolve()
    script = f'touch "{target}/.deadpush_sandbox_probe" 2>/dev/null || exit 1'
    result = subprocess.run(
        ["sandbox-exec", "-f", str(profile), "/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.returncode != 0


class SeatbeltEnforcementBackend(EnforcementBackend):
    name = "seatbelt"
    tier = "T2"

    def __init__(self, repo_root: Path, *, hardened: bool = False):
        super().__init__(repo_root)
        self.hardened = hardened
        self._profile: Path | None = None
        self._profile_hash: str | None = None

    def available(self) -> bool:
        if sys.platform != "darwin":
            return False
        return shutil.which("sandbox-exec") is not None

    def start(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self._profile = write_seatbelt_profile(self.repo_root, hardened=self.hardened)
        content = self._profile.read_text(encoding="utf-8")
        self._profile_hash = profile_content_hash(content)
        ok, err = validate_seatbelt_profile(self._profile)
        if not ok:
            self._last_error = f"Seatbelt profile invalid: {err}"
            logger.error(self._last_error)
            raise RuntimeError(self._last_error)
        self._started = True
        logger.info("Seatbelt profile ready: %s (hash=%s)", self._profile, self._profile_hash)

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        ok, reason = self.preflight(cmd)
        if not ok:
            raise ValueError(f"seatbelt preflight failed: {reason}")

        if not self._profile or not self._profile.exists():
            self.start(repo_root)

        assert self._profile is not None
        ok, err = validate_seatbelt_profile(self._profile)
        if not ok:
            self._last_error = f"Seatbelt profile rejected before launch: {err}"
            raise RuntimeError(self._last_error)

        self.apply_env_markers(env)
        env["DEADPUSH_SEATBELT_PROFILE"] = str(self._profile)
        if self._profile_hash:
            env["DEADPUSH_SEATBELT_HASH"] = self._profile_hash

        return ["sandbox-exec", "-f", str(self._profile), *cmd]

    def stop(self) -> None:
        self._started = False

    def describe(self) -> dict:
        d = super().describe()
        d.update({
            "os_sandbox": True,
            "profile": str(self._profile) if self._profile else None,
            "profile_hash": self._profile_hash,
            "hardened": self.hardened,
            "gates": ["seatbelt", "git-wrapper", "mcp-proxy", "guardian-quarantine"],
            "note": (
                "Seatbelt confines the wrapped subprocess tree. "
                "IDE native editor writes are not covered — watchdog quarantine applies."
            ),
        })
        return d


def seatbelt_available() -> bool:
    if sys.platform != "darwin":
        return False
    return shutil.which("sandbox-exec") is not None


# Backward-compatible alias used in tests
test_seatbelt_write_blocked = verify_write_blocked_outside_repo
