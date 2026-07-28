"""Writable path allowlist shared by Seatbelt and bubblewrap sandboxes."""

from __future__ import annotations

from pathlib import Path

# Linux temp roots agents commonly need for caches/IPC (mirror seatbelt temp prefixes).
LINUX_TEMP_PREFIXES = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
)

# macOS Seatbelt temp prefixes (re-exported for seatbelt.py).
MACOS_TEMP_PREFIXES = (
    "/private/tmp",
    "/private/var/folders",
    "/var/folders",
)


def collect_writable_sandbox_paths(
    repo_root: Path,
    *,
    hardened: bool = False,
    platform: str | None = None,
) -> list[Path]:
    """Paths where a sandboxed agent may write (repo, state, temp)."""
    import sys

    plat = platform or sys.platform
    repo = repo_root.resolve()
    paths: list[Path] = [repo, Path.home().resolve() / ".deadpush"]

    state_deadpush = Path("/var/db/deadpush")
    if hardened and state_deadpush.exists():
        paths.append(state_deadpush)

    if plat == "darwin":
        for tmp_prefix in MACOS_TEMP_PREFIXES:
            paths.append(Path(tmp_prefix))
    elif plat.startswith("linux"):
        for tmp_prefix in LINUX_TEMP_PREFIXES:
            paths.append(Path(tmp_prefix))

    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        key = str(resolved)
        if key not in seen:
            seen.add(key)
            out.append(resolved)
    return out
