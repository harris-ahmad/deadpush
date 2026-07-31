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
    ensure_home_state: bool = True,
) -> list[Path]:
    """Paths where a sandboxed agent may write (repo, state, temp).

    Only paths that exist on the host are returned. bubblewrap ``--bind`` fails
    immediately if the source path is missing (common for ``/dev/shm`` in
    containers and for a never-created ``~/.deadpush``).
    """
    import sys

    plat = platform or sys.platform
    repo = repo_root.resolve()
    if not repo.exists():
        raise FileNotFoundError(f"sandbox repo root does not exist: {repo}")

    candidates: list[Path] = [repo]

    home_deadpush = Path.home().resolve() / ".deadpush"
    if ensure_home_state:
        home_deadpush.mkdir(parents=True, exist_ok=True)
    candidates.append(home_deadpush)

    state_deadpush = Path("/var/db/deadpush")
    if hardened:
        candidates.append(state_deadpush)

    if plat == "darwin":
        candidates.extend(Path(p) for p in MACOS_TEMP_PREFIXES)
    elif plat.startswith("linux"):
        candidates.extend(Path(p) for p in LINUX_TEMP_PREFIXES)

    seen: set[str] = set()
    out: list[Path] = []
    for p in candidates:
        if not p.exists():
            continue
        resolved = p.resolve()
        key = str(resolved)
        if key not in seen:
            seen.add(key)
            out.append(resolved)
    return out
