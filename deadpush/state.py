"""Central ~/.deadpush layout, registry, migration, and repo discovery.

Layout (soft mode)::

    ~/.deadpush/
      registry.json
      repos/
        <repo-id>/
          manifest.json      # path, label, last_seen, hardened
          guardian.log
          safety_score.json
          guardian.pid / .lock / .start / .holder / .shadow / .repo
          control.port
          control.token
          gpc.sock
          mcp_suspended
          launchd.out.log
          launchd.err.log

Legacy flat files at ``~/.deadpush/guardian.<id>.*`` are migrated on first
access and replaced with symlinks so running guardians keep working.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import repo_id

HARDENED_STATE_DIR = Path("/var/db/deadpush")
REGISTRY_VERSION = 1

# legacy flat filename -> new name inside repos/<id>/
_ARTIFACT_MAP: tuple[tuple[str, str], ...] = (
    ("guardian.{id}.log", "guardian.log"),
    ("safety_score.{id}.json", "safety_score.json"),
    ("guardian.{id}.pid", "guardian.pid"),
    ("guardian.{id}.lock", "guardian.lock"),
    ("guardian.{id}.start", "guardian.start"),
    ("guardian.{id}.holder", "guardian.holder"),
    ("guardian.{id}.shadow", "guardian.shadow"),
    ("guardian.{id}.repo", "guardian.repo"),
    ("guardian.control.port.{id}", "control.port"),
    ("guardian.control.token.{id}", "control.token"),
    ("gpc.{id}.sock", "gpc.sock"),
    ("mcp_suspended.{id}", "mcp_suspended"),
    ("guardian.{id}.launchd.out.log", "launchd.out.log"),
    ("guardian.{id}.launchd.err.log", "launchd.err.log"),
)

_LEGACY_REPO_ID_RE = re.compile(
    r"^(?:guardian|safety_score|gpc|mcp_suspended)\.([0-9a-f]{12})"
    r"|^guardian\.control\.(?:port|token)\.([0-9a-f]{12})$"
)

_migrated_soft = False
_migrated_hardened = False


def state_dir(hardened: bool = False) -> Path:
    if hardened:
        return HARDENED_STATE_DIR
    return Path.home() / ".deadpush"


def registry_path(hardened: bool = False) -> Path:
    return state_dir(hardened) / "registry.json"


def repo_state_dir(repo_root: Path | str, hardened: bool = False) -> Path:
    """Per-repo state directory (creates parent ``repos/`` only)."""
    rid = repo_id(repo_root)
    root = state_dir(hardened)
    repos_root = root / "repos"
    repos_root.mkdir(parents=True, exist_ok=True)
    return repos_root / rid


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_registry(hardened: bool = False) -> dict[str, Any]:
    path = registry_path(hardened)
    if not path.exists():
        return {"version": REGISTRY_VERSION, "repos": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": REGISTRY_VERSION, "repos": {}}
    if "repos" not in data:
        data["repos"] = {}
    return data


def save_registry(data: dict[str, Any], hardened: bool = False) -> None:
    path = registry_path(hardened)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")


def touch_registry(
    repo_root: Path | str,
    *,
    hardened: bool = False,
    running: bool | None = None,
) -> None:
    """Record or refresh a repo in registry.json."""
    resolved = Path(repo_root).resolve()
    rid = repo_id(resolved)
    reg = load_registry(hardened)
    repos: dict[str, Any] = reg.setdefault("repos", {})
    entry = repos.get(rid, {})
    entry["path"] = str(resolved)
    entry["label"] = resolved.name
    entry["last_seen"] = _now_iso()
    entry["hardened"] = hardened
    if running is not None:
        entry["running"] = running
    repos[rid] = entry
    save_registry(reg, hardened)

    manifest = repo_state_dir(resolved, hardened) / "manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(entry, indent=2, default=str) + "\n", encoding="utf-8")


def _legacy_repo_ids(root: Path) -> set[str]:
    ids: set[str] = set()
    if not root.exists():
        return ids
    for pattern in (
        "guardian.*.pid",
        "guardian.*.holder",
        "guardian.*.log",
        "safety_score.*.json",
        "gpc.*.sock",
    ):
        for p in root.glob(pattern):
            m = _LEGACY_REPO_ID_RE.match(p.name)
            if m:
                ids.add(m.group(1) or m.group(2))
    for p in (root / "repos").glob("*") if (root / "repos").exists() else []:
        if p.is_dir() and re.fullmatch(r"[0-9a-f]{12}", p.name):
            ids.add(p.name)
    return ids


def _symlink_legacy(legacy: Path, target: Path) -> None:
    if legacy.exists() or legacy.is_symlink():
        return
    try:
        legacy.symlink_to(os.path.relpath(target, legacy.parent))
    except OSError:
        pass


def _migrate_repo(rid: str, hardened: bool) -> None:
    root = state_dir(hardened)
    dest = root / "repos" / rid
    dest.mkdir(parents=True, exist_ok=True)

    repo_path: str | None = None
    for legacy_pat, new_name in _ARTIFACT_MAP:
        legacy_name = legacy_pat.format(id=rid)
        src = root / legacy_name
        dst = dest / new_name
        if src.exists() and not src.is_symlink():
            if dst.exists():
                try:
                    src.unlink()
                except OSError:
                    pass
            else:
                try:
                    src.rename(dst)
                except OSError:
                    try:
                        shutil.copy2(src, dst)
                    except OSError:
                        pass
        if dst.exists() and not src.exists():
            _symlink_legacy(src, dst)

        if new_name == "guardian.holder" and dst.exists():
            try:
                repo_path = dst.read_text(encoding="utf-8").strip() or None
            except OSError:
                pass

    if repo_path:
        touch_registry(repo_path, hardened=hardened)


def ensure_layout_migrated(hardened: bool = False) -> None:
    global _migrated_soft, _migrated_hardened
    if hardened:
        if _migrated_hardened:
            return
        flag = "_migrated_hardened"
    else:
        if _migrated_soft:
            return
        flag = "_migrated_soft"

    root = state_dir(hardened)
    try:
        root.mkdir(parents=True, exist_ok=True)
        (root / "repos").mkdir(exist_ok=True)
    except PermissionError:
        if hardened:
            _migrated_hardened = True
            return
        raise

    for rid in _legacy_repo_ids(root):
        _migrate_repo(rid, hardened)

    if hardened:
        _migrated_hardened = True
    else:
        _migrated_soft = True


def _artifact_path(repo_root: Path | str, name: str, hardened: bool = False) -> Path:
    """Return path to a named artifact inside repos/<id>/ (runs migration once)."""
    ensure_layout_migrated(hardened)
    return repo_state_dir(repo_root, hardened) / name


# ---------------------------------------------------------------------------
# Scoped paths (replacement for guard._scoped_* helpers)
# ---------------------------------------------------------------------------

def scoped_pidfile(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "guardian.pid", hardened)


def scoped_lockfile(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "guardian.lock", hardened)


def scoped_portfile(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "control.port", hardened)


def scoped_token_file(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "control.token", hardened)


def scoped_suspend_file(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "mcp_suspended", hardened)


def scoped_safety_score_file(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "safety_score.json", hardened)


def scoped_log_file(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "guardian.log", hardened)


def scoped_gpc_socket(repo_root: Path | str, hardened: bool = False) -> Path:
    return _artifact_path(repo_root, "gpc.sock", hardened)


def scoped_plist_label(repo_root: Path | str) -> str:
    return f"com.deadpush.guardian.{repo_id(repo_root)}"


def scoped_plist_path(repo_root: Path | str, hardened: bool = False) -> Path:
    label = scoped_plist_label(repo_root)
    if hardened:
        return Path("/Library/LaunchDaemons") / f"{label}.plist"
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def scoped_systemd_unit_path(repo_root: Path | str, hardened: bool = False) -> Path:
    rid = repo_id(repo_root)
    if hardened:
        return Path("/etc/systemd/system") / f"deadpush-guardian.{rid}.service"
    return Path.home() / ".config" / "systemd" / "user" / f"deadpush-guardian.{rid}.service"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _read_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _process_alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _discover_ids_from_processes() -> set[str]:
    """Repo ids inferred from live guardian/shadow processes."""
    ids: set[str] = set()
    for pattern in ("deadpush_shadow_watch.", "guardian."):
        try:
            r = subprocess.run(
                ["pgrep", "-fl", pattern],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "deadpush_shadow_watch." in line:
                    tag = line.split("deadpush_shadow_watch.", 1)[1]
                    rid = tag.split()[0].strip(".")
                    if re.fullmatch(r"[0-9a-f]{12}", rid):
                        ids.add(rid)
                for part in line.split():
                    m = re.search(r"guardian\.([0-9a-f]{12})\.", part)
                    if m:
                        ids.add(m.group(1))
                    m2 = re.search(r"/repos/([0-9a-f]{12})/", part)
                    if m2:
                        ids.add(m2.group(1))
        except Exception:
            pass
    return ids


def discover_repos(hardened: bool = False) -> list[dict[str, Any]]:
    """Return all known repos with id, path, label, running, pid."""
    try:
        ensure_layout_migrated(hardened)
    except PermissionError:
        return []
    root = state_dir(hardened)
    if hardened and not root.exists():
        return []
    by_id: dict[str, dict[str, Any]] = {}

    reg = load_registry(hardened)
    for rid, entry in reg.get("repos", {}).items():
        by_id[rid] = {
            "id": rid,
            "path": entry.get("path", ""),
            "label": entry.get("label", rid),
            "hardened": entry.get("hardened", hardened),
        }

    repos_root = root / "repos"
    if repos_root.exists():
        for d in repos_root.iterdir():
            if not d.is_dir() or not re.fullmatch(r"[0-9a-f]{12}", d.name):
                continue
            rid = d.name
            manifest = d / "manifest.json"
            path = ""
            label = rid
            if manifest.exists():
                try:
                    m = json.loads(manifest.read_text(encoding="utf-8"))
                    path = m.get("path", "")
                    label = m.get("label", label)
                except Exception:
                    pass
            holder = d / "guardian.holder"
            if not path and holder.exists():
                try:
                    path = holder.read_text(encoding="utf-8").strip()
                except OSError:
                    pass
            if rid not in by_id:
                by_id[rid] = {"id": rid, "path": path, "label": label or rid, "hardened": hardened}
            elif path and not by_id[rid].get("path"):
                by_id[rid]["path"] = path

    # Legacy holders at flat root (pre-migration or symlink-only)
    for holder in root.glob("guardian.*.holder"):
        parts = holder.name.split(".")
        if len(parts) < 3:
            continue
        rid = parts[1]
        try:
            path = holder.read_text(encoding="utf-8").strip()
        except OSError:
            path = ""
        if rid not in by_id:
            by_id[rid] = {
                "id": rid,
                "path": path,
                "label": Path(path).name if path else rid,
                "hardened": hardened,
            }

    for rid in _discover_ids_from_processes():
        if rid in by_id:
            continue
        rdir = repos_root / rid
        legacy_pid = root / f"guardian.{rid}.pid"
        if not rdir.exists() and not legacy_pid.exists():
            continue
        by_id[rid] = {"id": rid, "path": "", "label": rid, "hardened": hardened}

    out: list[dict[str, Any]] = []
    for rid, entry in sorted(by_id.items(), key=lambda x: x[1].get("label", x[0])):
        path_str = entry.get("path") or ""
        pid: int | None = None
        running = False
        if path_str:
            pid = _read_pid(scoped_pidfile(path_str, hardened))
            running = _process_alive(pid)
        else:
            pid = _read_pid(repos_root / rid / "guardian.pid") if repos_root.exists() else None
            running = _process_alive(pid)
        entry["pid"] = pid
        entry["running"] = running
        out.append(entry)
    return out


def discover_all_repos() -> list[dict[str, Any]]:
    """Merge soft + hardened repo entries, dedupe by id (prefer entry with path)."""
    by_id: dict[str, dict[str, Any]] = {}
    for hardened in (False, True):
        for entry in discover_repos(hardened=hardened):
            rid = entry["id"]
            existing = by_id.get(rid)
            if existing is None:
                by_id[rid] = entry
            elif not existing.get("path") and entry.get("path"):
                by_id[rid] = {**existing, **entry}
            elif entry.get("running") and not existing.get("running"):
                by_id[rid] = {**existing, **entry}
    return sorted(by_id.values(), key=lambda e: (e.get("label") or e["id"]).lower())


def hub_pidfile() -> Path:
    return state_dir(False) / "hub.pid"


def hub_portfile() -> Path:
    return state_dir(False) / "hub.port"


def reset_migration_flags() -> None:
    """Clear one-shot migration flags (for tests)."""
    global _migrated_soft, _migrated_hardened
    _migrated_soft = False
    _migrated_hardened = False
