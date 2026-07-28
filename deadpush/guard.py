"""
deadpush Guard Mode - The AI Agent Guardian (Production Grade v2)

Major improvements:
- More robust daemon management with lock files and health checks
- Stronger intervention logic (quarantine instead of hard delete, modification blocking)
- Better error recovery
- Strict mode support
- More detailed intervention logging

This module is a **facade**: all implementations live in the sub-modules listed
below.  Import from here for backward compatibility.
"""

from __future__ import annotations

import sys  # noqa: F401 – kept so tests can patch guard.sys.platform
from pathlib import Path

from .config import repo_id as _repo_id  # noqa: F401 – re-exported for tests/callers
from . import state as _state

try:
    from watchdog.observers import Observer  # noqa: F401
    from watchdog.events import FileSystemEventHandler  # noqa: F401
    WATCHDOG_AVAILABLE = True
except ImportError:
    Observer = None  # type: ignore[assignment]
    FileSystemEventHandler = None  # type: ignore[assignment]
    WATCHDOG_AVAILABLE = False


# ---------------------------------------------------------------------------
# Path wrappers (all delegate to state; kept here so tests can patch guard.*)
# ---------------------------------------------------------------------------

def _state_dir(hardened: bool = False) -> Path:
    return _state.state_dir(hardened)


def _scoped_pidfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_pidfile(repo_root, hardened)


def _scoped_lockfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_lockfile(repo_root, hardened)


def _scoped_portfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_portfile(repo_root, hardened)


def _scoped_token_file(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_token_file(repo_root, hardened)


def _scoped_suspend_file(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_suspend_file(repo_root, hardened)


def _scoped_safety_score_file(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_safety_score_file(repo_root, hardened)


def _scoped_log_file(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_log_file(repo_root, hardened)


def _scoped_plist_label(repo_root: Path) -> str:
    return _state.scoped_plist_label(repo_root)


def _scoped_plist_path(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_plist_path(repo_root, hardened)


def _scoped_systemd_unit_path(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_systemd_unit_path(repo_root, hardened)


def _is_hardened(hardened: bool = False) -> bool:
    return hardened


# ---------------------------------------------------------------------------
# Re-exports from sub-modules (noqa: F401 — these are the public facade API)
# ---------------------------------------------------------------------------

# control_plane
from .control_plane import _load_or_create_control_token  # noqa: E402, F401
from .control_plane import (  # noqa: E402, F401
    DASHBOARD_HTML,
    GuardianControlHandler,
    GuardianControlServer,
    ThreadedHTTPServer,
)

# quarantine
from .quarantine import QuarantineManager  # noqa: E402, F401

# safety_score
from .safety_score import SessionSafetyScore  # noqa: E402, F401

# hardened
from .hardened import (  # noqa: E402, F401
    _HARDENED_STATE_DIR,
    _HARDENED_VENV_DIR,
    _hardened_python,
    _deadpush_source_root,
    _find_bootstrap_python,
    _is_system_path,
    _write_privileged_file,
    _HARDENED_TRAVERSE_ACE,
    _hardened_traverse_dirs,
    _apply_hardened_traverse_acls,
    _apply_hardened_repo_acls,
    _deadpush_account_valid,
    _find_free_system_id,
    _ensure_deadpush_account,
    _ensure_hardened_venv,
    _setup_hardened_policy,
    _launchctl_bootstrap_system,
    setup_autostart,
    setup_hardened_environment,
    teardown_hardened_environment,
)

# guardian_handler
from .guardian_handler import GuardianHandler  # noqa: E402, F401

# guardian_lifecycle
from .guardian_lifecycle import (  # noqa: E402, F401
    DaemonManager,
    setup_logging,
    _SHADOW_SCRIPT,
    _SHADOW_TAG_PREFIX,
    _shadow_tag,
    start_shadow_process,
    stop_shadow_for_repo,
    stop_guardian_for_repo,
    stop_guardian_by_id,
    kill_orphan_guardian_processes,
    count_running_guardians,
    guardian_is_running,
    guardian_persistence_installed,
    guardian_killed_uncleanly,
    run_guardian,
    _start_control_server,
    _run_observer,
)


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

__all__ = [
    "WATCHDOG_AVAILABLE",
    "QuarantineManager",
    "SessionSafetyScore",
    "ThreadedHTTPServer",
    "DASHBOARD_HTML",
    "GuardianControlHandler",
    "GuardianControlServer",
    "GuardianHandler",
    "DaemonManager",
    "setup_logging",
    "run_guardian",
    "start_shadow_process",
    "stop_shadow_for_repo",
    "stop_guardian_for_repo",
    "stop_guardian_by_id",
    "kill_orphan_guardian_processes",
    "count_running_guardians",
    "guardian_is_running",
    "guardian_persistence_installed",
    "guardian_killed_uncleanly",
    "setup_autostart",
    "setup_hardened_environment",
    "teardown_hardened_environment",
]
