"""
deadpush Guard Mode - The AI Agent Guardian (Production Grade v2)

Major improvements:
- More robust daemon management with lock files and health checks
- Stronger intervention logic (quarantine instead of hard delete, modification blocking)
- Better error recovery
- Strict mode support
- More detailed intervention logging
"""

from __future__ import annotations

import atexit
from collections import deque
import errno
import fcntl
import logging
import os
import shutil
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    Observer = None
    FileSystemEventHandler = None
    WATCHDOG_AVAILABLE = False

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

from .config import load_config
from .config import repo_id as _repo_id
from .debris import DebrisDetector
from .intercept import FEEDBACK_DIR
from .session import SessionManager
from . import state as _state


_HARDENED_STATE_DIR = Path("/var/db/deadpush")
_HARDENED_VENV_DIR = _HARDENED_STATE_DIR / "venv"


def _hardened_python() -> Path:
    return _HARDENED_VENV_DIR / "bin" / "python"


def _deadpush_source_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _find_bootstrap_python() -> str:
    """Python interpreter for creating the hardened venv (must be system-wide)."""
    import shutil
    for candidate in (
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ):
        if Path(candidate).exists():
            return candidate
    found = shutil.which("python3")
    if found:
        return found
    import sys
    return sys.executable


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


def _load_or_create_control_token(repo_root: Path, hardened: bool = False) -> str:
    """Return the control-server bearer token, creating it (0600) if absent.

    In hardened mode the token lives under the root/_deadpush-owned state dir
    with 0600 perms, so a same-UID agent cannot read it and therefore cannot
    call the mutating control endpoints (allowlist changes, quarantine restore).
    In soft mode it is user-owned (the agent could read it) — soft mode is
    deterrence, not a hard boundary — but it still blocks other local users.
    """
    import secrets

    token_file = _scoped_token_file(repo_root, hardened)
    try:
        if token_file.exists():
            existing = token_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing
    except Exception:
        pass
    token = secrets.token_urlsafe(32)
    try:
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token, encoding="utf-8")
        os.chmod(token_file, 0o600)
    except Exception:
        # If we cannot persist the token we still use it in-memory for this run
        # so the endpoints are not left unauthenticated.
        pass
    return token


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


# =============================================================================
# Logging
# =============================================================================
from logging.handlers import RotatingFileHandler  # noqa: E402  (kept beside the logging helpers)

def setup_logging(
    log_file: Optional[Path] = None,
    level=logging.INFO,
    daemon: bool = False,
    hardened: bool = False,
    repo_root: Path | None = None,
):
    """Setup logging.

    In daemon mode: ONLY file logging (headless/silent on stdout/stderr).
    Foreground: file + console.
    Uses RotatingFileHandler (10MB × 5 files) to prevent unbounded growth.
    """
    if log_file is None:
        if repo_root is None:
            log_file = _state_dir(hardened) / "guardian.log"
        else:
            log_file = _scoped_log_file(repo_root, hardened)
        log_file.parent.mkdir(parents=True, exist_ok=True)

    handlers = [RotatingFileHandler(log_file, maxBytes=10_000_000, backupCount=5, encoding="utf-8")]
    if not daemon:
        handlers.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )
    return logging.getLogger("deadpush.guardian")


# =============================================================================
# Improved Daemon Management with Lock File
# =============================================================================
class DaemonManager:
    """Robust daemon management with file locking."""

    def __init__(self, pidfile: Path, lockfile: Optional[Path] = None):
        self.pidfile = pidfile
        self.lockfile = lockfile or pidfile.with_suffix(".lock")
        self.startfile = pidfile.with_suffix(".start")
        self.holderfile = pidfile.with_suffix(".holder")
        self.lock_fd = None
        self.logger = logging.getLogger("deadpush.guardian")

    def acquire_lock(self) -> bool:
        """Try to acquire exclusive lock."""
        try:
            self.lock_fd = open(self.lockfile, "w")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Store holder PID in lock file for diagnostics
            self.lock_fd.seek(0)
            self.lock_fd.write(str(os.getpid()))
            self.lock_fd.flush()
            return True
        except (IOError, OSError):
            if self.lock_fd:
                self.lock_fd.close()
            return False

    def write_pid(self, repo_root: Path | None = None):
        pid = os.getpid()
        with self.pidfile.open("w") as f:
            f.write(str(pid))
        # Store process start time (monotonic nanoseconds since boot)
        start_time = time.clock_gettime(time.CLOCK_MONOTONIC)
        with self.startfile.open("w") as f:
            f.write(str(start_time))
        if repo_root is not None:
            resolved = repo_root.resolve()
            self.holderfile.write_text(str(resolved), encoding="utf-8")
            try:
                from .config import is_hardened_install
                _state.touch_registry(resolved, hardened=is_hardened_install(resolved), running=True)
            except Exception:
                pass
        self.logger.info(f"Daemon started with PID {pid}")

    def _state_files(self) -> tuple[Path, ...]:
        return (
            self.pidfile,
            self.lockfile,
            self.startfile,
            self.holderfile,
            self.pidfile.with_suffix(".repo"),
            self.pidfile.with_suffix(".shadow"),
        )

    def cleanup(self):
        if self.lock_fd:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                self.lock_fd.close()
            except Exception:
                pass
        for f in self._state_files():
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass

    def force_cleanup(self):
        """Force remove all daemon state files (for stale lock recovery)."""
        for f in self._state_files():
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass
        if self.lock_fd:
            try:
                self.lock_fd.close()
            except Exception:
                pass
        self.lock_fd = None

    def get_holder_pid(self) -> Optional[int]:
        """Get PID of current lock holder, if any."""
        if not self.lockfile.exists():
            return None
        try:
            with self.lockfile.open() as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def is_running(self) -> bool:
        if not self.pidfile.exists():
            return False
        try:
            with self.pidfile.open() as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
        except (OSError, ValueError):
            return False

        # Verify process start time matches our recorded start time
        if not self.startfile.exists():
            # No start time recorded (old PID file) - conservative: assume running
            return True
        try:
            with self.startfile.open() as f:
                recorded_start = float(f.read().strip())
        except (OSError, ValueError):
            return True

        # Get actual process start time via ps
        # macOS uses `etime` ([[DD-]hh:]mm:ss), Linux uses `etimes` (seconds)
        try:
            elapsed = None
            for opt in ("etimes=", "etime="):
                r = subprocess.run(
                    ["ps", "-o", opt, "-p", str(pid)],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and r.stdout.strip():
                    out = r.stdout.strip()
                    try:
                        elapsed = int(out)
                    except ValueError:
                        # macOS format: [[DD-]hh:]mm:ss
                        parts = out.split("-")
                        if len(parts) == 2:
                            out = parts[1]
                        tparts = list(map(int, out.split(":")))
                        if len(tparts) == 3:
                            elapsed = tparts[0] * 3600 + tparts[1] * 60 + tparts[2]
                        elif len(tparts) == 2:
                            elapsed = tparts[0] * 60 + tparts[1]
                    break
            if elapsed is not None:
                current_monotonic = time.clock_gettime(time.CLOCK_MONOTONIC)
                actual_start = current_monotonic - elapsed
                # Allow 2 second tolerance for clock resolution differences
                if abs(actual_start - recorded_start) > 2:
                    return False
        except Exception:
            pass  # Conservative: assume running if check fails

        # Additional verification: check command line contains deadpush
        try:
            r = subprocess.run(
                ["ps", "-o", "command=", "-p", str(pid)],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and "deadpush" not in r.stdout:
                return False
        except Exception:
            pass

        return True


# =============================================================================
# Quarantine System (Safer than hard delete)
# =============================================================================
class QuarantineManager:
    """Moves dangerous files to a quarantine folder instead of deleting them."""

    def __init__(self, base_dir: Path):
        self.quarantine_dir = base_dir / ".deadpush-quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("deadpush.guardian")

    def _unique_dest(self, basename: str, timestamp: str) -> Path:
        dest = self.quarantine_dir / f"{timestamp}_{basename}"
        if not dest.exists():
            return dest
        return self.quarantine_dir / f"{timestamp}_{os.getpid()}_{basename}"

    def _write_reason(self, dest: Path, reason: str, original: Path) -> None:
        reason_path = dest.with_suffix(dest.suffix + ".reason")
        reason_path.write_text(
            f"Quarantined at {datetime.now()}\nReason: {reason}\nOriginal path: {original}\n",
            encoding="utf-8",
        )

    def quarantine(self, path: Path, reason: str) -> Path:
        if not path.exists():
            return path

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = self._unique_dest(path.name, timestamp)
        retry_errnos = {errno.EBUSY, errno.EACCES, errno.EPERM}

        for attempt in range(4):
            try:
                shutil.copy2(path, dest)
                self._write_reason(dest, reason, path)
                try:
                    path.unlink()
                except OSError as unlink_err:
                    if unlink_err.errno in retry_errnos:
                        time.sleep(0.05 * (attempt + 1))
                        if not path.exists():
                            return dest
                        continue
                    try:
                        path.write_text("", encoding="utf-8")
                    except OSError:
                        pass
                return dest
            except OSError as e:
                if e.errno in retry_errnos and attempt < 3:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                break

        try:
            path.rename(dest)
            self._write_reason(dest, reason, path)
            return dest
        except Exception as e:
            self.logger.error(f"Failed to quarantine {path}: {e}")
            if dest.exists() and not path.exists():
                return dest
            return path

    def list_quarantined(self):
        """Return list of dicts with info about quarantined files (newest first)."""
        entries = []
        if not self.quarantine_dir.exists():
            return entries
        for f in sorted(self.quarantine_dir.iterdir(), reverse=True):
            if f.name.endswith(".reason"):
                continue
            reason_path = self.quarantine_dir / (f.name + ".reason")
            info = {
                "quarantined_file": f,
                "name": f.name,
                "size": f.stat().st_size if f.exists() else 0,
                "mtime": datetime.fromtimestamp(f.stat().st_mtime) if f.exists() else None,
            }
            if reason_path.exists():
                try:
                    text = reason_path.read_text(errors="ignore")
                    for line in text.splitlines():
                        if line.startswith("Quarantined at "):
                            info["quarantined_at"] = line.split("Quarantined at ", 1)[1]
                        elif line.startswith("Reason: "):
                            info["reason"] = line.split("Reason: ", 1)[1]
                        elif line.startswith("Original path: "):
                            info["original_path"] = line.split("Original path: ", 1)[1]
                except Exception:
                    pass
            entries.append(info)
        return entries

    def restore(self, quarantined_name_or_path: str) -> Path | None:
        """Restore a quarantined file back to its original location if possible.
        Returns the restored path or None on failure.
        """
        qpath = Path(quarantined_name_or_path)
        if not qpath.is_absolute():
            qpath = self.quarantine_dir / qpath.name
        if not qpath.exists() or qpath.name.endswith(".reason"):
            # try finding by name
            candidates = list(self.quarantine_dir.glob(f"*{Path(quarantined_name_or_path).name}*"))
            qpath = next((c for c in candidates if not c.name.endswith(".reason")), None)
            if not qpath:
                return None
        reason_path = self.quarantine_dir / (qpath.name + ".reason")
        original = None
        if reason_path.exists():
            for line in reason_path.read_text(errors="ignore").splitlines():
                if line.startswith("Original path: "):
                    original = Path(line.split("Original path: ", 1)[1].strip())
                    break
        if not original:
            # fallback: strip timestamp_ prefix
            name = qpath.name
            if "_" in name and name.split("_", 1)[0].isdigit():
                original = self.quarantine_dir.parent / name.split("_", 1)[1]
            else:
                original = self.quarantine_dir.parent / name
        # Confine the restore destination to the repo tree. The "Original path"
        # is read from an agent-writable .reason file, so without this a crafted
        # .reason could make the guardian (running as _deadpush in hardened mode)
        # move a file to an arbitrary absolute path — a confused-deputy write.
        repo_root = self.quarantine_dir.parent
        try:
            resolved = original.resolve()
            resolved.relative_to(repo_root.resolve())
        except (ValueError, OSError, RuntimeError):
            logging.getLogger("deadpush.guardian").warning(
                f"Refusing to restore outside the repo: {original}")
            return None
        original = resolved
        if original.exists():
            logging.getLogger("deadpush.guardian").warning(f"Refusing to restore: original already exists at {original}")
            return None
        try:
            original.parent.mkdir(parents=True, exist_ok=True)
            qpath.rename(original)
            if reason_path.exists():
                reason_path.unlink()
            logging.getLogger("deadpush.guardian").info(f"Restored {qpath.name} -> {original}")
            return original
        except Exception as e:
            logging.getLogger("deadpush.guardian").error(f"Restore failed for {qpath}: {e}")
            return None

    def clear(self, older_than_days: int | None = None) -> int:
        """Delete quarantined files (and their .reason). Returns count deleted.
        If older_than_days, only those older than N days.
        """
        count = 0
        if not self.quarantine_dir.exists():
            return 0
        now = datetime.now()
        for f in list(self.quarantine_dir.iterdir()):
            if f.name.endswith(".reason"):
                # will be handled with main file or orphaned cleanup
                try:
                    if older_than_days is None:
                        f.unlink()
                    else:
                        mtime = datetime.fromtimestamp(f.stat().st_mtime)
                        if (now - mtime).days >= older_than_days:
                            f.unlink()
                            count += 1
                    continue
                except Exception:
                    continue
            # main file
            try:
                if older_than_days is not None:
                    mtime = datetime.fromtimestamp(f.stat().st_mtime)
                    if (now - mtime).days < older_than_days:
                        continue
                f.unlink()
                count += 1
                rp = self.quarantine_dir / (f.name + ".reason")
                if rp.exists():
                    rp.unlink()
            except Exception as e:
                logging.getLogger("deadpush.guardian").error(f"Failed clearing {f}: {e}")
        return count


# =============================================================================
# Session Safety Score (Improved)
# =============================================================================
class SessionSafetyScore:
    """Improved Safety Score + simple multi-agent / burst / session tracking.

    Designed for users running many AI agents in parallel who step away.
    - Penalizes bursts of activity ( >3 incidents in 60s window gets extra hit)
    - Tracks total session events and recent unique files for "intelligence"
    - get_activity_level() and get_session_summary() used in logs + status cmd
    """

    def __init__(self, repo_root: Path, hardened: bool = False):
        self.repo_root = repo_root.resolve()
        self.score = 100
        self.incidents = []
        self.recent_window = 60  # seconds
        # Multi-agent / session tracking
        self.events_count = 0
        self.session_start = datetime.now()
        self.recent_paths: list[str] = []  # last ~10 distinct-ish paths touched
        self.hardened = hardened

    def _score_path(self) -> Path:
        """Path to the per-repo safety score JSON file."""
        return _scoped_safety_score_file(self.repo_root, self.hardened)

    def mark_clean_shutdown(self):
        """Mark clean shutdown so restart doesn't apply penalty.

        Saves score with clean_shutdown=True. On next load, the penalty for
        PID mismatch is skipped.
        """
        path = self._score_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            import json
            data = {
                "score": self.score,
                "event_count": self.events_count,
                "guardian_pid": os.getpid(),
                "last_updated": datetime.now().isoformat(),
                "clean_shutdown": True,
            }
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception:
            pass

    def save_score(self):
        """Persist current score to JSON file for MCP server to read."""
        path = self._score_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            import json
            data = {
                "score": self.score,
                "event_count": self.events_count,
                "guardian_pid": os.getpid(),
                "last_updated": datetime.now().isoformat(),
                "clean_shutdown": False,
            }
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception:
            pass

    def load_score(self):
        """Load score from JSON file on startup."""
        path = self._score_path()
        if not path.exists():
            return
        try:
            import json
            data = json.loads(path.read_text(encoding="utf-8"))
            self.score = data.get("score", 100)
            self.events_count = data.get("event_count", 0)
        except Exception:
            pass

    def report_incident(self, severity: int, reason: str, filepath: str = ""):
        now = datetime.now()
        self.score = max(0, self.score - severity)
        self.events_count += 1
        if filepath:
            # keep recent unique-ish
            if filepath not in self.recent_paths:
                self.recent_paths = (self.recent_paths + [filepath])[-10:]

        self.incidents.append({
            "time": now,
            "severity": severity,
            "reason": reason,
            "file": filepath
        })

        # Decay old incidents for recent activity calculation
        self.incidents = [inc for inc in self.incidents if (now - inc["time"]).total_seconds() < self.recent_window]

        # Bonus penalty for high recent activity (multi-agent bursts from parallel Claude/Cursor etc)
        recent_count = len(self.incidents)
        if recent_count > 3:
            extra_penalty = min(5 * (recent_count - 3), 20)
            self.score = max(0, self.score - extra_penalty)
        if recent_count >= 6:
            # Very bursty - many agents firing at once
            self.score = max(0, self.score - 5)

        self.save_score()
        return self.score

    def get_status(self) -> str:
        if self.score >= 90:
            return "🟢 Excellent"
        if self.score >= 70:
            return "🟡 Good"
        if self.score >= 50:
            return "🟠 Caution"
        return "🔴 At Risk"

    def get_activity_level(self) -> str:
        """Simple heuristic for 'how busy are the agents right now?'"""
        recent = len([inc for inc in self.incidents if (datetime.now() - inc["time"]).total_seconds() < self.recent_window])
        if recent >= 8:
            return "🔥 High (multiple agents in parallel?)"
        if recent >= 4:
            return "⚡ Elevated burst"
        return "Normal"

    def get_session_summary(self) -> str:
        dur_min = (datetime.now() - self.session_start).total_seconds() / 60.0
        recent_files = len(set(self.recent_paths))
        return f"Session: {dur_min:.1f}min | Total events: {self.events_count} | Recent files: {recent_files}"

    def get_summary(self) -> str:
        recent = len([inc for inc in self.incidents if (datetime.now() - inc["time"]).total_seconds() < self.recent_window])
        return f"Score: {self.score}/100 | Status: {self.get_status()} | Recent incidents (last 60s): {recent} | Activity: {self.get_activity_level()}"


# =============================================================================
# Local Control Interface (AGENT.md Priority 4 - key new feature for automatic agent interaction)
# Lightweight HTTP server on localhost only. Allows AI coding agents (Claude, Cursor, etc.)
# to query the guardian autonomously for status, score, recent risks, quarantines,
# and even trigger light analysis -- all without the human user having to run commands.
# Started automatically in daemon mode. Uses only stdlib (http.server + threading) for minimal footprint.
# Port is fixed for easy discovery by agents (or written to ~/.deadpush/guardian.control.port).
# All endpoints are read-only or safe actions. No auth needed since localhost only.
# =============================================================================

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads so guardian main loop isn't blocked."""
    daemon_threads = True


DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>deadpush Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #0d1117; color: #c9d1d9; padding: 20px; }}
  h1 {{ color: #58a6ff; margin-bottom: 8px; }}
  h2 {{ color: #8b949e; font-size: 16px; margin: 24px 0 12px;
        border-bottom: 1px solid #30363d; padding-bottom: 6px; }}
  .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 16px; flex: 1; min-width: 200px; }}
  .card h3 {{ color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
  .card .value {{ font-size: 28px; font-weight: 600; margin: 8px 0 0; }}
  .card .value.green {{ color: #3fb950; }}
  .card .value.red {{ color: #f85149; }}
  .card .value.yellow {{ color: #d29922; }}
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 13px; }}
  th {{ color: #8b949e; font-weight: 600; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            font-size: 11px; font-weight: 600; }}
  .badge.blocked {{ background: #f8514920; color: #f85149; }}
  .badge.approved {{ background: #3fb95020; color: #3fb950; }}
  .nav {{ display: flex; gap: 12px; margin: 16px 0; }}
  .nav a {{ color: #58a6ff; text-decoration: none; font-size: 14px; }}
  .nav a:hover {{ text-decoration: underline; }}
  .live {{ color: #3fb950; font-size: 12px; }}
  #live-log {{ max-height: 320px; overflow-y: auto; font-size: 11px; line-height: 1.4;
               background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
               padding: 10px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  #live-log .line {{ white-space: pre-wrap; word-break: break-all; }}
  #live-score {{ margin: 12px 0; }}
  .empty {{ color: #484f58; font-style: italic; padding: 12px; }}
  .actions button {{ background: #21262d; border: 1px solid #30363d; color: #c9d1d9;
                     padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; }}
  .actions button:hover {{ background: #30363d; }}
  pre {{ background: #0d1117; padding: 12px; border-radius: 6px; overflow-x: auto;
         font-size: 12px; border: 1px solid #30363d; }}
  .meta {{ color: #484f58; font-size: 12px; }}
  form {{ margin: 8px 0; }}
  input {{ background: #0d1117; border: 1px solid #30363d; color: #c9d1d9;
           padding: 6px 10px; border-radius: 6px; }}
  .violations {{ margin: 8px 0 0 12px; font-size: 12px; color: #f85149; }}
</style>
</head>
<body>
<h1>deadpush Dashboard</h1>
<p class="meta">Repo: {repo} &middot; Updated: {ts}</p>
<div class="nav">
  <a href="/dashboard">Overview</a>
  <a href="/dashboard/blocks">Blocks</a>
  <a href="/dashboard/quarantine">Quarantine</a>
  <a href="/dashboard/allowlist">Allowlist</a>
  <span class="live" id="live-status">● live</span>
</div>
<div id="live-score"></div>
<h2>Live Log</h2>
<div id="live-log"></div>
<script>
(function() {{
  const logEl = document.getElementById('live-log');
  const scoreEl = document.getElementById('live-score');
  const statusEl = document.getElementById('live-status');
  const es = new EventSource('/dashboard/events');
  es.addEventListener('log', (e) => {{
    const div = document.createElement('div');
    div.className = 'line';
    div.textContent = e.data;
    logEl.appendChild(div);
    logEl.scrollTop = logEl.scrollHeight;
    while (logEl.childNodes.length > 200) logEl.removeChild(logEl.firstChild);
  }});
  es.addEventListener('score', (e) => {{
    scoreEl.innerHTML = '<div class="card"><h3>Safety Score (live)</h3><div class="value">' + e.data + '</div></div>';
  }});
  es.onerror = () => {{ statusEl.textContent = '○ reconnecting…'; statusEl.style.color = '#d29922'; }};
  es.onopen = () => {{ statusEl.textContent = '● live'; statusEl.style.color = '#3fb950'; }};
}})();
</script>
{content}
</body>
</html>"""


class GuardianControlHandler(BaseHTTPRequestHandler):
    """Simple JSON API handler for the guardian control interface."""

    # Reference to the running GuardianControlServer (set by server)
    control_server = None

    def _send_html(self, html: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _send_json(self, obj, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "http://localhost")  # for any local browser tools
        self.end_headers()
        try:
            body = json.dumps(obj, default=str, indent=2).encode("utf-8")
        except Exception:
            body = json.dumps({"error": "serialization failed"}).encode("utf-8")
        self.wfile.write(body)

    def _get_handler(self):
        return self.control_server.guardian_handler if self.control_server else None

    def _verify_token(self) -> bool:
        """Verify Bearer token if token authentication is enabled."""
        server_token = self.control_server.token if self.control_server else None
        if not server_token:
            return True  # No token required
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        provided_token = auth_header[7:]  # Remove "Bearer " prefix
        import hmac
        return hmac.compare_digest(provided_token, server_token)

    def _require_auth(self) -> bool:
        """Check auth and send 401 if failed. Returns True if authorized."""
        if not self._verify_token():
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("WWW-Authenticate", 'Bearer realm="deadpush guardian"')
            self.end_headers()
            self.wfile.write(b'{"error": "unauthorized", "message": "Bearer token required"}')
            return False
        return True

    # ------------------------------------------------------------------
    # Dashboard helpers
    # ------------------------------------------------------------------
    def _read_feedback(self, limit: int = 20) -> list[dict]:
        handler = self._get_handler()
        if not handler:
            return []
        feedback_dir = handler.config.repo_root / FEEDBACK_DIR
        entries = []
        if feedback_dir.exists():
            for f in sorted(feedback_dir.glob("*.json"), reverse=True)[:limit]:
                try:
                    entries.append(json.loads(f.read_text(encoding="utf-8")))
                except Exception:
                    pass
        return entries

    def _read_runtime_config(self) -> dict:
        try:
            from .rules import RuntimeConfig
            handler = self._get_handler()
            if not handler:
                return {}
            rc = RuntimeConfig(handler.config.repo_root)
            return rc.to_dict()
        except Exception:
            return {}

    def _dashboard_page(self, content: str) -> str:
        handler = self._get_handler()
        repo = str(handler.config.repo_root) if handler else "?"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        return DASHBOARD_HTML.format(repo=repo, ts=ts, content=content)

    def _handle_dashboard(self, subpath: str):
        handler = self._get_handler()
        if not handler:
            return self._send_html("<h1>Guardian not ready</h1>", 503)

        if subpath == "" or subpath == "/":
            feedback = self._read_feedback(limit=5)
            blocks = [e for e in feedback if e.get("status") == "blocked"]
            approvals = [e for e in feedback if e.get("status") == "approved"]
            quarantine = handler.quarantine.list_quarantined()
            score = handler.safety_score

            cards = f"""
<div class="summary">
  <div class="card"><h3>Recent Blocks</h3><div class="value red">{len(blocks)}</div></div>
  <div class="card"><h3>Recent Approvals</h3><div class="value green">{len(approvals)}</div></div>
  <div class="card"><h3>Quarantined</h3><div class="value yellow">{len(quarantine)}</div></div>
  <div class="card"><h3>Safety Score</h3><div class="value">{score.get_summary()}</div></div>
</div>"""

            config = self._read_runtime_config()
            allowed = config.get("allowed_patterns", [])
            levels = config.get("guardrail_levels", {})
            config_section = f"""
<h2>Runtime Configuration</h2>
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>Allowed Patterns</td><td>{len(allowed)} pattern(s)</td></tr>
  <tr><td>Ignored Paths</td><td>{len(config.get('ignored_paths', []))} path(s)</td></tr>
  <tr><td>Guardrail Levels</td><td>{', '.join(f'{k}={v}' for k, v in levels.items()) if levels else 'all defaults'}</td></tr>
  <tr><td>Activity Level</td><td>{score.get_activity_level()}</td></tr>
</table>"""

            recent_rows = ""
            for e in feedback:
                recent_rows += f"""<tr>
  <td>{e.get('file', '?')}</td>
  <td><span class="badge {e.get('status', 'approved')}">{e.get('status', '?')}</span></td>
  <td>{len(e.get('violations', []))}</td>
  <td class="meta">{e.get('timestamp', '').replace('T', ' ')[:19]} UTC</td>
</tr>"""
            recent_section = f"""
<h2>Recent Activity</h2>
<table>
  <tr><th>File</th><th>Status</th><th>Violations</th><th>Time</th></tr>
  {recent_rows}
</table>""" if feedback else ""

            self._send_html(self._dashboard_page(cards + recent_section + config_section))

        elif subpath == "/blocks":
            feedback = self._read_feedback(limit=50)
            blocks = [e for e in feedback if e.get("status") == "blocked"]
            if not blocks:
                content = '<p class="empty">No blocked files yet.</p>'
            else:
                rows = ""
                for e in blocks:
                    violations_html = "".join(
                        f'<div class="violations">\\u2022 {v.get("category")}: {v.get("description")} (line {v.get("line")}, {v.get("severity")})</div>'
                        for v in e.get("violations", [])
                    )
                    diff = e.get("diff", "(no diff)")
                    rows += f"""<tr>
  <td>{e.get('file', '?')}</td>
  <td>{violations_html}<details><summary class="meta">Show diff</summary><pre>{diff}</pre></details></td>
  <td class="meta">{e.get('timestamp', '').replace('T', ' ')[:19]} UTC</td>
</tr>"""
                content = f"""<h2>Blocked Files</h2>
<p class="meta">{len(blocks)} block(s)</p>
<table><tr><th>File</th><th>Violations / Diff</th><th>Time</th></tr>{rows}</table>"""
            self._send_html(self._dashboard_page(content))

        elif subpath == "/quarantine":
            entries = handler.quarantine.list_quarantined()
            if not entries:
                content = '<p class="empty">No quarantined files.</p>'
            else:
                rows = ""
                for e in entries:
                    rows += f"""<tr>
  <td>{e.get('name', '?')}</td>
  <td>{e.get('original_path', '?')}</td>
  <td>{e.get('reason', e.get('violations', 'N/A'))}</td>
  <td class="actions">
    <form action="/dashboard/quarantine/restore" method="post" style="display:inline">
      <input type="hidden" name="name" value="{e.get('name', '')}">
      <button type="submit">Restore</button>
    </form>
  </td>
</tr>"""
                content = f"""<h2>Quarantine Manager</h2>
<p class="meta">{len(entries)} quarantined file(s)</p>
<table><tr><th>Name</th><th>Original Path</th><th>Reason</th><th>Action</th></tr>{rows}</table>"""
            self._send_html(self._dashboard_page(content))

        elif subpath == "/allowlist":
            config = self._read_runtime_config()
            patterns = config.get("allowed_patterns", [])
            levels = config.get("guardrail_levels", {})

            if patterns:
                rows = ""
                for p in patterns:
                    rows += f"""<tr>
  <td>{p.get('pattern', '?')}</td>
  <td>{p.get('description', '')}</td>
  <td class="actions"><form action="/dashboard/allowlist/remove" method="post" style="display:inline">
    <input type="hidden" name="pattern" value="{p.get('pattern', '')}">
    <button type="submit">Remove</button>
  </form></td>
</tr>"""
                patterns_html = f"""<h3>Allowed Patterns ({len(patterns)})</h3>
<table><tr><th>Pattern</th><th>Description</th><th>Action</th></tr>{rows}</table>"""
            else:
                patterns_html = '<p class="empty">No allowed patterns.</p>'

            level_rows = "".join(
                f"<tr><td>{cat}</td><td>{lvl}</td></tr>"
                for cat, lvl in sorted(levels.items())
            ) if levels else '<tr><td colspan="2"><span class="empty">All defaults</span></td></tr>'

            content = f"""{patterns_html}
<form action="/dashboard/allowlist/add" method="post">
  <input type="text" name="pattern" placeholder="regex pattern" required>
  <input type="text" name="description" placeholder="description (optional)">
  <button type="submit">Add Pattern</button>
</form>
<h3>Guardrail Levels</h3>
<table><tr><th>Category</th><th>Level</th></tr>{level_rows}</table>
<form action="/dashboard/allowlist/reset" method="post">
  <button type="submit" style="background:#f8514920;border:1px solid #f85149;color:#f85149;padding:6px 14px;border-radius:6px;cursor:pointer">Reset All Config</button>
</form>"""
            self._send_html(self._dashboard_page(content))

        else:
            self._send_json({"error": "unknown dashboard page"}, 404)

    def _handle_sse_events(self):
        """Server-Sent Events: live log tail + safety score updates."""
        handler = self._get_handler()
        if not handler:
            return self._send_json({"error": "guardian not ready"}, 503)

        from .config import is_hardened_install

        repo_root = handler.config.repo_root
        hardened = is_hardened_install(repo_root)
        log_path = _scoped_log_file(repo_root, hardened)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def _emit(event: str, data: str) -> bool:
            try:
                safe = data.replace("\n", " ").replace("\r", "")
                self.wfile.write(f"event: {event}\ndata: {safe}\n\n".encode("utf-8"))
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError):
                return False

        # Bootstrap: last 40 log lines
        if log_path.exists():
            try:
                text = log_path.read_text(errors="ignore")
                for line in text.strip().splitlines()[-40:]:
                    if not _emit("log", line):
                        return
            except OSError:
                pass

        pos = log_path.stat().st_size if log_path.exists() else 0
        last_score = ""
        while True:
            score = handler.safety_score.get_summary()
            if score != last_score:
                last_score = score
                if not _emit("score", score):
                    return

            if log_path.exists():
                try:
                    size = log_path.stat().st_size
                    if size > pos:
                        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
                            f.seek(pos)
                            chunk = f.read()
                        pos = size
                        for line in chunk.splitlines():
                            if line.strip() and not _emit("log", line):
                                return
                except OSError:
                    pass

            time.sleep(1.0)

    def do_GET(self):
        # Reads (status/dashboard/quarantine-list) stay open on localhost; only
        # state-changing POSTs require the token. This keeps the human dashboard
        # viewable while blocking the agent from mutating policy or restoring
        # quarantined files (see do_POST -> _require_auth).
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path.rstrip("/")

        handler = self._get_handler()
        if not handler:
            return self._send_json({"error": "guardian not ready"}, 503)

        try:
            if path in ("/", "/status"):
                score = handler.safety_score
                data = {
                    "running": True,
                    "safety_score": score.get_summary(),
                    "activity_level": score.get_activity_level(),
                    "session_summary": score.get_session_summary(),
                    "recent_incidents_count": len([i for i in score.incidents if (datetime.now() - i["time"]).total_seconds() < score.recent_window]),
                    "quarantine_count": len(handler.quarantine.list_quarantined()),
                    "intervention_enabled": handler.intervention,
                    "strict_mode": handler.strict_mode,
                    "fanotify": handler.fanotify_status(),
                }
                self._send_json(data)
            elif path == "/safety-score":
                self._send_json({"safety_score": handler.safety_score.get_summary(), "details": handler.safety_score.get_session_summary()})
            elif path == "/recent-incidents":
                limit = int(qs.get("limit", [10])[0])
                recent = handler.safety_score.incidents[-limit:]
                self._send_json({"incidents": recent})
            elif path == "/quarantine-list":
                limit = int(qs.get("limit", [20])[0])
                qlist = handler.quarantine.list_quarantined()[:limit]
                self._send_json({"quarantined": qlist, "dir": str(handler.quarantine.quarantine_dir)})
            elif path == "/health":
                self._send_json({"status": "ok", "guardian": "alive"})
            elif path.startswith("/dashboard"):
                subpath = path[len("/dashboard"):]
                if subpath in ("", "/") or subpath.startswith("/blocks") or subpath.startswith("/quarantine") or subpath.startswith("/allowlist"):
                    self._handle_dashboard(subpath)
                elif subpath == "/events":
                    self._handle_sse_events()
                else:
                    self._handle_dashboard(subpath)
            else:
                self._send_json({"error": "unknown endpoint", "available": ["/status", "/safety-score", "/recent-incidents", "/quarantine-list", "/health", "/dashboard"]}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_dashboard_post(self, path: str, params: dict[str, str]):
        handler = self._get_handler()
        if not handler:
            return self._send_json({"error": "guardian not ready"}, 503)

        try:
            from .rules import RuntimeConfig
            rc = RuntimeConfig(handler.config.repo_root)

            if path == "/quarantine/restore":
                name = params.get("name", "")
                if name:
                    handler.quarantine.restore(name)
                    handler._gpc_policy_update(f"Quarantine restore: {name}", file=name)
                self._redirect("/dashboard/quarantine")
                return

            elif path == "/allowlist/add":
                pattern = params.get("pattern", "")
                description = params.get("description", "")
                if pattern:
                    rc.add_allowed_pattern(pattern, description)
                    handler._gpc_policy_update(
                        f"Allowlist pattern added: {pattern}",
                        pattern=pattern,
                        description=description,
                    )
                self._redirect("/dashboard/allowlist")
                return

            elif path == "/allowlist/remove":
                pattern = params.get("pattern", "")
                if pattern:
                    rc.remove_allowed_pattern(pattern)
                    handler._gpc_policy_update(
                        f"Allowlist pattern removed: {pattern}",
                        pattern=pattern,
                    )
                self._redirect("/dashboard/allowlist")
                return

            elif path == "/allowlist/reset":
                rc.reset()
                handler._gpc_policy_update("Allowlist reset to defaults")
                self._redirect("/dashboard/allowlist")
                return

        except Exception as e:
            self._send_json({"error": str(e)}, 500)
            return

        self._redirect("/dashboard")

    def _redirect(self, path: str):
        self.send_response(302)
        self.send_header("Location", path)
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self):
        if not self._require_auth():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Handle dashboard form posts
        if path.startswith("/dashboard"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else ""
            params = {}
            if body:
                for pair in body.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        from urllib.parse import unquote_plus
                        params[unquote_plus(k)] = unquote_plus(v)
            self._handle_dashboard_post(path[len("/dashboard"):], params)
            return

        handler = self._get_handler()
        if not handler:
            return self._send_json({"error": "guardian not ready"}, 503)

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            payload = json.loads(body) if body.strip() else {}

            if path == "/trigger-light-analysis":
                result = {
                    "message": "Light analysis triggered. Current guardian state returned.",
                    "safety": handler.safety_score.get_summary(),
                    "quarantine_count": len(handler.quarantine.list_quarantined()),
                    "recommendation": "Use /quarantine-list for details. Run `deadpush doctor` for a full health check.",
                }
                self._send_json(result)
            elif path == "/quarantine/restore":
                qname = payload.get("path") or payload.get("name")
                if not qname:
                    return self._send_json({"error": "missing 'path' in payload"}, 400)
                restored = handler.quarantine.restore(qname)
                if restored:
                    handler._gpc_policy_update(f"Quarantine restore: {qname}", file=qname)
                    self._send_json({"success": True, "restored_to": str(restored)})
                else:
                    self._send_json({"success": False, "error": "restore failed or original exists"}, 409)
            else:
                self._send_json({"error": "unknown action", "supported_post": ["/trigger-light-analysis", "/quarantine/restore"]}, 404)
        except json.JSONDecodeError:
            self._send_json({"error": "invalid json body"}, 400)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def log_message(self, format, *args):
        # Silent by default (agents don't need our access logs). Can be verbose in debug.
        pass


class GuardianControlServer:
    """Manages the lightweight local HTTP control interface for AI agents.

    Uses a small range of ports starting from DEFAULT_PORT for reliability
    (avoids conflicts if multiple instances or previous unclean shutdowns).
    Writes the actual port to ~/.deadpush/guardian.control.port for agents
    to discover easily.
    """

    DEFAULT_PORT = 14242
    PORT_RANGE = 5  # try up to 5 ports

    def __init__(self, guardian_handler, port: int | None = None, repo_root: Path | None = None, hardened: bool = False, token: str | None = None):
        self.guardian_handler = guardian_handler
        self.requested_port = port or self.DEFAULT_PORT
        self.port = None
        self.httpd = None
        self.thread = None
        self.logger = logging.getLogger("deadpush.guardian")
        self.token = token
        self.require_auth = token is not None
        if repo_root:
            self.port_file = _scoped_portfile(repo_root, hardened)
        else:
            self.port_file = _state_dir(hardened) / "guardian.control.port"

    def start(self):
        if self.httpd:
            return

        handler_class = type(
            "BoundGuardianControlHandler",
            (GuardianControlHandler,),
            {"control_server": self}
        )

        self.port = None
        for offset in range(self.PORT_RANGE):
            candidate = self.requested_port + offset
            try:
                self.httpd = ThreadedHTTPServer(("127.0.0.1", candidate), handler_class)
                self.port = candidate
                self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="GuardianControlHTTP")
                self.thread.start()
                self.port_file.parent.mkdir(parents=True, exist_ok=True)
                self.port_file.write_text(str(self.port))
                self.logger.info(f"Local control interface started: http://127.0.0.1:{self.port} (for AI agents)")
                return
            except OSError as e:
                if e.errno == 48:  # Address already in use
                    self.logger.warning(f"Port {candidate} in use, trying next...")
                    continue
                else:
                    self.logger.error(f"Failed to bind control interface on port {candidate}: {e}")
                    break
            except Exception as e:
                self.logger.error(f"Failed to start local control interface on port {candidate}: {e}")
                break

        self.httpd = None
        self.logger.error(f"Could not start local control interface on any port in range {self.requested_port}-{self.requested_port + self.PORT_RANGE - 1}")

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        if self.port_file.exists():
            try:
                self.port_file.unlink()
            except Exception:
                pass
        self.logger.debug("Local control interface stopped.")


# =============================================================================
# Enhanced Guardian Handler with Stronger Intervention
# =============================================================================
class GuardianHandler(FileSystemEventHandler or object):
    """Real-time guardian with unified guardrail pipeline.

    Uses the full 7-category guardrails from intercept.py:
    - Watches the entire repo root via watchdog
    - Every file write goes through _run_guardrails
    - Block-level violations → quarantine + git restore + structured feedback
    """

    def __init__(self, config, intervention: bool = True, strict_mode: bool = False, daemon: bool = False, logger=None, hardened: bool = False, *, enable_fanotify: bool = True):
        self.config = config
        self.intervention = intervention
        self.strict_mode = strict_mode
        self.daemon = daemon
        self.hardened = hardened
        self.enable_fanotify = enable_fanotify
        self.logger = logger or logging.getLogger("deadpush.guardian")
        self.detector = DebrisDetector(config)
        self.quarantine = QuarantineManager(config.repo_root)
        self.safety_score = SessionSafetyScore(config.repo_root, hardened=hardened)
        self.safety_score.load_score()
        self.session_mgr = SessionManager()
        self.gpc = None  # GpcServer, started by run_guardian
        self._fanotify_backend = None

        # Dynamic rate limiting (based on safety score)
        self.last_intervention_ts = 0.0
        self._pending_events: deque[tuple[Path, str]] = deque()
        self._last_hook_repair_ts = 0.0
        self._last_hook_problems_key = ""

        # Shadow process (watching for crashes)
        self.shadow_process: subprocess.Popen | None = None

        # Out-of-band commit detection (git plumbing / --no-verify bypass the hooks).
        # We poll HEAD each loop and independently re-scan any new commit.
        self._last_head: str | None = None
        self._scanned_commits: set[str] = set()

    def fanotify_status(self) -> dict | None:
        if self._fanotify_backend is None:
            return None
        return self._fanotify_backend.describe()

    def _start_fanotify(self) -> None:
        if not self.enable_fanotify or self._fanotify_backend is not None:
            return
        if not sys.platform.startswith("linux"):
            return
        try:
            from .backends.linux import LinuxEnforcementBackend

            backend = LinuxEnforcementBackend(
                self.config.repo_root,
                on_deny=self._handle_fanotify_deny,
            )
            if not backend.available():
                self.logger.info(
                    "fanotify pre-write deny unavailable (%s); watchdog-only on Linux",
                    backend._last_error or "needs Linux 5.13+ and CAP_SYS_ADMIN",
                )
                return
            backend.start(self.config.repo_root)
            self._fanotify_backend = backend
            self.logger.info(
                "fanotify pre-write deny listener starting (T2-max); "
                "watchdog remains as post-write fallback"
            )
        except Exception as e:
            self.logger.warning("Could not start fanotify backend: %s", e)

    def _stop_fanotify(self) -> None:
        if self._fanotify_backend is None:
            return
        try:
            self._fanotify_backend.stop()
        except Exception:
            pass
        self._fanotify_backend = None

    def _handle_fanotify_deny(self, rel: str, reason: str, source: str) -> None:
        """Record a kernel-level write denial (write never landed on disk)."""
        from .intercept import GuardrailResult, Violation, _write_feedback, FEEDBACK_DIR

        self.last_intervention_ts = time.time()
        score = self.safety_score.report_incident(
            15, f"Fanotify deny: {reason}", rel,
        )
        result = GuardrailResult()
        result.reject(Violation("fanotify", reason, 0, "critical"))

        self.logger.warning(
            f"FANOTIFY DENY [{source.upper()}] {rel} | {reason} | Safety: {score}/100"
        )

        try:
            _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
        except Exception:
            pass
        try:
            self.session_mgr.record_incident({
                "type": "fanotify_deny",
                "file": rel,
                "reason": reason,
                "source": source,
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass
        if self.gpc is not None:
            try:
                self.gpc.emit_incident(category="fanotify", description=reason, file=rel)
            except Exception:
                pass
        self._record_audit("fanotify.deny", {
            "file": rel,
            "reason": reason,
            "source": source,
            "score": score,
        })

    def _get_cooldown(self) -> float:
        """Dynamic cooldown based on safety score.

        Lower score = shorter cooldown = more vigilant checking.
        """
        score = self.safety_score.score
        if score >= 80:
            return 1.0
        elif score >= 50:
            return 0.5
        elif score >= 20:
            return 0.2
        else:
            return 0.05

    def on_created(self, event):
        if event.is_directory:
            return
        self._evaluate(Path(event.src_path), event_type="created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._evaluate(Path(event.src_path), event_type="modified")

    def on_moved(self, event):
        # A rename/move can drop UN-SCANNED content into the repo: e.g. stage a
        # payload in a skipped dir (node_modules/.git) then `mv` it into place, or
        # rename a benign file onto a dangerous path/name. on_created/on_modified
        # never fire for the destination, so evaluate it exactly like a fresh write.
        if event.is_directory:
            return
        dest = getattr(event, "dest_path", None)
        if not dest:
            return
        self._evaluate(Path(dest), event_type="moved")

    def on_deleted(self, event):
        # A deleted file's bytes are already gone (nothing to quarantine), and
        # auto-restoring would fight legitimate refactors/`git rm`. Because the
        # safety score never recovers and has a burst multiplier, penalizing every
        # delete would false-trigger lockdown during normal multi-file deletes.
        # So treat rm as forensic telemetry only: log it + record a session
        # incident, without touching the safety score. Tracked files remain
        # recoverable from git history.
        if event.is_directory:
            return
        self._handle_deletion(Path(event.src_path))

    # ------------------------------------------------------------------
    # Shadow process lifecycle
    # ------------------------------------------------------------------
    def _start_shadow(self):
        if not self.daemon:
            return
        if self.shadow_process is not None and self._shadow_alive():
            return
        pidfile = _scoped_pidfile(self.config.repo_root, self.hardened)
        # Use the deadpush_bootstrap entrypoint (installed as a top-level module)
        # rather than "-m deadpush.cli": in editable installs the deadpush package
        # may be reachable only via a .pth that macOS marks hidden (and Python 3.12+
        # then skips), so "-m deadpush.cli" fails from a non-source cwd. The bootstrap
        # repairs sys.path first. For normal pip installs this is equivalent.
        respawn_cmd = [sys.executable, "-m", "deadpush_bootstrap", "guard", "--daemon"]
        if self.hardened:
            respawn_cmd.append("--hardened")
        proc = start_shadow_process(os.getpid(), pidfile, respawn_cmd, self.config.repo_root)
        if proc is not None:
            self.shadow_process = proc
            self.logger.info("Shadow process started (will re-spawn guardian on crash)")

    def _shadow_alive(self) -> bool:
        if self.shadow_process is None:
            return False
        return self.shadow_process.poll() is None

    def _check_shadow(self):
        if not self.daemon:
            return
        if self.shadow_process is None:
            self._start_shadow()
        elif not self._shadow_alive():
            self.logger.warning("Shadow process died, restarting...")
            self._start_shadow()

    def _stop_shadow(self) -> None:
        """Terminate the per-repo shadow watchdog (prevents respawn after stop)."""
        if self.shadow_process is not None:
            try:
                if self.shadow_process.poll() is None:
                    self.shadow_process.terminate()
                    self.shadow_process.wait(timeout=3)
            except Exception:
                try:
                    self.shadow_process.kill()
                except Exception:
                    pass
            self.shadow_process = None
        stop_shadow_for_repo(self.config.repo_root, self.hardened)

    def _check_hook_integrity(self) -> None:
        """Detect and repair tampered or missing deadpush git hooks."""
        try:
            from .hooks import repair_deadpush_hooks, verify_hooks_installed

            problems = verify_hooks_installed(self.config.repo_root)
            if not problems:
                self._last_hook_problems_key = ""
                return

            key = "|".join(sorted(problems))
            now = time.time()
            # Avoid hot-looping when re-lock/reinstall cannot fix the issue (e.g. uchg
            # unsupported, or hooks cleared repeatedly by an external tool).
            if (
                key == self._last_hook_problems_key
                and (now - self._last_hook_repair_ts) < 30.0
            ):
                return

            self.logger.warning(f"Hook integrity issue(s): {', '.join(problems)} — repairing")
            repaired = repair_deadpush_hooks(self.config.repo_root)
            self._last_hook_repair_ts = now
            self._last_hook_problems_key = key
            if repaired:
                self.logger.info(f"Reinstalled hooks: {', '.join(repaired)}")
            remaining = verify_hooks_installed(self.config.repo_root)
            if remaining and remaining == problems:
                self.logger.warning(
                    "Hook repair did not resolve: %s (will retry after cooldown)",
                    ", ".join(remaining),
                )
        except Exception as e:
            self.logger.debug(f"Hook integrity check skipped: {e}")

    # ------------------------------------------------------------------
    # Out-of-band commit detection (git plumbing / --no-verify bypass)
    # ------------------------------------------------------------------
    def _git_head(self) -> str | None:
        """Current HEAD commit sha, or None (unborn branch / not a repo)."""
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", "HEAD"],
                capture_output=True, text=True, timeout=5, cwd=self.config.repo_root,
            )
            return r.stdout.strip() or None
        except Exception:
            return None

    def _check_head_commit(self) -> None:
        """Detect commits that bypassed the hooks and re-enforce on them.

        The pre-commit/pre-push hooks only fire for git *porcelain*; `git commit-tree`
        + `git update-ref` (and `git commit --no-verify`) advance HEAD with no hook,
        and nothing else watches HEAD. Polling it here is the one commit-time layer a
        same-UID agent cannot dodge by choosing a different git command. Every new
        commit is re-scanned with the same enforcement kernel; because a hook-approved
        commit never carries block-level violations, any commit that reaches HEAD *with*
        them must have bypassed the hooks — so it is handled as an out-of-band bypass.
        """
        try:
            head = self._git_head()
            if not head:
                return
            if self._last_head is None:
                # First observation: adopt current HEAD as baseline; don't rescan history.
                self._last_head = head
                return
            if head == self._last_head or head in self._scanned_commits:
                return
            prev = self._last_head
            self._scanned_commits.add(head)
            self._last_head = head
            self._inspect_commit(head, prev)
        except Exception as e:
            self.logger.debug(f"HEAD check error: {e}")

    def _commit_changed_paths(self, sha: str) -> list[str]:
        """Paths introduced/modified by a commit (root commits handled via --root)."""
        try:
            r = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha],
                capture_output=True, text=True, timeout=15, cwd=self.config.repo_root,
            )
            if r.returncode != 0:
                return []
            return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        except Exception:
            return []

    def _git_show_at(self, sha: str, rel: str) -> str | None:
        try:
            r = subprocess.run(
                ["git", "show", f"{sha}:{rel}"],
                capture_output=True, text=True, timeout=5, cwd=self.config.repo_root,
            )
            return r.stdout if r.returncode == 0 else None
        except Exception:
            return None

    def _scan_commit(self, sha: str) -> dict[str, Any]:
        """{rel_path: GuardrailResult} for files in a commit with BLOCK-level violations."""
        from .intercept import enforce_content, is_enforceable_path
        from .rules import RuntimeConfig

        runtime = RuntimeConfig(self.config.repo_root)
        offending: dict[str, Any] = {}
        for rel in self._commit_changed_paths(sha):
            if not is_enforceable_path(rel):
                continue
            content = self._git_show_at(sha, rel)
            if content is None:
                continue
            try:
                result = enforce_content(rel, content, self.config, runtime)
            except Exception:
                continue
            if not result.allowed:
                offending[rel] = result
        return offending

    def _is_linear_child(self, sha: str, prev: str) -> bool:
        """True when `sha` is a single-parent commit directly on top of `prev`, so
        `git reset --soft prev` cleanly undoes exactly it (and nothing else)."""
        try:
            r = subprocess.run(
                ["git", "rev-list", "--parents", "-n", "1", sha],
                capture_output=True, text=True, timeout=5, cwd=self.config.repo_root,
            )
            if r.returncode != 0:
                return False
            parts = r.stdout.split()  # "<sha> <parent1> [<parent2> ...]"
            return len(parts) == 2 and parts[1] == prev
        except Exception:
            return False

    def _reset_soft(self, target: str) -> bool:
        """Undo the tip commit non-destructively (all changes stay staged)."""
        try:
            r = subprocess.run(
                ["git", "reset", "--soft", target],
                capture_output=True, text=True, timeout=10, cwd=self.config.repo_root,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _inspect_commit(self, sha: str, prev: str) -> None:
        """Re-enforce a newly observed commit; act if it bypassed the hooks."""
        offending = self._scan_commit(sha)
        if not offending:
            return

        n_viol = sum(len(r.violations) for r in offending.values())
        top = next(iter(offending.values())).violations[0].description
        self.logger.critical(
            f"OUT-OF-BAND COMMIT {sha[:8]} bypassed git hooks: "
            f"{n_viol} block-level violation(s) in {len(offending)} file(s) — top: {top}"
        )
        score = self.safety_score.report_incident(
            min(50, 10 * len(offending)),
            f"Out-of-band commit {sha[:8]} bypassed hooks ({n_viol} violations)",
            sha,
        )

        # Undo the sneaky commit when it is a clean linear advance: `git reset --soft`
        # keeps every change staged, so nothing is lost — the payload is quarantined
        # out of the worktree/index below. Non-linear moves (merge/rebase/pull/reset)
        # are quarantined + alerted but never auto-rewound (too destructive to assume).
        reverted = False
        if self._is_linear_child(sha, prev):
            reverted = self._reset_soft(prev)
            if reverted:
                self._last_head = prev
                self._scanned_commits.add(prev)
                self.logger.warning(
                    f"Reverted out-of-band commit {sha[:8]} (git reset --soft {prev[:8]})"
                )

        # HEAD is now back at the parent; quarantine each payload file and restore the
        # safe version — the same path a real-time block takes.
        for rel, result in offending.items():
            path = self.config.repo_root / rel
            try:
                self._quarantine_and_restore(path, rel, result)
            except Exception as e:
                self.logger.error(f"Failed to quarantine out-of-band file {rel}: {e}")

        try:
            self.session_mgr.record_incident({
                "type": "out_of_band_commit",
                "commit": sha,
                "reverted": reverted,
                "files": list(offending.keys()),
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # MCP suspension (disables agent's MCP access when score is critical)
    # ------------------------------------------------------------------
    def _record_audit(self, event: str, payload: dict) -> None:
        try:
            from .audit import append_audit_event
            append_audit_event(self.config.repo_root, event, payload)
        except Exception:
            pass

    def _gpc_policy_update(self, summary: str, **extra) -> None:
        self._record_audit("policy.update", {"summary": summary, **extra})
        if self.gpc is None:
            return
        try:
            self.gpc.emit_policy_update(summary, **extra)
        except Exception:
            pass

    def _gpc_maybe_instruction(self) -> None:
        """Emit INSTRUCTION when agents trigger repeated violations in a short window."""
        if self.gpc is None:
            return
        recent = len(self.safety_score.incidents)
        if recent < 3:
            return
        try:
            self.gpc.emit_instruction(
                "Repeated guardrail violations detected. Stop weakening protections; "
                "review feedback and restore quarantined files before continuing.",
                recent_incidents=recent,
                score=self.safety_score.score,
            )
        except Exception:
            pass

    def _suspend_mcp(self, reason: str):
        """Write a suspension flag that the MCP server checks at startup."""
        suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
        try:
            suspend_file.parent.mkdir(parents=True, exist_ok=True)
            suspend_file.write_text(reason, encoding="utf-8")
            self.logger.warning(f"MCP suspended: {reason}")
            self._record_audit("session.pause", {"reason": reason, "score": self.safety_score.score})
            if self.gpc is not None:
                try:
                    self.gpc.emit_session_pause(reason, score=self.safety_score.score)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Failed to write MCP suspension file: {e}")

    def _unsuspend_mcp(self):
        """Remove the suspension flag so MCP can start again."""
        suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
        try:
            if suspend_file.exists():
                suspend_file.unlink()
                self.logger.info("MCP unsuspended")
                self._gpc_policy_update(
                    "MCP access restored",
                    score=self.safety_score.score,
                )
        except Exception as e:
            self.logger.error(f"Failed to remove MCP suspension file: {e}")

    def _check_suspension(self):
        """Periodic check: suspend MCP if score <= 5, unsuspend if recovered."""
        if self.safety_score.score <= 5:
            suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
            if not suspend_file.exists():
                self._suspend_mcp(
                    f"Safety score dropped to {self.safety_score.score}/100. "
                    "Agent weakened guardrails repeatedly."
                )
        elif self.safety_score.score > 10:
            self._unsuspend_mcp()

    # ------------------------------------------------------------------
    # Git helpers for old-source retrieval and file restoration
    # ------------------------------------------------------------------
    def _git_show(self, rel: str) -> str:
        """Get file content from git HEAD. Returns empty string if missing."""
        try:
            result = subprocess.run(
                ["git", "show", f"HEAD:{rel}"],
                capture_output=True, text=True, timeout=5,
                cwd=self.config.repo_root,
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
        return ""

    def _safe_git_source(self, rel: str) -> str | None:
        """Return HEAD content only if it passes guardrails (safe to restore)."""
        source = self._git_show(rel)
        if not source:
            return None
        from .intercept import enforce_content
        from .rules import RuntimeConfig

        runtime = RuntimeConfig(self.config.repo_root)
        result = enforce_content(rel, source, self.config, runtime)
        if not result.allowed:
            self.logger.warning(
                f"Refusing git restore for {rel}: HEAD content also violates guardrails"
            )
            return None
        return source

    def _unstage_if_staged(self, rel: str) -> None:
        """Remove a file from the git index if it is staged."""
        try:
            check = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--", rel],
                capture_output=True, text=True, timeout=5,
                cwd=self.config.repo_root,
            )
            if check.returncode != 0 or rel not in {
                line.strip() for line in check.stdout.splitlines() if line.strip()
            }:
                return
            subprocess.run(
                ["git", "rm", "--cached", "-f", "--", rel],
                capture_output=True, text=True, timeout=5,
                cwd=self.config.repo_root,
            )
            self.logger.info(f"Unstaged {rel} from git index")
        except Exception as e:
            self.logger.debug(f"Unstage skipped for {rel}: {e}")

    def _restore_from_git(self, rel: str) -> bool:
        """Restore a file from git HEAD when HEAD content is safe."""
        old = self._safe_git_source(rel)
        if old is None:
            try:
                dest = self.config.repo_root / rel
                if dest.exists():
                    dest.unlink()
                    self.logger.info(f"Removed {rel} (no safe git version to restore)")
            except Exception as e:
                self.logger.debug(f"Could not remove unsafe file {rel}: {e}")
            return False
        try:
            dest = self.config.repo_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(old, encoding="utf-8")
            self.logger.info(f"Restored {rel} from git HEAD (reverted agent write)")
            return True
        except Exception as e:
            self.logger.error(f"Failed to restore {rel} from git: {e}")
            return False

    # ------------------------------------------------------------------
    # Main evaluation pipeline (called on every file create/modify)
    # ------------------------------------------------------------------
    def _evaluate(self, path: Path, event_type: str):
        try:
            if not path.exists():
                return
            # Skip internal dirs
            skip_names = {"__pycache__", ".git", "node_modules", ".deadpush",
                          ".deadpush-quarantine", ".deadpush-archive",
                          ".deadpush-config-backups"}
            if any(part in skip_names for part in path.parts):
                return

            # Dynamic rate limiting: queue events during cooldown, drain when ready
            now = time.time()
            cooldown = self._get_cooldown()
            if now - self.last_intervention_ts < cooldown:
                self._pending_events.append((path, event_type))
                return

            # Drain queued events first (from previous bursts)
            self._drain_pending()

            # Process the current event
            self._process_event(path, event_type)

        except Exception as e:
            self.logger.debug(f"Evaluation error on {path}: {e}")

    def _drain_pending(self):
        """Process all events queued during cooldown."""
        while self._pending_events:
            p, et = self._pending_events.popleft()
            if p.exists():
                try:
                    self._process_event(p, et)
                except Exception as e:
                    self.logger.debug(f"Pending event error on {p}: {e}")
                time.sleep(0.01)  # Brief yield between batch items

    @staticmethod
    def _looks_transient(name: str) -> bool:
        """True for editor/tool scratch files whose deletion is normal churn."""
        n = name.lower()
        if n == ".ds_store":
            return True
        if n.startswith(".#") or n.startswith("~$"):
            return True
        if n.isdigit():  # vim's numbered write-test files (e.g. 4913)
            return True
        return n.endswith((".tmp", ".temp", ".swp", ".swx", ".swo", "~", ".bak", ".orig"))

    def _handle_deletion(self, path: Path):
        """Record a deletion as forensic telemetry (see on_deleted for rationale).

        Deliberately non-punitive: no quarantine (nothing to quarantine) and no
        safety-score change (would false-trigger lockdown on legitimate refactors).
        """
        try:
            skip_names = {"__pycache__", ".git", "node_modules", ".deadpush",
                          ".deadpush-quarantine", ".deadpush-archive",
                          ".deadpush-config-backups"}
            if any(part in skip_names for part in path.parts):
                return
            if self._looks_transient(path.name):
                return
            try:
                rel = path.relative_to(self.config.repo_root).as_posix()
            except (ValueError, Exception):
                return
            self.logger.info(f"DELETE {rel} (recorded; not restored)")
            try:
                self.session_mgr.record_incident({"type": "file_deleted", "file": rel})
            except Exception:
                pass
        except Exception as e:
            self.logger.debug(f"Deletion handling error on {path}: {e}")

    def _process_event(self, path: Path, event_type: str):
        """Core single-event evaluation pipeline."""
        now = time.time()
        try:
            rel = path.relative_to(self.config.repo_root).as_posix()
        except (ValueError, Exception):
            return

        self.last_intervention_ts = now

        from .bootstrap import is_bootstrap_path

        if is_bootstrap_path(rel, self.config.repo_root):
            try:
                self.session_mgr.record_file_change(rel)
            except Exception:
                pass
            return

        # Lockdown: at score 0, quarantine every write (no pass-through)
        if self.intervention and self.safety_score.score <= 0 and path.exists():
            from .intercept import GuardrailResult, Violation, _write_feedback, FEEDBACK_DIR

            result = GuardrailResult()
            result.reject(Violation(
                "lockdown",
                "Guardian lockdown active (safety score 0): all writes quarantined",
                0,
                "critical",
            ))
            self._quarantine_and_restore(path, rel, result)
            self.safety_score.report_incident(5, f"Lockdown quarantine: {rel}", str(path))
            try:
                _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
            except Exception:
                pass
            self.logger.critical(f"LOCKDOWN [{event_type.upper()}] quarantined {rel}")
            if self.gpc is not None:
                try:
                    self.gpc.emit_lockdown(
                        "Guardian lockdown active (safety score 0): all writes quarantined",
                        file=rel,
                        score=self.safety_score.score,
                    )
                except Exception:
                    pass
            self._record_audit("guardrail.lockdown", {
                "file": rel,
                "description": "Guardian lockdown active (safety score 0)",
                "score": self.safety_score.score,
            })
            return

        # === STEP 1: Check blocked files (deadpush.toml blocked_files/blocked_patterns) ===
        if self.config.is_blocked(rel):
            self._intervene_blocked(path, rel, event_type)
            return

        # === STEP 2: Run full guardrail pipeline ===
        from .intercept import _run_guardrails, _write_feedback, FEEDBACK_DIR

        old_source = self._git_show(rel)

        result = _run_guardrails(
            path, self.config.repo_root, self.config,
            old_source=old_source or None, rel_path_override=rel,
        )

        # === STEP 3: Enforce guardrail results ===
        if not result.allowed:
            self._intervene_guardrails(path, rel, result, event_type)
            return  # File was quarantined; don't continue evaluation

        if result.violations:
            # Warn-level violations — log + write feedback + safety score hit
            for v in result.violations:
                penalty = 8 if v.severity == "high" else 4
                self.safety_score.report_incident(penalty, f"Warn: {v.description}", str(path))
            self.logger.warning(
                f"WARN [{event_type.upper()}] {rel} | "
                f"{len(result.violations)} warn-level violation(s) | "
                f"Safety: {self.safety_score.score}/100"
            )
            try:
                _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
            except Exception:
                pass
            self.session_mgr.record_incident({
                "type": "guardrail_warn", "file": rel,
                "count": len(result.violations),
            })

        # === STEP 4: Debris scan (secondary, in addition to guardrails) ===
        try:
            from .types import FileInfo
            fi = FileInfo(
                path=path,
                rel_path=path.relative_to(self.config.repo_root),
                size=path.stat().st_size,
                is_text=True,
                mtime=time.time(),
            )
            debris = self.detector.scan([fi])
            blocking = [d for d in debris if d.block_push]
            if blocking:
                self._intervene_blocking_debris(path, blocking, event_type)
        except Exception:
            pass

        # === STEP 5: Record in session ===
        try:
            self.session_mgr.record_file_change(rel)
            self.session_mgr.update_safety_score(self.safety_score.score)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Intervention actions
    # ------------------------------------------------------------------
    def _intervene_blocked(self, path: Path, rel: str, event_type: str):
        """Intervene when a blocked file is written (claude.md, etc.)."""
        from .intercept import GuardrailResult, Violation

        self.last_intervention_ts = time.time()
        score = self.safety_score.report_incident(25, f"Blocked file written: {rel}", str(path))

        result = GuardrailResult()
        result.reject(Violation("blocked_file", f"File {rel} is in the blocked list and cannot be written", 0, "critical"))

        self._quarantine_and_restore(path, rel, result)

        self.logger.warning(
            f"INTERVENTION [{event_type.upper()}] BLOCKED FILE: {rel} | "
            f"Moved to quarantine + restored from git | Safety: {score}/100"
        )
        try:
            self.session_mgr.record_incident({
                "type": "blocked_file", "file": rel, "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass

    def _intervene_guardrails(self, path: Path, rel: str, result, event_type: str):
        """Intervene when guardrails detect block-level violations."""
        from .intercept import _write_feedback, FEEDBACK_DIR

        self.last_intervention_ts = time.time()
        penalty = min(25, 5 * len(result.violations))
        score = self.safety_score.report_incident(penalty, f"Guardrail block: {result.violations[0].description}", str(path))

        self._quarantine_and_restore(path, rel, result)

        self.logger.warning(
            f"INTERVENTION [{event_type.upper()}] GUARDRAIL BLOCK: {rel} | "
            f"{len(result.violations)} violation(s) | "
            f"Top: {result.violations[0].description} | "
            f"Safety: {score}/100"
        )

        try:
            _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
        except Exception:
            pass

        try:
            self.session_mgr.record_incident({
                "type": "guardrail_block", "file": rel,
                "violations": [v.to_dict() for v in result.violations],
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass

        self._gpc_maybe_instruction()

    def _quarantine_and_restore(self, path: Path, rel: str, result) -> None:
        """Quarantine the violating file, unstage if needed, restore safe git version."""
        if self.intervention and path.exists():
            reason = result.violations[0].description if result.violations else "guardrail violation"
            try:
                quarantined = self.quarantine.quarantine(path, reason)
                self.logger.info(f"Quarantined: {quarantined}")
                if self.gpc is not None:
                    try:
                        self.gpc.emit_incident(
                            category=result.violations[0].category if result.violations else "guardrail",
                            description=reason,
                            file=rel,
                        )
                    except Exception:
                        pass
                self._record_audit("guardrail.quarantine", {
                    "file": rel,
                    "description": reason,
                    "category": result.violations[0].category if result.violations else "guardrail",
                    "violations": [v.to_dict() for v in result.violations[:5]],
                })
            except Exception as e:
                self.logger.error(f"Failed to quarantine {path}: {e}")
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass

        self._unstage_if_staged(rel)
        self._restore_from_git(rel)

    def _intervene_blocking_debris(self, path: Path, blocking_items, event_type: str):
        """Quarantine files with block_push debris (secrets, LLM context, etc.)."""
        from .intercept import GuardrailResult, Violation, _write_feedback, FEEDBACK_DIR

        self.last_intervention_ts = time.time()
        rel = path.relative_to(self.config.repo_root).as_posix()
        top = max(blocking_items, key=lambda d: (d.block_push, d.confidence))
        score = self.safety_score.report_incident(12, top.reason, str(path))

        result = GuardrailResult()
        result.reject(Violation("debris", top.reason, 0, "critical"))

        self.logger.warning(
            f"INTERVENTION [{event_type.upper()}] {top.category} in {path.name} | "
            f"{top.reason} | Safety: {score}/100"
        )

        if self.intervention:
            self._quarantine_and_restore(path, rel, result)

        try:
            _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
        except Exception:
            pass
        try:
            self.session_mgr.record_incident({
                "type": "blocking_debris",
                "reason": top.reason,
                "file": rel,
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass


# =============================================================================
# Shadow Process — Re-spawns guardian if it crashes
# =============================================================================

_SHADOW_SCRIPT = r"""import os, sys, time, signal, subprocess
guardian_pid = int(sys.argv[1])
pidfile = sys.argv[2]
respawn_cmd = sys.argv[3:-1]
shadow_pidfile = sys.argv[-1]
# TAG: {tag}

def _handle_exit(signum, frame):
    os._exit(0)

signal.signal(signal.SIGTERM, _handle_exit)
signal.signal(signal.SIGINT, _handle_exit)

# Write our own PID file for coordination
with open(shadow_pidfile, "w") as f:
    f.write(str(os.getpid()))

failure_count = 0
base_backoff = 3
max_backoff = 60
max_failures = 10

def _is_guardian_alive(pid):
    # Check if guardian process is actually alive and is a deadpush process.
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # Verify it's a deadpush process via ps
    try:
        r = subprocess.run(
            ["ps", "-o", "command=", "-p", str(pid)],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0 and "deadpush" in r.stdout
    except Exception:
        return True  # Conservative: assume alive if check fails

def _read_pidfile():
    try:
        with open(pidfile) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None

while True:
    # Check if guardian is alive
    if _is_guardian_alive(guardian_pid):
        failure_count = 0
        time.sleep(3)
        continue

    # Guardian appears dead - re-read PID file in case it was restarted
    new_pid = _read_pidfile()
    if new_pid and new_pid != guardian_pid and _is_guardian_alive(new_pid):
        guardian_pid = new_pid
        failure_count = 0
        time.sleep(3)
        continue

    # Guardian is dead - attempt respawn
    failure_count += 1
    if failure_count > max_failures:
        # Too many failures - exit to avoid spam
        os._exit(1)

    # Exponential backoff
    backoff = min(base_backoff * (2 ** (failure_count - 1)), max_backoff)
    time.sleep(backoff)

    # Final check before respawning
    if _is_guardian_alive(guardian_pid):
        failure_count = 0
        continue
    new_pid = _read_pidfile()
    if new_pid and new_pid != guardian_pid and _is_guardian_alive(new_pid):
        guardian_pid = new_pid
        failure_count = 0
        continue

    # Respawn guardian
    pid = os.fork()
    if pid == 0:
        # Child: execute guardian
        os.execvp(respawn_cmd[0], respawn_cmd)
        os._exit(1)
    else:
        # Parent: update guardian_pid to new child
        guardian_pid = pid
"""

_SHADOW_TAG_PREFIX = "deadpush_shadow_watch."


def _shadow_tag(repo_root: Path) -> str:
    return f"{_SHADOW_TAG_PREFIX}{_repo_id(str(repo_root))}"


def stop_shadow_for_repo(repo_root: Path, hardened: bool = False) -> int:
    """Kill shadow process(es) scoped to one repo. Returns count killed."""
    import signal

    tag = _shadow_tag(repo_root)
    killed = 0
    try:
        r = subprocess.run(
            ["pgrep", "-f", tag],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            my_pid = os.getpid()
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                pid = int(line.strip())
                if pid == my_pid:
                    continue
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed += 1
                except OSError:
                    pass
    except Exception:
        pass
    shadow_pidfile = _scoped_pidfile(repo_root, hardened).with_suffix(".shadow")
    shadow_pidfile.unlink(missing_ok=True)
    return killed


def start_shadow_process(guardian_pid: int, pidfile: Path, respawn_cmd: list[str], repo_root: Path) -> subprocess.Popen | None:
    """Launch a shadow subprocess that re-spawns the guardian if it dies.

    Only starts if no shadow is already running for this repo (checked via pgrep).
    """
    tag = _shadow_tag(repo_root)
    shadow_pidfile = pidfile.with_suffix(".shadow")
    try:
        r = subprocess.run(
            ["pgrep", "-f", tag],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            pids = [int(p) for p in r.stdout.strip().splitlines() if p.strip()]
            # Filter out our own PID if we're somehow in the list
            my_pid = os.getpid()
            pids = [pid for pid in pids if pid != my_pid]
            if pids:
                return None  # already running
    except Exception:
        pass

    script = _SHADOW_SCRIPT.replace("{tag}", tag)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", script, str(guardian_pid), str(pidfile)] + respawn_cmd + [str(shadow_pidfile)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        return proc
    except Exception:
        return None


def stop_guardian_for_repo(
    repo_root: Path | str,
    *,
    hardened: bool = False,
    force: bool = False,
) -> bool:
    """Stop the guardian for one repo. Returns True if a process was stopped."""
    import signal
    import subprocess
    import time

    from .hooks import _make_mutable

    repo_root = Path(repo_root).resolve()
    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)
    portfile = _scoped_portfile(repo_root, hardened)
    plist_label = _scoped_plist_label(repo_root)
    plist_path = _scoped_plist_path(repo_root, hardened)
    shadow_pidfile = pidfile.with_suffix(".shadow")

    if force:
        dm = DaemonManager(pidfile, lockfile)
        dm.force_cleanup()
        if not hardened and plist_path.exists():
            plist_path.unlink(missing_ok=True)
        for f in (portfile, shadow_pidfile):
            f.unlink(missing_ok=True)
        _state.touch_registry(repo_root, hardened=hardened, running=False)
        return True

    stopped = False

    if not hardened:
        if stop_shadow_for_repo(repo_root, hardened):
            stopped = True
            time.sleep(0.2)

    guardian_pid = None
    if hardened:
        try:
            r = subprocess.run(
                ["sudo", "cat", str(pidfile)],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                guardian_pid = int(r.stdout.strip())
        except Exception:
            pass
    elif pidfile.exists():
        try:
            guardian_pid = int(pidfile.read_text().strip())
        except (ValueError, OSError):
            pass

    if guardian_pid:
        try:
            if hardened:
                r = subprocess.run(
                    ["sudo", "kill", "-0", str(guardian_pid)],
                    capture_output=True, timeout=5,
                )
                if r.returncode != 0:
                    raise OSError("not running")
                subprocess.run(["sudo", "kill", str(guardian_pid)], capture_output=True, timeout=5)
            else:
                os.kill(guardian_pid, 0)
                os.kill(guardian_pid, signal.SIGTERM)
            for _ in range(10):
                try:
                    if hardened:
                        r = subprocess.run(
                            ["sudo", "kill", "-0", str(guardian_pid)],
                            capture_output=True, timeout=5,
                        )
                        if r.returncode != 0:
                            break
                    else:
                        os.kill(guardian_pid, 0)
                    time.sleep(0.2)
                except OSError:
                    break
            else:
                try:
                    if hardened:
                        subprocess.run(["sudo", "kill", "-9", str(guardian_pid)], capture_output=True, timeout=5)
                    else:
                        os.kill(guardian_pid, signal.SIGKILL)
                except OSError:
                    pass
            stopped = True
        except OSError:
            pass

    try:
        if sys.platform == "darwin":
            if hardened:
                subprocess.run(["sudo", "launchctl", "bootout", "system", plist_label], capture_output=True, timeout=10)
            else:
                uid = os.getuid()
                subprocess.run(["launchctl", "bootout", f"gui/{uid}/{plist_label}"], capture_output=True, timeout=10)
    except Exception:
        pass

    try:
        if hardened:
            subprocess.run(["sudo", "rm", "-f", str(plist_path)], capture_output=True, timeout=10)
        elif plist_path.exists():
            plist_path.unlink()
    except OSError:
        pass

    for f in (pidfile, lockfile, portfile, shadow_pidfile):
        try:
            if hardened:
                subprocess.run(["sudo", "rm", "-f", str(f)], capture_output=True, timeout=10)
            elif f.exists():
                f.unlink()
        except OSError:
            pass

    if hardened:
        shared_port = repo_root / ".guardian" / "guardian.control.port"
        try:
            subprocess.run(["sudo", "rm", "-f", str(shared_port)], capture_output=True, timeout=10)
        except OSError:
            pass

    try:
        hooks_dir = repo_root / ".git" / "hooks"
        if hooks_dir.exists():
            for hook in hooks_dir.iterdir():
                if hook.is_file() and not hook.name.endswith(".sample"):
                    _make_mutable(hook)
    except Exception:
        pass

    _state.touch_registry(repo_root, hardened=hardened, running=False)
    return stopped


def stop_guardian_by_id(rid: str, *, hardened: bool = False) -> bool:
    """Stop guardian when only repo id is known (orphan / missing holder)."""
    import signal
    import time

    stopped = False
    my_pid = os.getpid()
    patterns = (
        f"deadpush_shadow_watch.{rid}",
        f"guardian.{rid}.pid",
        f"repos/{rid}/",
    )
    pids: set[int] = set()
    for pattern in patterns:
        try:
            r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                try:
                    pid = int(line.strip())
                    if pid != my_pid:
                        pids.add(pid)
                except ValueError:
                    pass
        except Exception:
            pass

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            stopped = True
        except OSError:
            pass
    time.sleep(0.5)
    for pid in pids:
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
            stopped = True
        except OSError:
            pass

    root = _state.state_dir(hardened)
    for pidfile in (root / "repos" / rid / "guardian.pid", root / f"guardian.{rid}.pid"):
        if pidfile.exists():
            try:
                gpid = int(pidfile.read_text(encoding="utf-8").strip())
                if gpid != my_pid:
                    try:
                        os.kill(gpid, signal.SIGTERM)
                        stopped = True
                    except OSError:
                        pass
                    time.sleep(0.3)
                    try:
                        os.kill(gpid, signal.SIGKILL)
                    except OSError:
                        pass
            except (ValueError, OSError):
                pass
        pidfile.unlink(missing_ok=True)

    repos_dir = root / "repos" / rid
    for name in ("guardian.lock", "guardian.shadow", "control.port"):
        (repos_dir / name).unlink(missing_ok=True)
    (root / f"guardian.{rid}.shadow").unlink(missing_ok=True)
    sock = repos_dir / "gpc.sock"
    if sock.exists():
        sock.unlink(missing_ok=True)
    return stopped


def kill_orphan_guardian_processes() -> int:
    """SIGTERM stray guardian/shadow processes. Returns count killed."""
    import signal

    patterns = (
        "deadpush_shadow_watch.",
        "-m deadpush.cli guard --daemon",
        "-m deadpush_bootstrap guard --daemon",
        "-m deadpush guard --daemon",
    )
    my_pid = os.getpid()
    killed = 0
    seen: set[int] = set()
    for pattern in patterns:
        try:
            r = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                continue
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                pid = int(line.strip())
                if pid == my_pid or pid in seen:
                    continue
                seen.add(pid)
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed += 1
                except OSError:
                    pass
        except Exception:
            pass
    time.sleep(0.5)
    for pid in list(seen):
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return killed


def count_running_guardians() -> int:
    """Return number of guardian processes still alive."""
    try:
        r = subprocess.run(
            ["pgrep", "-f", "deadpush_shadow_watch.|guard --daemon"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return 0
        return len([ln for ln in r.stdout.strip().splitlines() if ln.strip()])
    except Exception:
        return 0


# =============================================================================
# Main Runner with Improved Daemon Support
# =============================================================================
def run_guardian(
    intervention: bool = True,
    daemon: bool = False,
    strict: bool = False,
    hardened: bool = False,
    *,
    allow_self_protect: bool = False,
    enable_fanotify: bool = True,
):
    if not WATCHDOG_AVAILABLE:
        print("Error: watchdog package required. pip install deadpush[watch]")
        return

    config = load_config()
    from .config import dev_repo_guard_refusal

    refusal = dev_repo_guard_refusal(
        config.repo_root,
        allow_self_protect=allow_self_protect,
        persistent=bool(daemon or hardened),
    )
    if refusal:
        print(f"Error: {refusal}", file=sys.stderr)
        raise SystemExit(2)

    logger = setup_logging(
        daemon=daemon, hardened=hardened, repo_root=config.repo_root,
    )

    _state_dir(hardened).mkdir(parents=True, exist_ok=True)
    pidfile = _scoped_pidfile(config.repo_root, hardened)
    lockfile = _scoped_lockfile(config.repo_root, hardened)

    daemon_mgr = DaemonManager(pidfile, lockfile)

    if daemon_mgr.is_running():
        logger.warning("Guardian is already running.")
        return

    if not daemon_mgr.acquire_lock():
        logger.error("Could not acquire lock. Another instance may be running.")
        return

    # A clean stop removes the PID/start files (DaemonManager.cleanup on graceful
    # SIGTERM / `deadpush stop`). If they are still here while the daemon is not
    # running, the previous instance was killed or crashed — surface it loudly so a
    # same-UID agent killing the guardian in soft mode is visible, not silent.
    try:
        prior_unclean = pidfile.exists() or daemon_mgr.startfile.exists()
    except Exception:
        prior_unclean = False

    def _note_unclean_restart(h) -> None:
        if not prior_unclean:
            return
        try:
            h.session_mgr.record_incident({"type": "guardian_unclean_restart"})
        except Exception:
            pass

    # Shadow process (re-spawns guardian if it crashes) is started post-fork in
    # the child so it runs in a new session, immune to fork issues.
    # Not needed in hardened mode — launchd handles restart via KeepAlive.

    # Create the Local Control Interface object (don't start it yet)
    # We'll create the handler and control_server after fork to avoid
    # FD/thread inheritance issues
    control_server = None

    if daemon:
        logger.info("Starting in DAEMON mode...")
        try:
            # Double fork
            if os.fork() > 0:
                sys.exit(0)
            os.setsid()
            if os.fork() > 0:
                sys.exit(0)
            os.chdir("/")
            os.umask(0)

            # Headless daemon: ensure no stray output to terminal
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            with open(os.devnull, "w") as devnull:
                os.dup2(devnull.fileno(), sys.stdout.fileno())
                os.dup2(devnull.fileno(), sys.stderr.fileno())

            # Re-initialize logging BEFORE closing FDs so the new
            # RotatingFileHandler has a valid FD that survives the close loop
            logger = setup_logging(daemon=True, hardened=hardened, repo_root=config.repo_root)

            # Close all inherited FDs except stdio (0,1,2) and the log FD.
            # Use root logger's handlers (named loggers propagate to root).
            import resource
            max_fd = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            if max_fd == resource.RLIM_INFINITY:
                max_fd = 1024
            log_fd = None
            for h in logging.getLogger().handlers:
                try:
                    if hasattr(h, 'stream') and hasattr(h.stream, 'fileno'):
                        log_fd = h.stream.fileno()
                except (OSError, AttributeError, ValueError):
                    pass
            for fd in range(3, max_fd):
                if fd == log_fd:
                    continue
                try:
                    os.close(fd)
                except OSError:
                    pass

            if prior_unclean:
                logger.warning(
                    "GUARDIAN RESTART (possible tamper): a previous guardian did not shut "
                    "down cleanly (stale PID file present). If you did not stop it, an agent "
                    "or process may have killed it. Soft mode cannot prevent a same-UID kill "
                    "— use hardened mode for an unkillable guardian."
                )
            daemon_mgr.write_pid(config.repo_root)
            atexit.register(daemon_mgr.cleanup)

            handler = GuardianHandler(
                config, intervention=intervention, strict_mode=strict, daemon=daemon,
                logger=logger, hardened=hardened, enable_fanotify=enable_fanotify,
            )
            _note_unclean_restart(handler)
            _control_token = _load_or_create_control_token(config.repo_root, hardened)
            control_server = GuardianControlServer(handler, repo_root=config.repo_root, hardened=hardened, token=_control_token)

            # Start shadow process in the final daemon process (post-fork)
            if not hardened:
                handler._start_shadow()

            # Start control server in the final daemon process (post-fork)
            _start_control_server(control_server, logger, config.repo_root, hardened)
            handler._start_fanotify()

            _run_observer(handler, logger, daemon_mgr)
        except Exception as e:
            logger.error(f"Daemon failed: {e}")
            daemon_mgr.cleanup()
    else:
        logger.info("Starting in FOREGROUND mode...")
        if prior_unclean:
            logger.warning(
                "GUARDIAN RESTART (possible tamper): a previous guardian did not shut "
                "down cleanly (stale PID file present). If you did not stop it, an agent "
                "or process may have killed it."
            )
        daemon_mgr.write_pid(config.repo_root)
        atexit.register(daemon_mgr.cleanup)

        handler = GuardianHandler(
            config, intervention=intervention, strict_mode=strict, daemon=daemon,
            logger=logger, hardened=hardened, enable_fanotify=enable_fanotify,
        )
        _note_unclean_restart(handler)
        _control_token = _load_or_create_control_token(config.repo_root, hardened)
        control_server = GuardianControlServer(handler, repo_root=config.repo_root, hardened=hardened, token=_control_token)

        # Start shadow process
        if not hardened:
            handler._start_shadow()

        _start_control_server(control_server, logger, config.repo_root, hardened)
        handler._start_fanotify()

        _run_observer(handler, logger, daemon_mgr)


def _start_control_server(control_server, logger, repo_root, hardened):
    """Start the local HTTP control interface and log its status.
    Safe to call after daemon fork (no threading before fork)."""
    from .gpc import GpcServer

    gpc = GpcServer(repo_root, hardened=hardened)
    try:
        gpc.start()
        if control_server.guardian_handler:
            control_server.guardian_handler.gpc = gpc
        logger.info(f"Guardian Push Channel (GPC) on {gpc.socket_path}")
        atexit.register(gpc.stop)
    except Exception as e:
        logger.warning(f"GPC server could not start: {e}")

    control_server.start()
    if control_server.port:
        logger.info(f"Local control interface on http://127.0.0.1:{control_server.port} (port file: {control_server.port_file})")
        logger.info("AI agents can now query the guardian autonomously (GET /status, /quarantine-list, etc.)")
        atexit.register(control_server.stop)
        if hardened:
            try:
                shared_port = repo_root / ".guardian" / "guardian.control.port"
                shared_port.parent.mkdir(parents=True, exist_ok=True)
                shared_port.write_text(str(control_server.port))
                atexit.register(lambda p=shared_port: p.unlink(missing_ok=True))
            except Exception:
                pass
    else:
        logger.warning("Local control interface could not be started (agents can fall back to `deadpush status` / CLI)")


def _run_observer(handler: GuardianHandler, logger, daemon_mgr: DaemonManager | None = None):
    """Run the filesystem observer with automatic recovery on crashes.

    This improves daemon reliability: if the watcher thread dies (e.g. transient FS error,
    handler bug), we log, wait with backoff, and restart the observer without killing the daemon.
    """
    if Observer is None:
        logger.error("Cannot start observer: watchdog not installed. Use `pip install deadpush[watch]`")
        return

    backoff = 1
    max_backoff = 30
    running = True

    def shutdown(signum, frame):
        nonlocal running
        if not running:
            return
        running = False
        logger.info("Guardian shutting down gracefully...")
        try:
            handler._stop_fanotify()
        except Exception:
            pass
        try:
            handler.safety_score.mark_clean_shutdown()
        except Exception:
            pass
        try:
            handler._stop_shadow()
        except Exception:
            pass
        if daemon_mgr is not None:
            try:
                daemon_mgr.cleanup()
            except Exception:
                pass

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    observer = None
    try:
        while running:
            try:
                if not running:
                    break
                if observer is None or not getattr(observer, 'is_alive', lambda: False)():
                    if observer is not None:
                        try:
                            observer.stop()
                            observer.join(timeout=2)
                        except Exception:
                            pass
                    observer = Observer()
                    observer.schedule(handler, str(handler.config.repo_root), recursive=True)
                    observer.start()
                    logger.info(f"Guardian (re)watching: {handler.config.repo_root}")
                    logger.info(f"Safety Score: {handler.safety_score.get_summary()}")
                    backoff = 1  # reset on healthy start

                handler._check_shadow()
                handler._check_suspension()
                handler._check_hook_integrity()
                handler._check_head_commit()
                time.sleep(1)
            except Exception as e:
                if not running:
                    break
                logger.error(f"Watcher error (auto-recovering in {backoff}s): {e}")
                if observer:
                    try:
                        observer.stop()
                    except Exception:
                        pass
                time.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
                observer = None  # force recreate next iter
    except KeyboardInterrupt:
        logger.info("Guardian interrupted.")
        running = False
    finally:
        try:
            handler._stop_shadow()
        except Exception:
            pass
        if observer:
            try:
                observer.stop()
                observer.join(timeout=3)
            except Exception:
                pass
        if daemon_mgr is not None:
            try:
                daemon_mgr.cleanup()
            except Exception:
                pass
        logger.info("Observer stopped.")
        # When the guardian stops, show a clean session summary (AGENT.md polish requirement)
        try:
            logger.info(f"SESSION SUMMARY: {handler.safety_score.get_session_summary()}")
            logger.info(f"FINAL SAFETY: {handler.safety_score.get_summary()}")
        except Exception:
            pass
        # Session summary on stop (AGENT.md polish): give the user a clear recap
        # of what the guardian did during this run. Uses the handler's score if available.
        try:
            if handler and hasattr(handler, "safety_score"):
                summary = handler.safety_score.get_summary()
                logger.info(f"SESSION SUMMARY: {summary} | Total incidents this session: {len(handler.safety_score.incidents)}")
                print(f"\n[Guardian Session Summary]\n{summary}\nIncidents logged: {len(handler.safety_score.incidents)}")
                print("Review full activity in ~/.deadpush/guardian.log")
        except Exception:
            pass


# =============================================================================
# Basic Auto-Start Support (systemd user / launchd)
# Called / documented from protect for "survive reboots with minimal intervention"
# =============================================================================
def _is_system_path(path: Path) -> bool:
    s = str(path)
    return s.startswith("/Library/") or s.startswith("/etc/")


def _write_privileged_file(path: Path, content: str, sudo_fn=None) -> None:
    """Write a config file that may require root (LaunchDaemons, systemd system units)."""
    import os
    import subprocess
    import tempfile

    if not _is_system_path(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return

    def _sudo(cmd, check=True, timeout=60):
        if sudo_fn is not None:
            return sudo_fn(cmd, check=check, timeout=timeout)
        full = ["sudo"] + cmd
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(full)} failed: {r.stderr.strip()}")
        return r

    with tempfile.NamedTemporaryFile(mode="w", suffix=path.suffix, delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        _sudo(["mkdir", "-p", str(path.parent)])
        _sudo(["cp", tmp, str(path)])
        _sudo(["chmod", "644", str(path)], check=False)
    finally:
        os.unlink(tmp)


def setup_autostart(repo_root: Path, hardened: bool = False, _sudo=None) -> str:
    """Generate OS-specific auto-start configuration for the guardian daemon.

    This helps fulfill "survive across sessions/reboots with minimal user intervention".

    - On Linux: writes ~/.config/systemd/user/deadpush-guardian.<repoid>.service
    - On macOS: writes ~/Library/LaunchAgents/com.deadpush.guardian.<repoid>.plist
    - In hardened mode: writes to system paths for the _deadpush user.

    Returns a string with the file path + exact commands the user should run to enable it.
    Safe to call multiple times (idempotent overwrite).
    Does not auto-enable (user must run the printed commands, for safety/permissions).
    """
    import sys as _sys
    home = Path.home()
    if hardened:
        exe = str(_hardened_python())
    else:
        exe = _sys.executable
    rid = _repo_id(str(repo_root))

    if _sys.platform.startswith("linux"):
        unit_path = _scoped_systemd_unit_path(repo_root, hardened)
        if not _is_system_path(unit_path):
            unit_path.parent.mkdir(parents=True, exist_ok=True)
        env_line = f'Environment="PATH=/usr/local/bin:/usr/bin:/bin:{home}/.local/bin"'
        wanted_by = "multi-user.target" if hardened else "default.target"
        content = f"""[Unit]
Description=deadpush AI Agent Guardian ({rid}) - persistent background protection
After=network.target

[Service]
Type=simple
ExecStart={exe} -m deadpush_bootstrap guard --daemon{' --hardened' if hardened else ''}
Restart=always
RestartSec=5
WorkingDirectory={repo_root}
Nice=10
{env_line}
{'User=_deadpush' if hardened else ''}

[Install]
WantedBy={wanted_by}
"""
        _write_privileged_file(unit_path, content, _sudo)
        return f"""Linux{' systemd system' if hardened else ' systemd --user'} unit written:
  {unit_path}

To enable auto-start{' on boot' if hardened else ' on login / reboot'} (run these once):
  systemctl{'' if hardened else ' --user'} daemon-reload
  systemctl{'' if hardened else ' --user'} enable --now deadpush-guardian.{rid}.service

Useful commands:
  systemctl{'' if hardened else ' --user'} status deadpush-guardian.{rid}.service
  journalctl{'' if hardened else ' --user'} -u deadpush-guardian.{rid} -f
  systemctl{'' if hardened else ' --user'} stop deadpush-guardian.{rid}.service
"""

    elif _sys.platform == "darwin":
        plist_label = _scoped_plist_label(repo_root)
        plist_path = _scoped_plist_path(repo_root, hardened)
        log_dir = _state_dir(hardened)
        if not hardened:
            log_dir.mkdir(parents=True, exist_ok=True)
        hardened_args = ""
        user_name = ""
        if hardened:
            hardened_args = "\n        <string>--hardened</string>"
            user_name = """
    <key>UserName</key>
    <string>_deadpush</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/var/db/deadpush/venv/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>"""
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{plist_label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>-m</string>
        <string>deadpush_bootstrap</string>
        <string>guard</string>
        <string>--daemon</string>{hardened_args}
    </array>
    <key>WorkingDirectory</key>
    <string>{repo_root}</string>{user_name}
    <key>WatchPaths</key>
    <array>
        <string>{repo_root}/.git/HEAD</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>{log_dir}/guardian.{rid}.launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/guardian.{rid}.launchd.err.log</string>
</dict>
</plist>
"""
        _write_privileged_file(plist_path, content, _sudo)
        return f"""macOS{' LaunchDaemon' if hardened else ' LaunchAgent'} plist written:
  {plist_path}

To load (start now + on{' boot' if hardened else ' login/reboot'}):
  {'sudo launchctl bootstrap system' if hardened else 'launchctl load'} {plist_path}

To unload / stop:
  {'sudo launchctl bootout system ' + plist_label if hardened else 'launchctl unload ' + str(plist_path)}

Logs: tail -f {log_dir}/guardian.{rid}.launchd.*.log
(Also file logs at {log_dir}/guardian.log )
"""

    else:
        return f"""Auto-start unit generation not supported on this platform ({_sys.platform}).
You can still achieve "survive reboot" by:
  - Adding `deadpush guard --daemon` to your shell's startup (~/.bashrc, ~/.zshrc, etc) with nohup or similar, or
  - Using your distro's service manager manually pointing at: {exe} -m deadpush_bootstrap guard --daemon
  - Or cron with @reboot (advanced).
See `deadpush guard --daemon` for the core persistent mode.
"""


def _launchctl_bootstrap_system(plist_path: Path, label: str, _sudo, repo_root: Path | None = None) -> None:
    """Load a system LaunchDaemon (bootstrap on modern macOS, load as fallback)."""
    import time

    plist_s = str(plist_path)
    expected_py = str(_hardened_python())

    # Preflight: hardened venv must be importable as _deadpush
    _sudo(["-u", "_deadpush", expected_py, "-c", "import deadpush.cli"], check=True)

    # Fully unload stale job (plist edits do not apply until bootout + bootstrap)
    _sudo(["launchctl", "bootout", f"system/{label}"], check=False)
    _sudo(["launchctl", "bootout", "system", plist_s], check=False)
    _sudo(["launchctl", "unload", "-w", plist_s], check=False)
    time.sleep(1)

    r = _sudo(["launchctl", "bootstrap", "system", plist_s], check=False)
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").lower()
        if "already" not in err and "loaded" not in err:
            _sudo(["launchctl", "load", "-w", plist_s])

    _sudo(["launchctl", "enable", f"system/{label}"], check=False)
    _sudo(["launchctl", "kickstart", "-k", f"system/{label}"], check=False)
    time.sleep(2)

    status = _sudo(["launchctl", "print", f"system/{label}"], check=False)
    out = (status.stdout or "") + (status.stderr or "")
    if "state = running" in out and expected_py in out:
        return

    rid = _repo_id(str(repo_root)) if repo_root else "unknown"
    err_log = _HARDENED_STATE_DIR / f"guardian.{rid}.launchd.err.log"
    log_tail = _sudo(["tail", "-30", str(err_log)], check=False).stdout or ""
    raise RuntimeError(
        "LaunchDaemon did not enter running state after bootstrap.\n"
        f"Expected interpreter: {expected_py}\n"
        f"launchctl print:\n{out.strip()}\n"
        f"stderr log ({err_log}):\n{log_tail.strip() or '(empty)'}"
    )


def guardian_is_running(repo_root: Path, hardened: bool = False) -> bool:
    """Return True if the guardian daemon is running for this repo."""
    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)

    if not hardened:
        return DaemonManager(pidfile, lockfile).is_running()

    shared_port = repo_root / ".guardian" / "guardian.control.port"
    if shared_port.exists():
        try:
            import socket
            port = int(shared_port.read_text().strip())
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except Exception:
            pass

    label = _scoped_plist_label(repo_root)
    try:
        r = subprocess.run(
            ["sudo", "launchctl", "print", f"system/{label}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and "state = running" in r.stdout:
            return True
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["sudo", "cat", str(pidfile)],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            pid = int(r.stdout.strip())
            os.kill(pid, 0)
            return True
    except Exception:
        pass
    return False


def guardian_persistence_installed(repo_root: Path, hardened: bool = False) -> bool:
    """True when the guardian is set up to run persistently (launchd/systemd) or the
    repo is marked protected — i.e. it *should* be running. Used to distinguish
    'never installed' from 'installed but not running (possible tamper)'."""
    try:
        if _scoped_plist_path(repo_root, hardened).exists():
            return True
    except Exception:
        pass
    try:
        if _scoped_systemd_unit_path(repo_root, hardened).exists():
            return True
    except Exception:
        pass
    try:
        from .config import install_marker_path
        if install_marker_path(repo_root).exists():
            return True
    except Exception:
        pass
    return False


def guardian_killed_uncleanly(repo_root: Path, hardened: bool = False) -> bool:
    """True when a stale PID/start file remains but the guardian is not running.

    A clean stop (`deadpush stop` / graceful SIGTERM) removes these files via
    DaemonManager.cleanup(), so their presence while nothing is alive is evidence
    the daemon was killed or crashed rather than stopped intentionally.
    """
    if guardian_is_running(repo_root, hardened):
        return False
    pidfile = _scoped_pidfile(repo_root, hardened)
    try:
        return pidfile.exists() or pidfile.with_suffix(".start").exists()
    except Exception:
        return False


# =============================================================================
# Hardened environment setup (privilege separation)
# =============================================================================
# macOS ACE granted to _deadpush on parent dirs so it can traverse into the repo.
_HARDENED_TRAVERSE_ACE = "_deadpush allow list,search,readattr,readextattr,readsecurity"


def _hardened_traverse_dirs(repo_root: Path):
    """Yield existing parent dirs (under $HOME) that need _deadpush traverse access.

    Walks up from the repo toward $HOME, stopping at the filesystem root or a
    system dir. Shared by setup (grant) and teardown (revoke) so the two can
    never drift out of sync.
    """
    repo_root = repo_root.resolve()
    home = Path.home().resolve()
    skip = {Path("/"), Path("/Users")}
    cur = repo_root.parent
    while cur != cur.parent:
        if cur in skip:
            break
        try:
            under_home = cur.is_relative_to(home)
        except AttributeError:
            under_home = str(cur).startswith(str(home) + os.sep) or cur == home
        if not under_home:
            break
        if cur.exists():
            yield cur
        cur = cur.parent


def _apply_hardened_traverse_acls(repo_root: Path, _sudo) -> None:
    """Grant _deadpush traverse access to parent dirs (e.g. ~/Documents mode 700)."""
    if sys.platform == "darwin":
        for cur in _hardened_traverse_dirs(repo_root):
            _sudo(["chmod", "+a", _HARDENED_TRAVERSE_ACE, str(cur)])
    elif sys.platform.startswith("linux"):
        for cur in _hardened_traverse_dirs(repo_root):
            _sudo(["setfacl", "-m", "u:_deadpush:--x", str(cur)], check=False)


def teardown_hardened_environment(repo_root: Path, _sudo=None) -> list[str]:
    """Reverse ``setup_hardened_environment``: revoke every _deadpush ACL (repo
    tree, ``.guardian``, and the parent traverse dirs) and delete the _deadpush
    user/group.

    Platform-aware (macOS ``chmod``/``dscl``, Linux ``setfacl``/``userdel``) and
    strictly best-effort: a missing tool (e.g. ``dscl`` on Linux) or an absent
    ACL/account entry is a no-op, never a hard failure. ACLs are revoked BEFORE
    the account is deleted so name-based removal still resolves. Returns a list
    of human-readable actions taken.
    """
    import subprocess as _sp

    actions: list[str] = []

    def run(cmd):
        try:
            if _sudo is not None:
                return _sudo(cmd, check=False)
            return _sp.run(["sudo", *cmd], capture_output=True, text=True, timeout=30)
        except Exception:
            return None

    repo_root = repo_root.resolve()
    guardian_dir = repo_root / ".guardian"

    if sys.platform == "darwin":
        run(["chmod", "-R", "-N", str(repo_root)])
        if guardian_dir.exists():
            run(["chmod", "-R", "-N", str(guardian_dir)])
        for cur in _hardened_traverse_dirs(repo_root):
            run(["chmod", "-a", _HARDENED_TRAVERSE_ACE, str(cur)])
        actions.append("Cleared _deadpush ACLs")
        run(["dscl", ".", "-delete", "/Users/_deadpush"])
        run(["dscl", ".", "-delete", "/Groups/_deadpush"])
        actions.append("Removed _deadpush user and group")
    elif sys.platform.startswith("linux"):
        run(["setfacl", "-R", "-x", "u:_deadpush", str(repo_root)])
        if guardian_dir.exists():
            run(["setfacl", "-R", "-x", "u:_deadpush", str(guardian_dir)])
        for cur in _hardened_traverse_dirs(repo_root):
            run(["setfacl", "-x", "u:_deadpush", str(cur)])
        actions.append("Cleared _deadpush ACLs")
        run(["userdel", "_deadpush"])
        run(["groupdel", "_deadpush"])
        actions.append("Removed _deadpush user and group")
    return actions


def _apply_hardened_repo_acls(repo_root: Path, _sudo=None) -> None:
    """Grant _deadpush read + intervention ACLs on the protected repo tree."""
    import subprocess as _sp

    def run(cmd, **kwargs):
        if _sudo is not None:
            return _sudo(cmd, **kwargs)
        return _sp.run(["sudo"] + cmd, capture_output=True, text=True, timeout=30, **kwargs)

    repo_root = repo_root.resolve()
    quarantine_dir = repo_root / ".deadpush-quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    if sys.platform == "darwin":
        intervention = (
            "_deadpush allow list,readattr,readsecurity,search,read,readextattr,"
            "write,append,add_file,add_subdirectory,delete,delete_child,"
            "file_inherit,directory_inherit"
        )
        run(["chmod", "+a", intervention, str(repo_root)])
        guardian_dir = repo_root / ".guardian"
        guardian_dir.mkdir(parents=True, exist_ok=True)
        run(
            ["chmod", "+a",
             "_deadpush allow write,append,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit",
             str(guardian_dir)],
            timeout=15,
        )
    elif sys.platform.startswith("linux"):
        run(["setfacl", "-R", "-m", "u:_deadpush:rwx", str(repo_root)])
        guardian_dir = repo_root / ".guardian"
        guardian_dir.mkdir(parents=True, exist_ok=True)
        run(["setfacl", "-R", "-m", "u:_deadpush:rwx", str(guardian_dir)], timeout=15)


def _deadpush_account_valid() -> bool:
    """Return True if _deadpush resolves in the passwd database."""
    import pwd
    try:
        pwd.getpwnam("_deadpush")
        return True
    except KeyError:
        return False


def _find_free_system_id(kind: str, start: int = 400, end: int = 499) -> str:
    """Find an unused UID/GID in a safe system range (macOS dscl)."""
    import subprocess

    r = subprocess.run(
        ["dscl", ".", "-list", f"/{kind}", "UniqueID" if kind == "Users" else "PrimaryGroupID"],
        capture_output=True, text=True, timeout=30,
    )
    used: set[int] = set()
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    used.add(int(parts[-1]))
                except ValueError:
                    pass
    for candidate in range(start, end):
        if candidate not in used:
            return str(candidate)
    raise RuntimeError(f"No free {'UID' if kind == 'Users' else 'GID'} in range {start}-{end - 1}")


def _ensure_deadpush_account(_sudo, lines: list[str]) -> None:
    """Create or repair the _deadpush system user used by hardened mode."""
    import grp
    import subprocess
    import sys as _sys

    if _deadpush_account_valid():
        lines.append("User _deadpush already exists")
        return

    if _sys.platform == "darwin":
        # Remove broken dscl records (exist in Directory Service but not in passwd).
        if subprocess.run(
            ["dscl", ".", "-read", "/Users/_deadpush"],
            capture_output=True, timeout=10,
        ).returncode == 0:
            _sudo(["dscl", ".", "-delete", "/Users/_deadpush"], check=False)
            lines.append("Removed broken _deadpush user record")

        try:
            grp.getgrnam("_deadpush")
        except KeyError:
            if subprocess.run(
                ["dscl", ".", "-read", "/Groups/_deadpush"],
                capture_output=True, timeout=10,
            ).returncode == 0:
                _sudo(["dscl", ".", "-delete", "/Groups/_deadpush"], check=False)
                lines.append("Removed broken _deadpush group record")
            gid = _find_free_system_id("Groups")
            _sudo(["dscl", ".", "-create", "/Groups/_deadpush"])
            _sudo(["dscl", ".", "-create", "/Groups/_deadpush", "PrimaryGroupID", gid])
            _sudo(["dscl", ".", "-create", "/Groups/_deadpush", "RealName", "deadpush Guardian"])
            lines.append(f"Created _deadpush group (GID {gid})")
        else:
            lines.append("Group _deadpush already exists")

        gid = str(grp.getgrnam("_deadpush").gr_gid)
        uid = _find_free_system_id("Users")
        _sudo(["dscl", ".", "-create", "/Users/_deadpush"])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "UserShell", "/usr/bin/false"])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "NFSHomeDirectory", "/var/empty"])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "UniqueID", uid])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "PrimaryGroupID", gid])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "RealName", "deadpush Guardian"])
        _sudo(["dscl", ".", "-passwd", "/Users/_deadpush", "*"], check=False)
        _sudo(["dscl", ".", "-append", "/Groups/_deadpush", "GroupMembership", "_deadpush"], check=False)
        lines.append(f"Created _deadpush user (UID {uid}, GID {gid})")
    else:
        try:
            grp.getgrnam("_deadpush")
            lines.append("Group _deadpush already exists")
        except KeyError:
            _sudo(["groupadd", "--system", "_deadpush"])
            lines.append("Created _deadpush system group")
        _sudo([
            "useradd", "--system", "--no-create-home",
            "--shell", "/usr/sbin/nologin",
            "--home-dir", "/var/empty",
            "--gid", "_deadpush",
            "_deadpush",
        ])
        lines.append("Created _deadpush system user")

    if not _deadpush_account_valid():
        raise RuntimeError(
            "_deadpush account setup failed — user not visible to the system. "
            "Try: sudo dscl . -delete /Users/_deadpush && deadpush protect --daemon"
        )


def _ensure_hardened_venv(_sudo, lines: list[str]) -> None:
    """Install deadpush into a dedicated venv owned by _deadpush (not the dev venv)."""

    venv = _HARDENED_VENV_DIR
    py = venv / "bin" / "python"
    if not py.exists():
        bootstrap_py = _find_bootstrap_python()
        _sudo([bootstrap_py, "-m", "venv", str(venv)])
        lines.append(f"Created hardened venv at {venv}")
    else:
        lines.append(f"Hardened venv already exists at {venv}")

    _sudo(["chown", "-R", "_deadpush:_deadpush", str(venv)])

    # How we populate the hardened venv depends on how deadpush itself was installed:
    #  - dev/source checkout (a pyproject.toml sits above the package): install the
    #    working tree so hardened mode tracks local changes.
    #  - normal pip/wheel install (site-packages has no pyproject.toml): install the
    #    matching version from PyPI. Previously this path raised "source not found",
    #    so `deadpush protect --hardened` was broken for every pip-installed user.
    source = _deadpush_source_root()
    if (source / "pyproject.toml").exists():
        target = str(source)
        origin = f"source {source}"
    else:
        from . import __version__ as _dp_version
        target = f"deadpush=={_dp_version}"
        origin = f"PyPI ({target})"

    pip = str(venv / "bin" / "pip")
    _sudo([pip, "install", "--upgrade", "pip"], check=False)
    _sudo([pip, "install", target])
    _sudo(["chown", "-R", "_deadpush:_deadpush", str(venv)])
    lines.append(f"Installed deadpush into hardened venv from {origin}")


def _setup_hardened_policy(repo_root: Path, _sudo, lines: list[str]) -> None:
    """Create the root-owned policy dir + marker for a hardened install.

    This is what makes hardened mode a real boundary: guardrail policy
    (rules.json / learned_patterns.json) and the fail-closed marker live here,
    owned by _deadpush and readable-but-not-writable by the user, so a same-UID
    agent cannot weaken enforcement by editing in-repo `.deadpush/` files. Any
    existing in-repo policy is migrated in so the operator's current config
    carries over.
    """
    import json as _json
    import tempfile
    import time as _time
    from .config import hardened_policy_dir, hardened_install_marker

    pol_root = _HARDENED_STATE_DIR / "policy"
    pol_dir = hardened_policy_dir(repo_root)
    _sudo(["mkdir", "-p", str(pol_dir)])

    def _install_file(dst: Path, content: str) -> None:
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".tmp", delete=False, encoding="utf-8") as tf:
                tf.write(content)
                tmp = tf.name
            _sudo(["cp", tmp, str(dst)])
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # Migrate existing in-repo policy so the operator's current config carries over.
    for fname in ("rules.json", "learned_patterns.json"):
        src = repo_root / ".deadpush" / fname
        dst = pol_dir / fname
        if src.exists() and not dst.exists():
            try:
                _install_file(dst, src.read_text(encoding="utf-8"))
            except Exception:
                pass

    # Root-owned marker: its presence is the trustworthy signal that this repo
    # is a hardened install (the agent can neither forge nor delete it).
    payload = _json.dumps({
        "mode": "hardened",
        "installed_at": _time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "repo": str(repo_root),
    }, indent=2)
    _install_file(hardened_install_marker(repo_root), payload)

    # _deadpush owns the policy tree; perms let the user (and thus its git hooks)
    # traverse + read the authoritative policy but never write it.
    _sudo(["chown", "-R", "_deadpush:_deadpush", str(pol_root)])
    _sudo(["chmod", "-R", "a+rX", str(pol_root)])
    lines.append(f"Created root-owned policy dir {pol_dir}")


def setup_hardened_environment(repo_root: Path, auto_load: bool = True) -> str:
    """One-time sudo setup for hardened mode: create _deadpush user, state
    directory, repo ACLs, install daemon plist, and load it.

    Uses ``sudo`` for every privileged operation. The user will be prompted
    for their password once (then cached for 5 minutes on macOS).

    Returns a multi-line summary of what was done.
    """
    import subprocess
    import sys as _sys

    lines = []

    def _sudo(cmd, check=True, timeout=60):
        full = ["sudo"] + cmd
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(full)} failed: {r.stderr.strip()}")
        return r

    _ensure_deadpush_account(_sudo, lines)

    # Create state directory. 0711 (not 0700) so the user can *traverse* it to
    # execute the root-owned hardened venv interpreter and read the root-owned
    # policy — but not list it, and secret files (control token) stay 0600.
    state = _HARDENED_STATE_DIR
    _sudo(["mkdir", "-p", str(state)])
    _sudo(["chown", "_deadpush:_deadpush", str(state)])
    _sudo(["chmod", "0711", str(state)])
    lines.append(f"Created state dir {state}")

    _ensure_hardened_venv(_sudo, lines)

    # Root-owned policy + fail-closed marker (agent cannot tamper with these).
    _setup_hardened_policy(repo_root, _sudo, lines)

    _apply_hardened_traverse_acls(repo_root, _sudo)
    lines.append(f"Granted _deadpush traverse ACLs to {repo_root}")

    # Intervention ACLs on repo (quarantine, restore, feedback)
    _apply_hardened_repo_acls(repo_root, _sudo)
    lines.append(f"Granted _deadpush intervention ACLs on {repo_root}")

    # 5. Write plist / systemd unit in hardened mode
    autostart_info = setup_autostart(repo_root, hardened=True, _sudo=_sudo)
    _ = autostart_info  # we already wrote the unit, just use it
    lines.append("Generated daemon configuration")

    # 6. Load the daemon
    if auto_load:
        if _sys.platform == "darwin":
            plist_path = _scoped_plist_path(repo_root, hardened=True)
            label = _scoped_plist_label(repo_root)
            _launchctl_bootstrap_system(plist_path, label, _sudo, repo_root)
            lines.append(f"Loaded launchd daemon: {plist_path}")
        elif _sys.platform.startswith("linux"):
            rid = _repo_id(str(repo_root))
            _sudo(["systemctl", "daemon-reload"])
            _sudo(["systemctl", "enable", "--now", f"deadpush-guardian.{rid}.service"])
            lines.append("Enabled and started systemd service")

    lines.append("")
    lines.append("Hardened mode setup complete.")
    lines.append("The guardian now runs as _deadpush — the AI agent cannot kill or modify it.")
    return "\n".join(lines)
