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
import fcntl
import functools
import hashlib
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    Observer = None
    FileSystemEventHandler = None
    WATCHDOG_AVAILABLE = False

from .config import load_config
from .debris import DebrisDetector
from .intercept import FEEDBACK_DIR
from .session import SessionManager

# For Local Control Interface (AGENT priority 4 - for automatic interaction by Claude/Cursor/etc agents)
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs


# =============================================================================
# Logging
# =============================================================================
from logging.handlers import RotatingFileHandler

def setup_logging(log_file: Optional[Path] = None, level=logging.INFO, daemon: bool = False, hardened: bool = False):
    """Setup logging.

    In daemon mode: ONLY file logging (headless/silent on stdout/stderr).
    Foreground: file + console.
    Uses RotatingFileHandler (10MB × 5 files) to prevent unbounded growth.
    """
    if log_file is None:
        log_file = _state_dir(hardened) / "guardian.log"
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

    def write_pid(self):
        pid = os.getpid()
        with self.pidfile.open("w") as f:
            f.write(str(pid))
        # Store process start time (monotonic nanoseconds since boot)
        start_time = time.clock_gettime(time.CLOCK_MONOTONIC)
        with self.startfile.open("w") as f:
            f.write(str(start_time))
        self.logger.info(f"Daemon started with PID {pid}")

    def cleanup(self):
        if self.lock_fd:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                self.lock_fd.close()
            except Exception:
                pass
        for f in (self.pidfile, self.lockfile, self.startfile, self.holderfile):
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass

    def force_cleanup(self):
        """Force remove all daemon state files (for stale lock recovery)."""
        for f in (self.pidfile, self.lockfile, self.startfile, self.holderfile):
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
        # to prevent false positive from PID reuse
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
                        days = 0
                        if len(parts) == 2:
                            days = int(parts[0])
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

    def quarantine(self, path: Path, reason: str) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = self.quarantine_dir / f"{timestamp}_{path.name}"
        try:
            path.rename(dest)
            with dest.with_suffix(dest.suffix + ".reason").open("w") as f:
                f.write(f"Quarantined at {datetime.now()}\nReason: {reason}\nOriginal path: {path}\n")
            return dest
        except Exception as e:
            logging.getLogger("deadpush.guardian").error(f"Failed to quarantine {path}: {e}")
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

    def __init__(self, hardened: bool = False):
        self.score = 100
        self.incidents = []
        self.recent_window = 60  # seconds
        # Multi-agent / session tracking
        self.events_count = 0
        self.session_start = datetime.now()
        self.recent_paths: list[str] = []  # last ~10 distinct-ish paths touched
        self.hardened = hardened

    def _score_path(self) -> Path:
        """Path to the safety score JSON file."""
        return _state_dir(self.hardened) / "safety_score.json"

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
        if self.score >= 90: return "🟢 Excellent"
        if self.score >= 70: return "🟡 Good"
        if self.score >= 50: return "🟠 Caution"
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
  <a href="/dashboard">&#x21bb; Refresh</a>
</div>
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
        return provided_token == server_token

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

    def do_GET(self):
        if not self._require_auth():
            return
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
                self._redirect("/dashboard/quarantine")
                return

            elif path == "/allowlist/add":
                pattern = params.get("pattern", "")
                description = params.get("description", "")
                if pattern:
                    import re
                    rc.add_allowed_pattern(pattern, description)
                self._redirect("/dashboard/allowlist")
                return

            elif path == "/allowlist/remove":
                pattern = params.get("pattern", "")
                if pattern:
                    rc.remove_allowed_pattern(pattern)
                self._redirect("/dashboard/allowlist")
                return

            elif path == "/allowlist/reset":
                rc.reset()
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

    def __init__(self, config, intervention: bool = True, strict_mode: bool = False, daemon: bool = False, logger=None, hardened: bool = False):
        self.config = config
        self.intervention = intervention
        self.strict_mode = strict_mode
        self.daemon = daemon
        self.hardened = hardened
        self.logger = logger or logging.getLogger("deadpush.guardian")
        self.detector = DebrisDetector(config)
        self.quarantine = QuarantineManager(config.repo_root)
        self.safety_score = SessionSafetyScore(hardened=hardened)
        self.safety_score.load_score()
        self.session_mgr = SessionManager()

        # Dynamic rate limiting (based on safety score)
        self.last_intervention_ts = 0.0
        self._pending_events: deque[tuple[Path, str]] = deque()

        # Shadow process (watching for crashes)
        self.shadow_process: subprocess.Popen | None = None

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

    # ------------------------------------------------------------------
    # Shadow process lifecycle
    # ------------------------------------------------------------------
    def _start_shadow(self):
        if not self.daemon:
            return
        if self.shadow_process is not None and self._shadow_alive():
            return
        pidfile = _scoped_pidfile(self.config.repo_root, self.hardened)
        respawn_cmd = [sys.executable, "-m", "deadpush.cli", "guard", "--daemon"]
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

    # ------------------------------------------------------------------
    # MCP suspension (disables agent's MCP access when score is critical)
    # ------------------------------------------------------------------
    def _suspend_mcp(self, reason: str):
        """Write a suspension flag that the MCP server checks at startup."""
        suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
        try:
            suspend_file.parent.mkdir(parents=True, exist_ok=True)
            suspend_file.write_text(reason, encoding="utf-8")
            self.logger.warning(f"MCP suspended: {reason}")
        except Exception as e:
            self.logger.error(f"Failed to write MCP suspension file: {e}")

    def _unsuspend_mcp(self):
        """Remove the suspension flag so MCP can start again."""
        suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
        try:
            if suspend_file.exists():
                suspend_file.unlink()
                self.logger.info("MCP unsuspended")
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

    def _restore_from_git(self, rel: str) -> bool:
        """Restore a file from git HEAD. Returns True on success."""
        old = self._git_show(rel)
        if not old:
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
            skip_names = {"__pycache__", ".git", "node_modules",
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

    def _process_event(self, path: Path, event_type: str):
        """Core single-event evaluation pipeline."""
        now = time.time()
        try:
            rel = path.relative_to(self.config.repo_root).as_posix()
        except (ValueError, Exception):
            return

        self.last_intervention_ts = now

        # === STEP 1: Check blocked files (deadpush.toml blocked_files/blocked_patterns) ===
        if self.config.is_blocked(rel):
            self._intervene_blocked(path, rel, event_type)
            return

        # === STEP 2: Run full guardrail pipeline ===
        from .intercept import _run_guardrails, _write_feedback, FEEDBACK_DIR

        old_source = self._git_show(rel)

        result = _run_guardrails(
            path, self.config.repo_root, self.config,
            old_source=old_source, rel_path_override=rel,
        )

        # === STEP 3: Enforce guardrail results ===
        if not result.allowed:
            self._intervene_guardrails(path, rel, result, event_type, old_source=old_source)
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

        old_source = self._git_show(rel)
        self._quarantine_and_restore(path, rel, result, old_source)

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

    def _intervene_guardrails(self, path: Path, rel: str, result, event_type: str, old_source: str = ""):
        """Intervene when guardrails detect block-level violations."""
        from .intercept import _write_feedback, FEEDBACK_DIR

        self.last_intervention_ts = time.time()
        penalty = min(25, 5 * len(result.violations))
        score = self.safety_score.report_incident(penalty, f"Guardrail block: {result.violations[0].description}", str(path))

        self._quarantine_and_restore(path, rel, result, old_source)

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

    def _quarantine_and_restore(self, path: Path, rel: str, result, old_source: str):
        """Quarantine the violating file and restore the original from git."""
        if self.intervention and path.exists():
            reason = result.violations[0].description if result.violations else "guardrail violation"
            try:
                quarantined = self.quarantine.quarantine(path, reason)
                self.logger.info(f"Quarantined: {quarantined}")
            except Exception as e:
                self.logger.error(f"Failed to quarantine {path}: {e}")
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass

        # Restore original from git (if the file existed before)
        if old_source:
            self._restore_from_git(rel)

    def _intervene_blocking_debris(self, path: Path, blocking_items, event_type: str):
        self.last_intervention_ts = time.time()
        for item in blocking_items:
            score = self.safety_score.report_incident(12, item.reason, str(path))
            try:
                self.session_mgr.record_incident({
                    "type": "blocking_debris", "reason": item.reason,
                    "file": str(path), "score": score,
                })
                self.session_mgr.update_safety_score(score)
            except Exception:
                pass
            self.logger.warning(
                f"INTERVENTION [{event_type.upper()}] {item.category} in {path.name} | "
                f"{item.reason} | Safety: {score}/100"
            )
            if self.intervention and item.category == "hardcoded_secret":
                try:
                    if path.exists():
                        quarantined = self.quarantine.quarantine(path, item.reason)
                        self.logger.critical(f"QUARANTINED FILE WITH HARDCODED SECRET: {quarantined}")
                except Exception as e:
                    self.logger.error(f"Failed to quarantine secret file: {e}")


# =============================================================================
# State directory management
# =============================================================================

_HARDENED_STATE_DIR = Path("/var/db/deadpush")


def _state_dir(hardened: bool = False) -> Path:
    """Get the state directory for a repo.
    
    Args:
        hardened: If True, returns /var/db/deadpush (requires root/_deadpush).
                  If False, returns ~/.deadpush (user-writable).
    """
    if hardened:
        return _HARDENED_STATE_DIR
    return Path.home() / ".deadpush"


def _is_hardened(hardened: bool = False) -> bool:
    """Check if running in hardened mode.
    
    Args:
        hardened: Explicit hardened flag.
    """
    return hardened


# =============================================================================
# Repo-scoped resource helpers
# =============================================================================
@functools.lru_cache(maxsize=16)
def _repo_id(repo_root: str) -> str:
    """Short deterministic hash from repo root path."""
    return hashlib.sha256(repo_root.encode()).hexdigest()[:12]


def _scoped_pidfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state_dir(hardened) / f"guardian.{_repo_id(str(repo_root))}.pid"


def _scoped_lockfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state_dir(hardened) / f"guardian.{_repo_id(str(repo_root))}.lock"


def _scoped_portfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state_dir(hardened) / f"guardian.control.port.{_repo_id(str(repo_root))}"


def _scoped_suspend_file(repo_root: Path, hardened: bool = False) -> Path:
    return _state_dir(hardened) / f"mcp_suspended.{_repo_id(str(repo_root))}"


def _scoped_plist_label(repo_root: Path) -> str:
    return f"com.deadpush.guardian.{_repo_id(str(repo_root))}"


def _scoped_plist_path(repo_root: Path, hardened: bool = False) -> Path:
    if hardened:
        return Path("/Library/LaunchDaemons") / f"com.deadpush.guardian.{_repo_id(str(repo_root))}.plist"
    return Path.home() / "Library" / "LaunchAgents" / f"com.deadpush.guardian.{_repo_id(str(repo_root))}.plist"


def _scoped_systemd_unit_path(repo_root: Path, hardened: bool = False) -> Path:
    """Path for Linux systemd unit file (user or system scope)."""
    rid = _repo_id(str(repo_root))
    if hardened:
        return Path("/etc/systemd/system") / f"deadpush-guardian.{rid}.service"
    return Path.home() / ".config" / "systemd" / "user" / f"deadpush-guardian.{rid}.service"


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
    except Exception as e:
        return None


# =============================================================================
# Main Runner with Improved Daemon Support
# =============================================================================
def run_guardian(intervention: bool = True, daemon: bool = False, strict: bool = False, hardened: bool = False):
    if not WATCHDOG_AVAILABLE:
        print("Error: watchdog package required. pip install deadpush[watch]")
        return

    config = load_config()

    logger = setup_logging(daemon=daemon, hardened=hardened)

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

    # Start shadow process (re-spawns guardian if it crashes)
    # Not needed in hardened mode — launchd handles restart via KeepAlive
    shadow_proc = None
    if not hardened:
        # We'll create handler after fork, but start shadow here since it runs
        # in a new session and is immune to fork issues
        pass  # Shadow will be started post-fork in the child

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
            logger = setup_logging(daemon=True, hardened=hardened)

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

            daemon_mgr.write_pid()
            atexit.register(daemon_mgr.cleanup)

            handler = GuardianHandler(config, intervention=intervention, strict_mode=strict, daemon=daemon, logger=logger, hardened=hardened)
            control_server = GuardianControlServer(handler, repo_root=config.repo_root, hardened=hardened)

            # Start shadow process in the final daemon process (post-fork)
            if not hardened:
                handler._start_shadow()

            # Start control server in the final daemon process (post-fork)
            _start_control_server(control_server, logger, config.repo_root, hardened)

            _run_observer(handler, logger)
        except Exception as e:
            logger.error(f"Daemon failed: {e}")
            daemon_mgr.cleanup()
    else:
        logger.info("Starting in FOREGROUND mode...")
        daemon_mgr.write_pid()
        atexit.register(daemon_mgr.cleanup)

        handler = GuardianHandler(config, intervention=intervention, strict_mode=strict, daemon=daemon, logger=logger, hardened=hardened)
        control_server = GuardianControlServer(handler, repo_root=config.repo_root, hardened=hardened)

        # Start shadow process
        if not hardened:
            handler._start_shadow()

        _start_control_server(control_server, logger, config.repo_root, hardened)

        _run_observer(handler, logger)


def _start_control_server(control_server, logger, repo_root, hardened):
    """Start the local HTTP control interface and log its status.
    Safe to call after daemon fork (no threading before fork)."""
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


def _run_observer(handler: GuardianHandler, logger):
    """Run the filesystem observer with automatic recovery on crashes.

    This improves daemon reliability: if the watcher thread dies (e.g. transient FS error,
    handler bug), we log, wait with backoff, and restart the observer without killing the daemon.
    """
    if Observer is None:
        logger.error("Cannot start observer: watchdog not installed. Use `pip install deadpush[watch]`")
        return

    backoff = 1
    max_backoff = 30

    def shutdown(signum, frame):
        logger.info("Guardian shutting down gracefully...")
        try:
            handler.safety_score.mark_clean_shutdown()
        except Exception:
            pass
        if 'observer' in locals() and observer:
            try:
                observer.stop()
            except Exception:
                pass
        # note: sys.exit will be caught by outer if needed

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    observer = None
    try:
        while True:
            try:
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
                time.sleep(1)
            except Exception as e:
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
    finally:
        if observer:
            try:
                observer.stop()
                observer.join(timeout=3)
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
def setup_autostart(repo_root: Path, hardened: bool = False) -> str:
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
    exe = _sys.executable
    rid = _repo_id(str(repo_root))

    if _sys.platform.startswith("linux"):
        unit_path = _scoped_systemd_unit_path(repo_root, hardened)
        unit_dir = unit_path.parent
        unit_dir.mkdir(parents=True, exist_ok=True)
        user_part = "" if hardened else "--user"
        env_line = f'Environment="PATH=/usr/local/bin:/usr/bin:/bin:{home}/.local/bin"'
        wanted_by = "multi-user.target" if hardened else "default.target"
        content = f"""[Unit]
Description=deadpush AI Agent Guardian ({rid}) - persistent background protection
After=network.target

[Service]
Type=simple
ExecStart={exe} -m deadpush.cli guard --daemon{' --hardened' if hardened else ''}
Restart=always
RestartSec=5
WorkingDirectory={repo_root}
Nice=10
{env_line}
{'User=_deadpush' if hardened else ''}

[Install]
WantedBy={wanted_by}
"""
        unit_path.write_text(content)
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
        log_dir.mkdir(parents=True, exist_ok=True)
        hardened_args = ""
        user_name = ""
        if hardened:
            hardened_args = "\n        <string>--hardened</string>"
            user_name = """    <key>UserName</key>
    <string>_deadpush</string>
"""
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
        <string>deadpush.cli</string>
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
        plist_path.write_text(content)
        return f"""macOS{' LaunchDaemon' if hardened else ' LaunchAgent'} plist written:
  {plist_path}

To load (start now + on{' boot' if hardened else ' login/reboot'}):
  {'sudo launchctl load -w' if hardened else 'launchctl load'} {plist_path}

To unload / stop:
  {'sudo launchctl unload -w' if hardened else 'launchctl unload'} {plist_path}

Logs: tail -f {log_dir}/guardian.{rid}.launchd.*.log
(Also file logs at {log_dir}/guardian.log )
"""

    else:
        return f"""Auto-start unit generation not supported on this platform ({_sys.platform}).
You can still achieve "survive reboot" by:
  - Adding `deadpush guard --daemon` to your shell's startup (~/.bashrc, ~/.zshrc, etc) with nohup or similar, or
  - Using your distro's service manager manually pointing at: {exe} -m deadpush.cli guard --daemon
  - Or cron with @reboot (advanced).
See `deadpush guard --daemon` for the core persistent mode.
"""


# =============================================================================
# Hardened environment setup (privilege separation)
# =============================================================================
def setup_hardened_environment(repo_root: Path, auto_load: bool = True) -> str:
    """One-time sudo setup for hardened mode: create _deadpush user, state
    directory, repo ACLs, install daemon plist, and load it.

    Uses ``sudo`` for every privileged operation. The user will be prompted
    for their password once (then cached for 5 minutes on macOS).

    Returns a multi-line summary of what was done.
    """
    import os
    import pwd
    import grp
    import subprocess
    import sys as _sys

    lines = []

    def _sudo(cmd, check=True, timeout=60):
        full = ["sudo"] + cmd
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(full)} failed: {r.stderr.strip()}")
        return r

    # 1. Create _deadpush group (dedicated, minimal privileges)
    try:
        grp.getgrnam("_deadpush")
        lines.append("Group _deadpush already exists")
    except KeyError:
        if _sys.platform == "darwin":
            _sudo(["dscl", ".", "-create", "/Groups/_deadpush", "PrimaryGroupID", "499"])
            lines.append("Created _deadpush group (GID 499)")
        else:
            _sudo(["groupadd", "--system", "_deadpush"])
            lines.append("Created _deadpush system group")

    # 2. Create _deadpush user (platform-specific)
    try:
        pwd.getpwnam("_deadpush")
        lines.append("User _deadpush already exists")
    except KeyError:
        if _sys.platform == "darwin":
            _sudo([
                "dscl", ".", "-create", "/Users/_deadpush",
                "UniqueID", "499",
                "PrimaryGroupID", "499",  # Use _deadpush group, not wheel
                "NFSHomeDirectory", "/var/empty",
                "UserShell", "/usr/bin/false",
                "RealName", "deadpush Guardian",
            ])
            lines.append("Created _deadpush user (UID 499, system account)")
        else:
            _sudo([
                "useradd", "--system", "--no-create-home",
                "--shell", "/usr/sbin/nologin",
                "--home-dir", "/var/empty",
                "--gid", "_deadpush",
                "_deadpush",
            ])
            lines.append("Created _deadpush system user")

    # 3. Create state directory
    state = _HARDENED_STATE_DIR
    _sudo(["mkdir", "-p", str(state)])
    _sudo(["chown", "_deadpush:_deadpush", str(state)])
    _sudo(["chmod", "0700", str(state)])
    lines.append(f"Created state dir {state}")

    # 4. Set ACL on repo so _deadpush can read the tree
    if _sys.platform == "darwin":
        r = _sudo(
            ["chmod", "+a",
             f"_deadpush allow list,readattr,readsecurity,search,read,readattr,readextattr,file_inherit,directory_inherit",
             str(repo_root)],
            check=False, timeout=15,
        )
        if r.returncode == 0:
            lines.append(f"Granted _deadpush read access to {repo_root} (ACL)")

        guardian_dir = repo_root / ".guardian"
        guardian_dir.mkdir(parents=True, exist_ok=True)
        _sudo([
            "chmod", "+a",
            f"_deadpush allow write,append,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit",
            str(guardian_dir),
        ])
        lines.append(f"Granted _deadpush write access to {guardian_dir} (ACL)")
    else:
        _sudo(["setfacl", "-R", "-m", "u:_deadpush:rx", str(repo_root)])
        guardian_dir = repo_root / ".guardian"
        guardian_dir.mkdir(parents=True, exist_ok=True)
        _sudo(["setfacl", "-R", "-m", "u:_deadpush:rwx", str(guardian_dir)])
        lines.append("Set ACLs via setfacl")

    # 5. Write plist / systemd unit in hardened mode
    autostart_info = setup_autostart(repo_root, hardened=True)
    _ = autostart_info  # we already wrote the unit, just use it
    lines.append("Generated daemon configuration")

    # 6. Load the daemon
    if auto_load:
        if _sys.platform == "darwin":
            plist_path = _scoped_plist_path(repo_root, hardened=True)
            _sudo(["launchctl", "load", "-w", str(plist_path)])
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