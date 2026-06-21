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
import fcntl
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
def setup_logging(log_file: Optional[Path] = None, level=logging.INFO, daemon: bool = False):
    """Setup logging.

    In daemon mode: ONLY file logging (headless/silent on stdout/stderr).
    Foreground: file + console.
    """
    if log_file is None:
        log_file = Path.home() / ".deadpush" / "guardian.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)

    handlers = [logging.FileHandler(log_file)]
    if not daemon:
        handlers.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
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
        self.lock_fd = None
        self.logger = logging.getLogger("deadpush.guardian")

    def acquire_lock(self) -> bool:
        """Try to acquire exclusive lock."""
        try:
            self.lock_fd = open(self.lockfile, "w")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (IOError, OSError):
            if self.lock_fd:
                self.lock_fd.close()
            return False

    def write_pid(self):
        pid = os.getpid()
        with self.pidfile.open("w") as f:
            f.write(str(pid))
        self.logger.info(f"Daemon started with PID {pid}")

    def cleanup(self):
        if self.lock_fd:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                self.lock_fd.close()
            except Exception:
                pass
        if self.pidfile.exists():
            try:
                self.pidfile.unlink()
            except Exception:
                pass
        if self.lockfile.exists():
            try:
                self.lockfile.unlink()
            except Exception:
                pass

    def is_running(self) -> bool:
        if not self.pidfile.exists():
            return False
        try:
            with self.pidfile.open() as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False


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

    def __init__(self):
        self.score = 100
        self.incidents = []
        self.recent_window = 60  # seconds
        # Multi-agent / session tracking
        self.events_count = 0
        self.session_start = datetime.now()
        self.recent_paths: list[str] = []  # last ~10 distinct-ish paths touched

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
                # Light / safe action: run a quick debris scan on the repo root (non-blocking hint)
                # For deep analysis agents can still call full scan, this is for "is it safe?" quick check
                from .debris import DebrisDetector
                detector = DebrisDetector(handler.config)
                # Quick: just scan for high-risk debris without full graph
                files = []  # could use crawler but to keep light, just note
                # In practice, return current quarantine + score as "analysis"
                result = {
                    "message": "Light analysis triggered. Current guardian state returned.",
                    "safety": handler.safety_score.get_summary(),
                    "quarantine_count": len(handler.quarantine.list_quarantined()),
                    "recommendation": "Use /quarantine-list for details. Run full `deadpush scan` for deep static analysis if needed."
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

    def __init__(self, guardian_handler, port: int | None = None):
        self.guardian_handler = guardian_handler
        self.requested_port = port or self.DEFAULT_PORT
        self.port = None
        self.httpd = None
        self.thread = None
        self.logger = logging.getLogger("deadpush.guardian")
        self.port_file = Path.home() / ".deadpush" / "guardian.control.port"

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

    def __init__(self, config, intervention: bool = True, strict_mode: bool = False, logger=None):
        self.config = config
        self.intervention = intervention
        self.strict_mode = strict_mode
        self.logger = logger or logging.getLogger("deadpush.guardian")
        self.detector = DebrisDetector(config)
        self.quarantine = QuarantineManager(config.repo_root)
        self.safety_score = SessionSafetyScore()
        self.session_mgr = SessionManager()

        # Rate limiting for multi-agent scenarios
        self.last_intervention_ts = 0.0
        self.cooldown_seconds = 0.5  # Aggressive but not spammy

    def on_created(self, event):
        if event.is_directory:
            return
        self._evaluate(Path(event.src_path), event_type="created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._evaluate(Path(event.src_path), event_type="modified")

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

            # Rate limiting for multi-agent
            now = time.time()
            if now - self.last_intervention_ts < self.cooldown_seconds:
                return

            try:
                rel = path.relative_to(self.config.repo_root).as_posix()
            except (ValueError, Exception):
                return

            filename = path.name.lower()

            # === STEP 1: Check blocked files (deadpush.toml blocked_files/blocked_patterns) ===
            if self.config.is_blocked(rel):
                self._intervene_blocked(path, rel, event_type)
                return

            # === STEP 2: Run full guardrail pipeline ===
            from .intercept import _run_guardrails, _write_feedback, GuardrailResult, FEEDBACK_DIR

            old_source = self._git_show(rel)
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return

            result = _run_guardrails(
                path, self.config.repo_root, self.config,
                _old_source=old_source, _rel_path_override=rel,
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
                from .crawler import FileInfo
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

        except Exception as e:
            self.logger.debug(f"Evaluation error on {path}: {e}")

    # ------------------------------------------------------------------
    # Intervention actions
    # ------------------------------------------------------------------
    def _intervene_blocked(self, path: Path, rel: str, event_type: str):
        """Intervene when a blocked file is written (claude.md, etc.)."""
        from .intercept import GuardrailResult, Violation, _write_feedback, FEEDBACK_DIR

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
# Main Runner with Improved Daemon Support
# =============================================================================
def run_guardian(intervention: bool = True, daemon: bool = False, strict: bool = False):
    if not WATCHDOG_AVAILABLE:
        print("Error: watchdog package required. pip install deadpush[watch]")
        return

    config = load_config()
    logger = setup_logging(daemon=daemon)

    pid_dir = Path.home() / ".deadpush"
    pid_dir.mkdir(parents=True, exist_ok=True)
    pidfile = pid_dir / "guardian.pid"
    lockfile = pid_dir / "guardian.lock"

    daemon_mgr = DaemonManager(pidfile, lockfile)

    if daemon_mgr.is_running():
        logger.warning("Guardian is already running.")
        return

    if not daemon_mgr.acquire_lock():
        logger.error("Could not acquire lock. Another instance may be running.")
        return

    handler = GuardianHandler(config, intervention=intervention, strict_mode=strict, logger=logger)

    # Start the Local Control Interface so AI agents can query/interact autonomously
    # (status, quarantine list, safety score, light analysis, safe restores).
    # Works for both foreground `guard` and `--daemon`.
    control_server = GuardianControlServer(handler)
    control_server.start()
    if control_server.port:
        logger.info(f"Local control interface on http://127.0.0.1:{control_server.port} (port file: {control_server.port_file})")
        logger.info("AI agents can now query the guardian autonomously (GET /status, /quarantine-list, etc.)")
        atexit.register(control_server.stop)
    else:
        logger.warning("Local control interface could not be started (agents can fall back to `deadpush status` / CLI)")

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

            # Headless daemon: ensure no stray output to terminal (even if stdio inherited).
            # Logging is already file-only because daemon=True was passed to setup_logging.
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            with open(os.devnull, "w") as devnull:
                os.dup2(devnull.fileno(), sys.stdout.fileno())
                os.dup2(devnull.fileno(), sys.stderr.fileno())

            daemon_mgr.write_pid()
            atexit.register(daemon_mgr.cleanup)

            _run_observer(handler, logger)
        except Exception as e:
            logger.error(f"Daemon failed: {e}")
            daemon_mgr.cleanup()
    else:
        logger.info("Starting in FOREGROUND mode...")
        daemon_mgr.write_pid()
        atexit.register(daemon_mgr.cleanup)
        _run_observer(handler, logger)


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

                time.sleep(2)
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
def setup_autostart(repo_root: Path) -> str:
    """Generate OS-specific auto-start configuration for the guardian daemon.

    This helps fulfill "survive across sessions/reboots with minimal user intervention".

    - On Linux: writes ~/.config/systemd/user/deadpush-guardian.service
    - On macOS: writes ~/Library/LaunchAgents/com.deadpush.guardian.plist

    Returns a string with the file path + exact commands the user should run to enable it.
    Safe to call multiple times (idempotent overwrite).
    Does not auto-enable (user must run the printed commands, for safety/permissions).
    """
    import sys as _sys
    home = Path.home()
    exe = _sys.executable  # use the exact python that has deadpush installed

    if _sys.platform.startswith("linux"):
        unit_dir = home / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / "deadpush-guardian.service"
        content = f"""[Unit]
Description=deadpush AI Agent Guardian - persistent background protection for vibe coding
After=network.target

[Service]
Type=simple
ExecStart={exe} -m deadpush.cli guard --daemon
Restart=always
RestartSec=5
WorkingDirectory={repo_root}
# Nice low priority so it doesn't interfere with agents
Nice=10
# Inherit PATH so 'deadpush' etc work if needed
Environment="PATH=/usr/local/bin:/usr/bin:/bin:{home}/.local/bin"

[Install]
WantedBy=default.target
"""
        unit_path.write_text(content)
        return f"""Linux systemd --user unit written:
  {unit_path}

To enable auto-start on login / reboot (run these once):
  systemctl --user daemon-reload
  systemctl --user enable --now deadpush-guardian.service

Useful commands:
  systemctl --user status deadpush-guardian.service
  journalctl --user -u deadpush-guardian -f   # live logs (file logs also at ~/.deadpush/guardian.log)
  systemctl --user stop deadpush-guardian.service
"""

    elif _sys.platform == "darwin":
        plist_dir = home / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist_path = plist_dir / "com.deadpush.guardian.plist"
        log_dir = home / ".deadpush"
        log_dir.mkdir(parents=True, exist_ok=True)
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.deadpush.guardian</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>-m</string>
        <string>deadpush.cli</string>
        <string>guard</string>
        <string>--daemon</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{repo_root}</string>
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
    <string>{log_dir}/guardian.launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/guardian.launchd.err.log</string>
</dict>
</plist>
"""
        plist_path.write_text(content)
        return f"""macOS launchd plist written:
  {plist_path}

To load (start now + on login/reboot):
  launchctl load {plist_path}

To unload / stop:
  launchctl unload {plist_path}

Logs: tail -f {log_dir}/guardian.launchd.*.log
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