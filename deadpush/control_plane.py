"""Localhost HTTP control plane and dashboard for the guardian."""

from __future__ import annotations

import errno
import json
import logging
import os
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

from .intercept import FEEDBACK_DIR
from .state import scoped_log_file, scoped_portfile, scoped_token_file, state_dir as _state_dir

def _load_or_create_control_token(repo_root: Path, hardened: bool = False) -> str:
    """Return the control-server bearer token, creating it (0600) if absent.

    In hardened mode the token lives under the root/_deadpush-owned state dir
    with 0600 perms, so a same-UID agent cannot read it and therefore cannot
    call the mutating control endpoints (allowlist changes, quarantine restore).
    In soft mode it is user-owned (the agent could read it) — soft mode is
    deterrence, not a hard boundary — but it still blocks other local users.
    """
    import secrets

    token_file = scoped_token_file(repo_root, hardened)
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
        log_path = scoped_log_file(repo_root, hardened)

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
                    "recent_incidents_count": score.recent_incident_count(),
                    "quarantine_count": len(handler.quarantine.list_quarantined()),
                    "intervention_enabled": handler.intervention,
                    "strict_mode": handler.strict_mode,
                    "fanotify": handler.fanotify_status(),
                    "pipeline": handler.pipeline_status(),
                    "gpc": handler.gpc_status(),
                }
                self._send_json(data)
            elif path == "/safety-score":
                self._send_json({"safety_score": handler.safety_score.get_summary(), "details": handler.safety_score.get_session_summary()})
            elif path == "/recent-incidents":
                limit = int(qs.get("limit", [10])[0])
                recent = handler.safety_score.get_recent_incidents(limit)
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
            self.port_file = scoped_portfile(repo_root, hardened)
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
                if e.errno == errno.EADDRINUSE:
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
