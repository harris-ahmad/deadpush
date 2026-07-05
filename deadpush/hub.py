"""Global multi-repo hub — one dashboard for all deadpush guardians.

Serves on a fixed localhost port (default 8742) and aggregates status from
``~/.deadpush/repos/<id>/`` plus live ``/status`` from running guardians.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import urlparse

from . import state

logger = logging.getLogger("deadpush.hub")

DEFAULT_HUB_PORT = 8742


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _repo_dir(entry: dict[str, Any]) -> Path:
    path = entry.get("path") or ""
    hardened = entry.get("hardened", False)
    if path:
        return state.repo_state_dir(path, hardened)
    return state.state_dir(hardened) / "repos" / entry["id"]


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_port(repo_dir: Path) -> int | None:
    port_file = repo_dir / "control.port"
    if not port_file.exists():
        return None
    try:
        return int(port_file.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def _fetch_json(url: str, timeout: float = 1.5) -> dict[str, Any] | None:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def _last_log_line(log_path: Path) -> str | None:
    if not log_path.exists():
        return None
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        lines = [ln for ln in text.strip().splitlines() if ln.strip()]
        return lines[-1] if lines else None
    except OSError:
        return None


def _score_label(score: int | None) -> str:
    if score is None:
        return "—"
    if score >= 90:
        return "excellent"
    if score >= 70:
        return "good"
    if score >= 50:
        return "caution"
    return "at_risk"


def _is_meaningful_repo(entry: dict[str, Any], repo_dir: Path) -> bool:
    """Skip orphan state dirs that only contain a stale safety_score.json."""
    if entry.get("running"):
        return True
    path = entry.get("path") or ""
    if path and path not in ("", "/"):
        return True
    if (repo_dir / "guardian.log").exists():
        return True
    manifest = _read_json(repo_dir / "manifest.json")
    if manifest and manifest.get("path") not in (None, "", "/"):
        return True
    return False


def collect_repo_snapshots() -> list[dict[str, Any]]:
    """Build enriched snapshot for every known repo."""
    snapshots: list[dict[str, Any]] = []
    for entry in state.discover_all_repos():
        rid = entry["id"]
        path = entry.get("path") or ""
        label = entry.get("label") or rid
        repo_dir = _repo_dir(entry)
        if not _is_meaningful_repo(entry, repo_dir):
            continue
        if path in ("", "/"):
            label = rid
        running = bool(entry.get("running"))
        port = _read_port(repo_dir)

        score: int | None = None
        score_summary: str | None = None
        quarantine_count = 0
        activity: str | None = None

        if running and port:
            live = _fetch_json(f"http://127.0.0.1:{port}/status")
            if live:
                raw = live.get("safety_score")
                if isinstance(raw, str) and "Score:" in raw:
                    score_summary = raw
                    try:
                        score = int(raw.split("Score:")[1].split("/")[0].strip())
                    except (ValueError, IndexError):
                        pass
                quarantine_count = int(live.get("quarantine_count") or 0)
                activity = live.get("activity_level")

        if score is None:
            data = _read_json(repo_dir / "safety_score.json")
            if data and data.get("score") is not None:
                score = int(data["score"])
                score_summary = f"Score: {score}/100"

        dashboard_url = f"http://127.0.0.1:{port}/dashboard" if port and running else None
        log_path = repo_dir / "guardian.log"

        snapshots.append({
            "id": rid,
            "label": label,
            "path": path,
            "hardened": entry.get("hardened", False),
            "running": running,
            "pid": entry.get("pid"),
            "port": port,
            "score": score,
            "score_class": _score_label(score),
            "score_summary": score_summary,
            "quarantine_count": quarantine_count,
            "activity": activity,
            "dashboard_url": dashboard_url,
            "log_path": str(log_path) if log_path.exists() else None,
            "last_log_line": _last_log_line(log_path),
            "state_dir": str(repo_dir),
        })
    return snapshots


HUB_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>deadpush Hub</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #0d1117; color: #c9d1d9; padding: 24px; max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #58a6ff; font-size: 1.75rem; }}
  .subtitle {{ color: #8b949e; margin: 8px 0 20px; font-size: 14px; }}
  .live {{ color: #3fb950; font-size: 12px; margin-left: 12px; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 14px 18px; min-width: 140px; }}
  .card h3 {{ color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }}
  .card .val {{ font-size: 26px; font-weight: 600; margin-top: 6px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 13px; }}
  th {{ color: #8b949e; font-weight: 600; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
  .badge.running {{ background: #3fb95020; color: #3fb950; }}
  .badge.stopped {{ background: #484f5820; color: #8b949e; }}
  .score {{ font-weight: 600; }}
  .score.excellent {{ color: #3fb950; }}
  .score.good {{ color: #58a6ff; }}
  .score.caution {{ color: #d29922; }}
  .score.at_risk {{ color: #f85149; }}
  .score.none {{ color: #484f58; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .path {{ color: #484f58; font-size: 11px; font-family: ui-monospace, monospace; }}
  .log {{ color: #8b949e; font-size: 11px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .empty {{ color: #484f58; font-style: italic; padding: 32px; text-align: center; }}
</style>
</head>
<body>
<h1>deadpush Hub <span class="live" id="live">● live</span></h1>
<p class="subtitle">All protected repos · updated <span id="ts">{ts}</span></p>
<div class="summary" id="summary">{summary_cards}</div>
<table>
  <thead>
    <tr>
      <th>Repo</th>
      <th>Status</th>
      <th>Score</th>
      <th>Activity</th>
      <th>Quarantine</th>
      <th>Latest log</th>
      <th></th>
    </tr>
  </thead>
  <tbody id="repos">{rows}</tbody>
</table>
<script>
(function() {{
  const es = new EventSource('/api/events');
  es.addEventListener('snapshot', (e) => {{
    try {{
      const data = JSON.parse(e.data);
      document.getElementById('ts').textContent = data.updated;
      document.getElementById('summary').innerHTML = data.summary_html;
      document.getElementById('repos').innerHTML = data.rows_html;
      document.getElementById('live').textContent = '● live';
      document.getElementById('live').style.color = '#3fb950';
    }} catch (_) {{}}
  }});
  es.onerror = () => {{
    document.getElementById('live').textContent = '○ reconnecting';
    document.getElementById('live').style.color = '#d29922';
  }};
}})();
</script>
</body>
</html>"""


def _render_rows(repos: list[dict[str, Any]]) -> str:
    if not repos:
        return '<tr><td colspan="7" class="empty">No repos yet. Run <code>deadpush protect --daemon</code> in a project.</td></tr>'

    rows = []
    for r in repos:
        status_cls = "running" if r["running"] else "stopped"
        status_txt = "RUNNING" if r["running"] else "stopped"
        if r["running"] and r.get("pid"):
            status_txt += f" · {r['pid']}"
        score = r.get("score")
        score_cls = r.get("score_class") or "none"
        score_txt = str(score) if score is not None else "—"
        activity = r.get("activity") or "—"
        q = r.get("quarantine_count", 0)
        log = (r.get("last_log_line") or "—").replace("<", "&lt;")
        path = (r.get("path") or r.get("state_dir") or "").replace("<", "&lt;")
        dash = r.get("dashboard_url")
        links = f'<a href="{dash}" target="_blank">Dashboard</a>' if dash else '<span class="path">—</span>'
        rows.append(f"""<tr>
  <td><strong>{r['label']}</strong><div class="path">{path}</div><div class="path">{r['id']}</div></td>
  <td><span class="badge {status_cls}">{status_txt}</span></td>
  <td><span class="score {score_cls}">{score_txt}</span></td>
  <td>{activity}</td>
  <td>{q}</td>
  <td class="log" title="{log}">{log}</td>
  <td>{links}</td>
</tr>""")
    return "\n".join(rows)


def _render_summary(repos: list[dict[str, Any]]) -> str:
    total = len(repos)
    running = sum(1 for r in repos if r["running"])
    at_risk = sum(1 for r in repos if r.get("score") is not None and r["score"] < 50)
    return f"""
  <div class="card"><h3>Repos</h3><div class="val">{total}</div></div>
  <div class="card"><h3>Running</h3><div class="val" style="color:#3fb950">{running}</div></div>
  <div class="card"><h3>At risk (&lt;50)</h3><div class="val" style="color:#f85149">{at_risk}</div></div>"""


def render_hub_page(repos: list[dict[str, Any]] | None = None) -> str:
    repos = repos if repos is not None else collect_repo_snapshots()
    return HUB_HTML.format(
        ts=_now_iso(),
        summary_cards=_render_summary(repos),
        rows=_render_rows(repos),
    )


def snapshot_payload(repos: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    repos = repos if repos is not None else collect_repo_snapshots()
    return {
        "updated": _now_iso(),
        "repos": repos,
        "summary_html": _render_summary(repos),
        "rows_html": _render_rows(repos),
    }


class ThreadedHubServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class HubHandler(BaseHTTPRequestHandler):
    server: ThreadedHubServer  # type: ignore[assignment]

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, default=str, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def _send_html(self, html: str, code: int = 200) -> None:
        self._send(code, html.encode("utf-8"), "text/html; charset=utf-8")

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if path in ("/", "/hub"):
                self._send_html(render_hub_page())
            elif path == "/api/repos":
                self._send_json({"repos": collect_repo_snapshots(), "updated": _now_iso()})
            elif path == "/api/health":
                self._send_json({"status": "ok", "service": "deadpush-hub"})
            elif path == "/api/events":
                self._handle_sse()
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_sse(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        last_payload = ""
        while True:
            try:
                payload = json.dumps(snapshot_payload(), default=str)
                if payload != last_payload:
                    safe = payload.replace("\n", " ")
                    self.wfile.write(f"event: snapshot\ndata: {safe}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    last_payload = payload
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
            time.sleep(2.0)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def hub_is_running() -> bool:
    pidfile = state.hub_pidfile()
    if not pidfile.exists():
        return False
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        pidfile.unlink(missing_ok=True)
        return False


def hub_url() -> str | None:
    portfile = state.hub_portfile()
    if portfile.exists():
        try:
            port = int(portfile.read_text(encoding="utf-8").strip())
            return f"http://127.0.0.1:{port}"
        except (ValueError, OSError):
            pass
    return f"http://127.0.0.1:{DEFAULT_HUB_PORT}"


def stop_hub() -> bool:
    pidfile = state.hub_pidfile()
    if not pidfile.exists():
        return False
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            try:
                os.kill(pid, 0)
                time.sleep(0.1)
            except OSError:
                break
        else:
            os.kill(pid, signal.SIGKILL)
    except (OSError, ValueError):
        pass
    pidfile.unlink(missing_ok=True)
    state.hub_portfile().unlink(missing_ok=True)
    return True


def run_hub(port: int = DEFAULT_HUB_PORT, *, foreground: bool = True) -> None:
    """Run the hub HTTP server (blocking)."""
    state.state_dir(False).mkdir(parents=True, exist_ok=True)
    state.hub_pidfile().write_text(str(os.getpid()), encoding="utf-8")
    state.hub_portfile().write_text(str(port), encoding="utf-8")

    server = ThreadedHubServer(("127.0.0.1", port), HubHandler)
    logger.info("deadpush hub listening on http://127.0.0.1:%s", port)
    try:
        server.serve_forever()
    finally:
        state.hub_pidfile().unlink(missing_ok=True)


def start_hub(port: int = DEFAULT_HUB_PORT, *, daemon: bool = False) -> int | None:
    """Start hub; returns PID when daemon=True, else blocks until stopped."""
    if hub_is_running():
        pidfile = state.hub_pidfile()
        try:
            return int(pidfile.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return None

    if not daemon:
        run_hub(port, foreground=True)
        return os.getpid()

    pid = os.fork()
    if pid > 0:
        for _ in range(30):
            if hub_is_running():
                return pid
            time.sleep(0.1)
        return pid
    if pid < 0:
        raise RuntimeError("fork failed")

    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        os._exit(0)
    if pid2 < 0:
        os._exit(1)

    with open(os.devnull, "w") as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

    run_hub(port, foreground=True)
    os._exit(0)
