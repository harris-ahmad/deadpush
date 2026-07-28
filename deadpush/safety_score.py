"""Session safety score tracking for the always-on guardian."""

from __future__ import annotations

import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .state import scoped_safety_score_file

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
        self._lock = threading.Lock()

    def _score_path(self) -> Path:
        """Path to the per-repo safety score JSON file."""
        return scoped_safety_score_file(self.repo_root, self.hardened)

    def _save_score_locked(self, *, clean_shutdown: bool) -> None:
        path = self._score_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            import json
            data = {
                "score": self.score,
                "event_count": self.events_count,
                "guardian_pid": os.getpid(),
                "last_updated": datetime.now().isoformat(),
                "clean_shutdown": clean_shutdown,
            }
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception:
            pass

    def mark_clean_shutdown(self):
        """Mark clean shutdown so restart doesn't apply penalty.

        Saves score with clean_shutdown=True. On next load, the penalty for
        PID mismatch is skipped.
        """
        with self._lock:
            self._save_score_locked(clean_shutdown=True)

    def save_score(self):
        """Persist current score to JSON file for MCP server to read."""
        with self._lock:
            self._save_score_locked(clean_shutdown=False)

    def load_score(self):
        """Load score from JSON file on startup."""
        with self._lock:
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
        with self._lock:
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
            self.incidents = [
                inc for inc in self.incidents
                if (now - inc["time"]).total_seconds() < self.recent_window
            ]

            # Bonus penalty for high recent activity (multi-agent bursts from parallel Claude/Cursor etc)
            recent_count = len(self.incidents)
            if recent_count > 3:
                extra_penalty = min(5 * (recent_count - 3), 20)
                self.score = max(0, self.score - extra_penalty)
            if recent_count >= 6:
                # Very bursty - many agents firing at once
                self.score = max(0, self.score - 5)

            self._save_score_locked(clean_shutdown=False)
            return self.score

    def get_status(self) -> str:
        with self._lock:
            if self.score >= 90:
                return "🟢 Excellent"
            if self.score >= 70:
                return "🟡 Good"
            if self.score >= 50:
                return "🟠 Caution"
            return "🔴 At Risk"

    def recent_incident_count(self) -> int:
        with self._lock:
            now = datetime.now()
            return len(
                [inc for inc in self.incidents if (now - inc["time"]).total_seconds() < self.recent_window]
            )

    def incident_count(self) -> int:
        with self._lock:
            return len(self.incidents)

    def get_score(self) -> int:
        with self._lock:
            return self.score

    def get_recent_incidents(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.incidents[-limit:])

    def get_activity_level(self) -> str:
        """Simple heuristic for 'how busy are the agents right now?'"""
        with self._lock:
            recent = len(
                [
                    inc for inc in self.incidents
                    if (datetime.now() - inc["time"]).total_seconds() < self.recent_window
                ]
            )
            if recent >= 8:
                return "🔥 High (multiple agents in parallel?)"
            if recent >= 4:
                return "⚡ Elevated burst"
            return "Normal"

    def get_session_summary(self) -> str:
        with self._lock:
            dur_min = (datetime.now() - self.session_start).total_seconds() / 60.0
            recent_files = len(set(self.recent_paths))
            return f"Session: {dur_min:.1f}min | Total events: {self.events_count} | Recent files: {recent_files}"

    def get_summary(self) -> str:
        with self._lock:
            recent = len(
                [inc for inc in self.incidents if (datetime.now() - inc["time"]).total_seconds() < self.recent_window]
            )
            if self.score >= 90:
                status = "🟢 Excellent"
            elif self.score >= 70:
                status = "🟡 Good"
            elif self.score >= 50:
                status = "🟠 Caution"
            else:
                status = "🔴 At Risk"
            if recent >= 8:
                activity = "🔥 High (multiple agents in parallel?)"
            elif recent >= 4:
                activity = "⚡ Elevated burst"
            else:
                activity = "Normal"
            return f"Score: {self.score}/100 | Status: {status} | Recent incidents (last 60s): {recent} | Activity: {activity}"
