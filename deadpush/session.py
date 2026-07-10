"""
Vibe Session Tracking — tags guardian activity and file changes into named sessions.

Vibe coding sessions are periods of continuous AI-assisted development. This module
lets users explicitly start/stop sessions, and the guardian tags all interventions
with the active session. At session end, a rollup summary is generated showing
what changed, what went wrong, and what the safety impact was.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import threading
from typing import Any


SESSION_DIR = Path.home() / ".deadpush" / "sessions"
ACTIVE_SESSION_FILE = Path.home() / ".deadpush" / "active_session.json"


@dataclass
class VibeSession:
    """Represents a single vibe coding session."""
    id: str
    label: str
    start_time: str
    end_time: str | None = None
    files_changed: list[str] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    safety_score_start: int = 100
    safety_score_end: int | None = None


class SessionManager:
    """Manages vibe coding sessions — start, end, status, history."""

    def __init__(self):
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------
    def start_session(self, label: str = "") -> VibeSession:
        """Start a new vibe session. Returns the session object."""
        with self._lock:
            now = datetime.now()
            session_id = now.strftime("%Y%m%d_%H%M%S")

            session = VibeSession(
                id=session_id,
                label=label or f"Vibe session {session_id}",
                start_time=now.isoformat(),
            )

            ACTIVE_SESSION_FILE.write_text(
                json.dumps(self._session_to_dict(session), indent=2, default=str),
                encoding="utf-8",
            )
            return session

    def end_session(self, safety_score: int | None = None) -> VibeSession | None:
        """End the active session. Returns the completed session or None."""
        with self._lock:
            active = self._get_active_session_unlocked()
            if active is None:
                return None

            now = datetime.now()
            active.end_time = now.isoformat()
            active.safety_score_end = safety_score or active.safety_score_start

            # Save to history
            history_path = SESSION_DIR / f"{active.id}.json"
            history_path.write_text(
                json.dumps(self._session_to_dict(active), indent=2, default=str),
                encoding="utf-8",
            )

            # Clear active
            if ACTIVE_SESSION_FILE.exists():
                ACTIVE_SESSION_FILE.unlink(missing_ok=True)

            # Clean up old sessions (keep last 50)
            self._cleanup_old_sessions_unlocked()

            return active

    def get_active_session(self) -> VibeSession | None:
        """Get the currently active session, if any."""
        with self._lock:
            return self._get_active_session_unlocked()

    def _get_active_session_unlocked(self) -> VibeSession | None:
        if not ACTIVE_SESSION_FILE.exists():
            return None
        try:
            data = json.loads(ACTIVE_SESSION_FILE.read_text(encoding="utf-8"))
            return self._dict_to_session(data)
        except Exception:
            return None

    def get_session_history(self, limit: int = 20) -> list[VibeSession]:
        """Get recent completed sessions."""
        with self._lock:
            if not SESSION_DIR.exists():
                return []

            sessions: list[VibeSession] = []
            for f in sorted(SESSION_DIR.iterdir(), reverse=True):
                if f.suffix == ".json":
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        sessions.append(self._dict_to_session(data))
                    except Exception:
                        pass
                    if len(sessions) >= limit:
                        break

            return sessions

    # ------------------------------------------------------------------
    # Session tracking helpers (used by guardian)
    # ------------------------------------------------------------------
    def record_file_change(self, filepath: str):
        """Record a file change in the active session."""
        with self._lock:
            active = self._get_active_session_unlocked()
            if active is None:
                return
            if filepath not in active.files_changed:
                active.files_changed.append(filepath)
            self._save_active_unlocked(active)

    def record_incident(self, incident: dict[str, Any]):
        """Record a guardian incident in the active session."""
        with self._lock:
            active = self._get_active_session_unlocked()
            if active is None:
                return
            active.incidents.append(incident)
            self._save_active_unlocked(active)

    def update_safety_score(self, score: int):
        """Update the running safety score for the session."""
        with self._lock:
            active = self._get_active_session_unlocked()
            if active is None:
                return
            active.safety_score_end = score
            self._save_active_unlocked(active)

    def get_session_summary(self, session: VibeSession) -> str:
        """Generate a human-readable summary of a session."""
        duration = ""
        if session.end_time:
            start = datetime.fromisoformat(session.start_time)
            end = datetime.fromisoformat(session.end_time)
            delta = end - start
            mins = int(delta.total_seconds() / 60)
            duration = f"{mins}min"
        else:
            start = datetime.fromisoformat(session.start_time)
            elapsed = int((datetime.now() - start).total_seconds() / 60)
            duration = f"{elapsed}min (active)"

        score_delta = ""
        if session.safety_score_end is not None:
            diff = session.safety_score_end - session.safety_score_start
            if diff < 0:
                score_delta = f" ↓ {abs(diff)} pts"
            else:
                score_delta = f" ↑ {diff} pts"

        return (
            f"Session: {session.label}\n"
            f"  Duration: {duration}\n"
            f"  Files touched: {len(session.files_changed)}\n"
            f"  Incidents: {len(session.incidents)}\n"
            f"  Safety: {session.safety_score_start} → {session.safety_score_end or '?'}{score_delta}"
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _session_to_dict(self, session: VibeSession) -> dict[str, Any]:
        return {
            "id": session.id,
            "label": session.label,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "files_changed": session.files_changed,
            "incidents": session.incidents,
            "safety_score_start": session.safety_score_start,
            "safety_score_end": session.safety_score_end,
        }

    def _dict_to_session(self, data: dict[str, Any]) -> VibeSession:
        return VibeSession(
            id=data.get("id", ""),
            label=data.get("label", ""),
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time"),
            files_changed=data.get("files_changed", []),
            incidents=data.get("incidents", []),
            safety_score_start=data.get("safety_score_start", 100),
            safety_score_end=data.get("safety_score_end"),
        )

    def _save_active(self, session: VibeSession):
        with self._lock:
            self._save_active_unlocked(session)

    def _save_active_unlocked(self, session: VibeSession):
        ACTIVE_SESSION_FILE.write_text(
            json.dumps(self._session_to_dict(session), indent=2, default=str),
            encoding="utf-8",
        )

    def _cleanup_old_sessions(self, keep: int = 50):
        with self._lock:
            self._cleanup_old_sessions_unlocked(keep=keep)

    def _cleanup_old_sessions_unlocked(self, keep: int = 50):
        if not SESSION_DIR.exists():
            return
        all_sessions = sorted(SESSION_DIR.iterdir(), reverse=True)
        for f in all_sessions[keep:]:
            try:
                f.unlink()
            except Exception:
                pass
