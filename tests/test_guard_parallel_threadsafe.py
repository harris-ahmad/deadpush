from __future__ import annotations

import json
import threading
from pathlib import Path

from deadpush.config import Config
from deadpush.guard import GuardianHandler, QuarantineManager, SessionSafetyScore
from deadpush import session as session_mod


def test_enqueue_dedupes_within_cooldown(temp_repo: Path, monkeypatch):
    handler = GuardianHandler(Config(repo_root=temp_repo), intervention=False, daemon=False)
    target = temp_repo / "burst.txt"
    target.write_text("x\n", encoding="utf-8")

    calls: list[tuple[str, str]] = []
    calls_lock = threading.Lock()

    def fake_worker(path: Path, event_type: str):
        with calls_lock:
            calls.append((path.as_posix(), event_type))

    monkeypatch.setattr(handler, "_worker_run", fake_worker)
    monkeypatch.setattr(handler, "_get_cooldown", lambda: 10.0)

    handler._enqueue(target, "modified")
    handler._enqueue(target, "modified")
    handler._shutdown_workers()

    assert len(calls) == 1
    assert calls[0][0] == target.as_posix()


def test_enqueue_processes_many_paths(temp_repo: Path, monkeypatch):
    handler = GuardianHandler(Config(repo_root=temp_repo), intervention=False, daemon=False)
    monkeypatch.setattr(handler, "_get_cooldown", lambda: 0.0)

    processed: list[str] = []
    processed_lock = threading.Lock()

    def fake_worker(path: Path, event_type: str):
        with processed_lock:
            processed.append(path.as_posix())

    monkeypatch.setattr(handler, "_worker_run", fake_worker)

    files = []
    for i in range(200):
        p = temp_repo / f"f_{i}.txt"
        p.write_text("ok\n", encoding="utf-8")
        files.append(p)

    for p in files:
        handler._enqueue(p, "created")

    handler._shutdown_workers()
    assert len(processed) == 200


def test_thread_safe_shared_state(tmp_path: Path, monkeypatch):
    session_dir = tmp_path / "sessions"
    active_file = tmp_path / "active_session.json"
    monkeypatch.setattr(session_mod, "SESSION_DIR", session_dir)
    monkeypatch.setattr(session_mod, "ACTIVE_SESSION_FILE", active_file)

    safety = SessionSafetyScore(tmp_path)
    session_mgr = session_mod.SessionManager()
    session_mgr.start_session("threaded")
    quarantine = QuarantineManager(tmp_path)

    errors: list[Exception] = []
    errors_lock = threading.Lock()

    def record_error(exc: Exception):
        with errors_lock:
            errors.append(exc)

    def writer(tid: int):
        for i in range(60):
            try:
                rel = f"src/t{tid}_{i}.py"
                safety.report_incident(1, "test", rel)
                session_mgr.record_file_change(rel)
                session_mgr.record_incident({"type": "test", "file": rel})
                session_mgr.update_safety_score(safety.get_score())

                p = tmp_path / f"q_{tid}_{i}.txt"
                p.write_text("danger\n", encoding="utf-8")
                q = quarantine.quarantine(p, "test")
                quarantine.restore(q.name)
            except Exception as exc:  # pragma: no cover - we assert this stays empty
                record_error(exc)

    def reader():
        for _ in range(400):
            try:
                safety.get_summary()
                safety.get_activity_level()
                safety.get_session_summary()
                safety.get_recent_incidents(10)
                quarantine.list_quarantined()
                session_mgr.get_active_session()
            except Exception as exc:  # pragma: no cover - we assert this stays empty
                record_error(exc)

    writers = [threading.Thread(target=writer, args=(idx,)) for idx in range(8)]
    readers = [threading.Thread(target=reader) for _ in range(2)]
    for t in writers + readers:
        t.start()
    for t in writers + readers:
        t.join()

    assert errors == []
    assert 0 <= safety.get_score() <= 100

    active = session_mgr.get_active_session()
    assert active is not None
    assert active_file.exists()
    json.loads(active_file.read_text(encoding="utf-8"))
