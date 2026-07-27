from __future__ import annotations

import threading
import time
from pathlib import Path

from deadpush.config import Config
from deadpush.event_pipeline import EventPipeline
from deadpush.guard import GuardianHandler


def test_pipeline_coalesces_pending_burst():
    processed: list[str] = []
    gate = threading.Event()
    started = threading.Event()

    def process(path: Path, event_type: str):
        started.set()
        gate.wait(timeout=2)
        processed.append(f"{path.name}:{event_type}")

    pipe = EventPipeline(process_fn=process, cooldown_fn=lambda: 0.0, max_pending=100, max_workers=1)
    path = Path("/tmp/coalesce.txt")
    assert pipe.enqueue(path, "created", rel="coalesce.txt")
    assert started.wait(timeout=2)
    # Still in-flight: further events coalesce into dirty, then one requeue.
    assert pipe.enqueue(path, "modified", rel="coalesce.txt")
    assert pipe.enqueue(path, "modified", rel="coalesce.txt")
    gate.set()
    pipe.shutdown(wait=True)

    assert processed == ["coalesce.txt:created", "coalesce.txt:modified"]
    assert pipe.stats.coalesced >= 2
    assert pipe.stats.enqueued == 1  # external accepts only; requeues counted separately
    assert pipe.stats.requeued == 1
    assert pipe.stats.dropped == 0


def test_pipeline_drops_when_full():
    block = threading.Event()
    entered = threading.Event()

    def process(path: Path, event_type: str):
        entered.set()
        block.wait(timeout=5)

    pipe = EventPipeline(process_fn=process, cooldown_fn=lambda: 0.0, max_pending=2, max_workers=1)
    assert pipe.enqueue(Path("/tmp/a"), "created", rel="a")
    assert entered.wait(timeout=2)
    # One path in-flight; fill pending to capacity, then drop.
    assert pipe.enqueue(Path("/tmp/b"), "created", rel="b")
    assert pipe.enqueue(Path("/tmp/c"), "created", rel="c")
    assert pipe.enqueue(Path("/tmp/d"), "created", rel="d") is False
    assert pipe.stats.dropped == 1
    block.set()
    pipe.shutdown(wait=True)


def test_pipeline_cooldown_suppresses_repeat():
    calls: list[str] = []

    def process(path: Path, event_type: str):
        calls.append(path.name)

    pipe = EventPipeline(process_fn=process, cooldown_fn=lambda: 10.0, max_pending=10, max_workers=2)
    p = Path("/tmp/cool.txt")
    assert pipe.enqueue(p, "modified", rel="cool.txt")
    time.sleep(0.05)
    assert pipe.enqueue(p, "modified", rel="cool.txt")
    pipe.shutdown(wait=True)
    assert calls == ["cool.txt"]
    assert pipe.stats.coalesced >= 1


def test_prune_last_done_respects_long_cooldown():
    pipe = EventPipeline(process_fn=lambda p, e: None, cooldown_fn=lambda: 30.0, max_pending=10)
    now = time.time()
    # Simulate churn past the prune trigger with entries still inside cooldown.
    pipe._last_done = {f"p{i}": now - 6.0 for i in range(5001)}
    with pipe._lock:
        pipe._prune_last_done()
    assert len(pipe._last_done) == 5001  # 6s-old entries kept when cooldown is 30s
    pipe.shutdown(wait=False)


def test_wait_idle_logs_on_timeout(caplog):
    import logging

    block = threading.Event()
    entered = threading.Event()

    def process(path: Path, event_type: str):
        entered.set()
        block.wait(timeout=5)

    pipe = EventPipeline(
        process_fn=process,
        cooldown_fn=lambda: 0.0,
        max_pending=10,
        max_workers=1,
        idle_timeout=0.05,
    )
    assert pipe.enqueue(Path("/tmp/slow"), "created", rel="slow")
    assert entered.wait(timeout=2)
    with caplog.at_level(logging.WARNING, logger="deadpush.pipeline"):
        assert pipe._wait_idle() is False
    assert any("idle wait timed out" in r.message for r in caplog.records)
    block.set()
    pipe.shutdown(wait=True)


def test_enqueue_coalesces_event_type(temp_repo: Path, monkeypatch):
    handler = GuardianHandler(Config(repo_root=temp_repo), intervention=False, daemon=False)
    target = temp_repo / "burst2.txt"
    target.write_text("x\n", encoding="utf-8")

    calls: list[str] = []
    lock = threading.Lock()
    gate = threading.Event()
    started = threading.Event()

    def fake_worker(path: Path, event_type: str):
        started.set()
        gate.wait(timeout=2)
        with lock:
            calls.append(event_type)

    monkeypatch.setattr(handler, "_worker_run", fake_worker)
    monkeypatch.setattr(handler, "_get_cooldown", lambda: 0.0)

    handler._enqueue(target, "created")
    assert started.wait(timeout=2)
    handler._enqueue(target, "modified")
    handler._enqueue(target, "modified")
    gate.set()
    handler._shutdown_workers()

    assert calls == ["created", "modified"]
    status = handler.pipeline_status()
    assert status["coalesced"] >= 1
    assert status["requeued"] == 1


def test_enqueue_backpressure_drops(temp_repo: Path, monkeypatch):
    handler = GuardianHandler(Config(repo_root=temp_repo), intervention=False, daemon=False)
    handler._pipeline.shutdown(wait=False)
    handler._pipeline = EventPipeline(
        process_fn=lambda path, event_type: handler._worker_run(path, event_type),
        cooldown_fn=lambda: 0.0,
        max_pending=2,
        max_workers=1,
        logger=handler.logger,
    )

    block = threading.Event()
    entered = threading.Event()

    def fake_worker(path: Path, event_type: str):
        entered.set()
        block.wait(timeout=5)

    monkeypatch.setattr(handler, "_worker_run", fake_worker)

    files = []
    for i in range(4):
        p = temp_repo / f"bp_{i}.txt"
        p.write_text("ok\n", encoding="utf-8")
        files.append(p)

    handler._enqueue(files[0], "created")
    assert entered.wait(timeout=2)
    for p in files[1:]:
        handler._enqueue(p, "created")

    status = handler.pipeline_status()
    assert status["dropped"] >= 1
    block.set()
    handler._shutdown_workers()
