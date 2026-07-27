"""Bounded filesystem-event pipeline for the always-on guardian.

Watchdog callbacks stay cheap: they only enqueue. Worker threads drain the
queue, coalesce bursts per path, and apply a post-process cooldown so parallel
agents cannot unbounded-grow work.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ProcessFn = Callable[[Path, str], None]
CooldownFn = Callable[[], float]


@dataclass
class _Pending:
    path: Path
    event_type: str


@dataclass
class PipelineStats:
    enqueued: int = 0
    coalesced: int = 0
    dropped: int = 0
    processed: int = 0
    requeued: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "enqueued": self.enqueued,
            "coalesced": self.coalesced,
            "dropped": self.dropped,
            "processed": self.processed,
            "requeued": self.requeued,
        }


class EventPipeline:
    """Per-path coalescing work queue backed by a thread pool.

    Semantics
    ---------
    * First event for a path schedules a worker.
    * Further events for the same path while pending/in-flight update the
      latest ``event_type`` (coalesce) instead of scheduling another worker.
    * After a path finishes, a cooldown window rejects immediate re-enqueue
      (burst suppression). Dirty updates that arrived during in-flight work
      are re-queued once after completion (still subject to capacity).
    * When ``max_pending`` unique paths are already pending, new paths are
      dropped and counted — never unbounded growth.
    """

    def __init__(
        self,
        *,
        process_fn: ProcessFn,
        cooldown_fn: CooldownFn | None = None,
        max_pending: int = 2000,
        max_workers: int | None = None,
        logger: logging.Logger | None = None,
    ):
        self._process_fn = process_fn
        self._cooldown_fn = cooldown_fn or (lambda: 0.0)
        self._max_pending = max(1, max_pending)
        workers = max_workers if max_workers is not None else min(32, (os.cpu_count() or 4) * 4)
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix="deadpush-pipeline",
        )
        self._logger = logger or logging.getLogger("deadpush.pipeline")
        self._lock = threading.RLock()
        self._pending: dict[str, _Pending] = {}
        self._inflight: set[str] = set()
        self._dirty: dict[str, _Pending] = {}
        self._last_done: dict[str, float] = {}
        self._futures: set[Future] = set()
        self._stats = PipelineStats()
        self._accepting = True
        self._closed = False

    @property
    def stats(self) -> PipelineStats:
        return self._stats

    def describe(self) -> dict:
        with self._lock:
            return {
                "pending": len(self._pending),
                "inflight": len(self._inflight),
                "dirty": len(self._dirty),
                "max_pending": self._max_pending,
                "accepting": self._accepting,
                "closed": self._closed,
                **self._stats.snapshot(),
            }

    def enqueue(self, path: Path, event_type: str, *, rel: str | None = None) -> bool:
        """Accept a filesystem event. Returns False when dropped under backpressure."""
        key = rel if rel is not None else path.as_posix()
        with self._lock:
            if not self._accepting or self._closed:
                self._stats.dropped += 1
                return False

            if key in self._pending:
                self._pending[key] = _Pending(path, event_type)
                self._stats.coalesced += 1
                return True

            if key in self._inflight:
                self._dirty[key] = _Pending(path, event_type)
                self._stats.coalesced += 1
                return True

            now = time.time()
            last = self._last_done.get(key)
            cooldown = 0.0
            try:
                cooldown = float(self._cooldown_fn())
            except Exception:
                cooldown = 0.0
            if last is not None and cooldown > 0 and (now - last) < cooldown:
                self._stats.coalesced += 1
                return True

            if len(self._pending) >= self._max_pending:
                self._stats.dropped += 1
                if self._stats.dropped == 1 or self._stats.dropped % 100 == 0:
                    self._logger.warning(
                        "Event pipeline backpressure: dropped=%s pending=%s max=%s",
                        self._stats.dropped,
                        len(self._pending),
                        self._max_pending,
                    )
                return False

            self._pending[key] = _Pending(path, event_type)
            self._stats.enqueued += 1
            self._schedule(key)
            return True

    def _schedule(self, key: str) -> None:
        fut = self._executor.submit(self._run, key)
        self._futures.add(fut)
        fut.add_done_callback(self._futures.discard)

    def _run(self, key: str) -> None:
        with self._lock:
            item = self._pending.pop(key, None)
            if item is None:
                return
            self._inflight.add(key)
        try:
            self._process_fn(item.path, item.event_type)
        except Exception as e:
            self._logger.debug("Pipeline worker error on %s: %s", key, e)
        finally:
            with self._lock:
                self._inflight.discard(key)
                self._last_done[key] = time.time()
                self._stats.processed += 1
                self._prune_last_done()
                dirty = self._dirty.pop(key, None)
                if dirty is not None and not self._closed:
                    if len(self._pending) < self._max_pending:
                        self._pending[key] = dirty
                        self._stats.requeued += 1
                        self._stats.enqueued += 1
                        self._schedule(key)
                    else:
                        self._stats.dropped += 1

    def _prune_last_done(self) -> None:
        if len(self._last_done) <= 5000:
            return
        now = time.time()
        self._last_done = {k: v for k, v in self._last_done.items() if now - v < 5.0}

    def _wait_idle(self, timeout: float = 60.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if not self._pending and not self._inflight and not self._dirty:
                    return
            time.sleep(0.01)

    def shutdown(self, *, wait: bool = True) -> None:
        # Stop accepting external events, but allow in-flight dirty coalesces
        # to re-queue once so a burst is not silently discarded on stop.
        with self._lock:
            self._accepting = False
        if wait:
            self._wait_idle()
        with self._lock:
            self._closed = True
            self._dirty.clear()
            self._pending.clear()
        try:
            self._executor.shutdown(wait=wait, cancel_futures=not wait)
        except TypeError:
            # Python < 3.9 has no cancel_futures
            self._executor.shutdown(wait=wait)
        except Exception as e:
            self._logger.debug("Pipeline shutdown skipped: %s", e)
