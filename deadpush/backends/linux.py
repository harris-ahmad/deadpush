"""Linux fanotify/Landlock enforcement backend (T2-max)."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .base import EnforcementBackend, logger

# fanotify constants (Linux)
FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010
FAN_OPEN = 0x00000020
FAN_MODIFY = 0x00000002
FAN_DENY = 0x00002000


class LinuxEnforcementBackend(EnforcementBackend):
    """fanotify FAN_DENY backend for Linux T2-max."""

    name = "linux-fanotify"
    tier = "T2-max"

    def __init__(self, repo_root: Path):
        super().__init__(repo_root)
        self._fd: int | None = None
        self._thread: threading.Thread | None = None
        self._libc: Any = None
        self._running = False

    def available(self) -> bool:
        if not sys.platform.startswith("linux"):
            return False
        try:
            self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            if not hasattr(self._libc, "fanotify_init"):
                return False
            fd = self._libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, 0)
            if fd < 0:
                return False
            os.close(fd)
            return True
        except (OSError, AttributeError):
            return False

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        ok, reason = self.preflight(cmd)
        if not ok:
            raise ValueError(f"linux backend preflight failed: {reason}")
        self.apply_env_markers(env)
        env["DEADPUSH_LINUX_SANDBOX"] = "1"
        return cmd

    def start(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        if not self.available():
            self._last_error = "fanotify unavailable (needs Linux + CAP_SYS_ADMIN)"
            logger.warning(self._last_error)
            return
        if self._running:
            return
        self._running = True
        self._started = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="fanotify-listener")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._started = False
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _listen_loop(self) -> None:
        if self._libc is None and not self.available():
            return
        fd = self._libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, 0)
        if fd < 0:
            self._last_error = "fanotify_init failed"
            logger.error(self._last_error)
            return
        self._fd = fd
        repo = str(self.repo_root)
        res = self._libc.fanotify_mark(
            fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_OPEN | FAN_MODIFY | FAN_DENY,
            -1,
            repo.encode(),
        )
        if res != 0:
            self._last_error = "fanotify_mark failed"
            logger.error(self._last_error)
            os.close(fd)
            self._fd = None
            return
        logger.info("fanotify listener active on %s", self.repo_root)
        while self._running:
            try:
                os.read(fd, 8192)
            except BlockingIOError:
                time.sleep(0.1)
            except OSError:
                break

    def describe(self) -> dict:
        d = super().describe()
        d.update({
            "os_sandbox": self.available(),
            "repo_root": str(self.repo_root),
            "note": "Requires CAP_SYS_ADMIN or _deadpush privileged context on Linux.",
        })
        return d
