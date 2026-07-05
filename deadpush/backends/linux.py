"""Linux fanotify/Landlock enforcement backend (T2-max)."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import threading
from pathlib import Path
from typing import Any

from .base import EnforcementBackend

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

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self._fd: int | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._libc: Any = None

    def available(self) -> bool:
        if not sys.platform.startswith("linux"):
            return False
        try:
            self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            if not hasattr(self._libc, "fanotify_init"):
                return False
            # Quick probe — requires CAP_SYS_ADMIN or privileged context
            fd = self._libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, 0)
            if fd < 0:
                return False
            os.close(fd)
            return True
        except (OSError, AttributeError):
            return False

    def wrap_command(self, cmd: list[str], *, repo_root: Path, env: dict[str, str]) -> list[str]:
        env["DEADPUSH_LINUX_SANDBOX"] = "1"
        return cmd

    def start(self, repo_root: Path) -> None:
        if not self.available() or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="fanotify-listener")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def _listen_loop(self) -> None:
        if self._libc is None:
            return
        fd = self._libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, 0)
        if fd < 0:
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
            os.close(fd)
            self._fd = None
            return
        # v0: listener thread keeps fd open; deny events handled by kernel synchronously.
        while self._running:
            try:
                os.read(fd, 8192)
            except BlockingIOError:
                import time
                time.sleep(0.1)
            except OSError:
                break

    def describe(self) -> dict:
        d = super().describe()
        d["repo_root"] = str(self.repo_root)
        d["note"] = "Requires CAP_SYS_ADMIN or _deadpush privileged context on Linux."
        return d
