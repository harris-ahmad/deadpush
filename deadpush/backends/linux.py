"""Linux fanotify enforcement — content-aware FAN_DENY (G-10)."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import threading
import time
from ctypes import Structure, c_int32, c_uint32, c_uint64, c_uint8, c_uint16
from pathlib import Path
from typing import Any, Callable

from .base import EnforcementBackend, logger

# fanotify constants (Linux uapi)
FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_EVENT_ON_CHILD = 0x00000080
FAN_MARK_ADD = 0x00000001
FAN_MARK_ONLYDIR = 0x00000008
FAN_OPEN = 0x00000020
FAN_MODIFY = 0x00000002
FAN_DENY = 0x00002000
FAN_ALLOW = 0x00000001
FAN_DENY_RESP = 0x00000002
FAN_METADATA_VERSION = 3
FAN_EVENT_METADATA_LEN = 24
AT_FDCWD = -100

# Text extensions we content-scan; others are path-only allow.
_TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml",
    ".md", ".txt", ".sh", ".env", ".cfg", ".ini", ".xml", ".html", ".css",
    ".sql", ".go", ".rs", ".java", ".rb", ".php", "",  # empty = no suffix
}


class FanotifyEventMetadata(Structure):
    _fields_ = [
        ("event_len", c_uint32),
        ("vers", c_uint8),
        ("reserved", c_uint8),
        ("metadata_len", c_uint16),
        ("mask", c_uint64),
        ("fd", c_int32),
        ("pid", c_int32),
    ]


class FanotifyResponse(Structure):
    _fields_ = [
        ("fd", c_int32),
        ("response", c_uint32),
    ]


def evaluate_repo_write(
    repo_root: Path,
    rel_path: str,
    content: str,
    *,
    old_source: str | None = None,
) -> tuple[bool, str]:
    """Return (allowed, reason) using the shared enforcement kernel."""
    from ..config import load_config
    from ..intercept import enforce_content
    from ..rules import RuntimeConfig

    config = load_config(explicit_root=repo_root)
    runtime = RuntimeConfig(repo_root)
    result = enforce_content(rel_path, content, config, runtime, old_source=old_source)
    if result.allowed:
        return True, ""
    reason = result.violations[0].description if result.violations else "policy violation"
    return False, reason


def _rel_path_for_repo(repo_root: Path, abs_path: str) -> str | None:
    try:
        return Path(abs_path).resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return None


def _read_event_fd(event_fd: int, max_bytes: int = 512_000) -> str:
    try:
        data = os.read(event_fd, max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _path_from_proc(pid: int, event_fd: int) -> str | None:
    """Best-effort path for a fanotify event fd via /proc."""
    link = f"/proc/{pid}/fd/{event_fd}"
    try:
        return os.readlink(link)
    except OSError:
        return None


def decide_fanotify_write(
    repo_root: Path,
    *,
    abs_path: str | None = None,
    content: str = "",
    pid: int = 0,
    event_fd: int = -1,
) -> tuple[bool, str]:
    """Decide allow/deny for a fanotify write event (testable without fanotify fd)."""
    repo = repo_root.resolve()
    path = abs_path
    if not path and pid and event_fd >= 0:
        path = _path_from_proc(pid, event_fd)
    if not path:
        return True, ""

    resolved = Path(path).resolve()
    try:
        resolved.relative_to(repo)
    except ValueError:
        return True, ""  # outside repo — kernel should not have marked it

    rel = _rel_path_for_repo(repo, str(resolved))
    if rel is None:
        return True, ""

    from ..bootstrap import is_bootstrap_path

    if is_bootstrap_path(rel, repo):
        return True, ""

    text = content
    if not text and event_fd >= 0:
        suffix = Path(rel).suffix.lower()
        if suffix in _TEXT_SUFFIXES:
            text = _read_event_fd(event_fd)

    allowed, reason = evaluate_repo_write(repo, rel, text)
    return allowed, reason


class LinuxEnforcementBackend(EnforcementBackend):
    """fanotify FAN_DENY backend with enforce_content() decisions (T2-max)."""

    name = "linux-fanotify"
    tier = "T2-max"

    def __init__(
        self,
        repo_root: Path,
        *,
        on_deny: Callable[[str, str, str], None] | None = None,
    ):
        super().__init__(repo_root)
        self._fd: int | None = None
        self._thread: threading.Thread | None = None
        self._libc: Any = None
        self._running = False
        self._on_deny = on_deny
        self._deny_count = 0
        self._allow_count = 0

    @property
    def is_active(self) -> bool:
        return self._running and self._fd is not None

    def available(self) -> bool:
        if not sys.platform.startswith("linux"):
            return False
        try:
            self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            if not hasattr(self._libc, "fanotify_init"):
                return False
            fd = self._libc.fanotify_init(
                FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_EVENT_ON_CHILD, 0,
            )
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
            self._last_error = "fanotify unavailable (needs Linux 5.13+ and CAP_SYS_ADMIN)"
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

    def _write_response(self, notify_fd: int, event_fd: int, allow: bool) -> None:
        resp = FanotifyResponse()
        resp.fd = event_fd
        resp.response = FAN_ALLOW if allow else FAN_DENY_RESP
        try:
            os.write(notify_fd, bytes(resp))
        except OSError as e:
            logger.debug("fanotify response write failed: %s", e)

    def _handle_metadata(self, notify_fd: int, meta: FanotifyEventMetadata) -> None:
        event_fd = meta.fd
        if event_fd < 0:
            return
        try:
            allowed, reason = decide_fanotify_write(
                self.repo_root,
                pid=meta.pid,
                event_fd=event_fd,
            )
            if not allowed:
                self._deny_count += 1
                logger.warning("fanotify DENY pid=%s: %s", meta.pid, reason)
                if self._on_deny:
                    try:
                        path = _path_from_proc(meta.pid, event_fd) or "unknown"
                        rel = _rel_path_for_repo(self.repo_root, path) or path
                        self._on_deny(rel, reason, "fanotify")
                    except Exception:
                        pass
            else:
                self._allow_count += 1
            self._write_response(notify_fd, event_fd, allowed)
        finally:
            try:
                os.close(event_fd)
            except OSError:
                pass

    def _listen_loop(self) -> None:
        if self._libc is None and not self.available():
            return
        fd = self._libc.fanotify_init(
            FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_EVENT_ON_CHILD,
            0,
        )
        if fd < 0:
            self._last_error = "fanotify_init failed"
            logger.error(self._last_error)
            return
        self._fd = fd
        repo = str(self.repo_root).encode()
        res = self._libc.fanotify_mark(
            fd,
            FAN_MARK_ADD | FAN_MARK_ONLYDIR,
            FAN_OPEN | FAN_MODIFY | FAN_DENY,
            AT_FDCWD,
            repo,
        )
        if res != 0:
            err = ctypes.get_errno()
            self._last_error = f"fanotify_mark failed: errno {err}"
            logger.error(self._last_error)
            os.close(fd)
            self._fd = None
            return
        logger.info("fanotify content-deny listener active on %s", self.repo_root)
        while self._running:
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                time.sleep(0.05)
                continue
            except OSError:
                break
            if not data:
                continue
            offset = 0
            while offset + FAN_EVENT_METADATA_LEN <= len(data):
                meta = FanotifyEventMetadata.from_buffer_copy(data[offset:offset + FAN_EVENT_METADATA_LEN])
                if meta.event_len < FAN_EVENT_METADATA_LEN:
                    break
                self._handle_metadata(fd, meta)
                offset += meta.event_len

    def describe(self) -> dict:
        d = super().describe()
        d.update({
            "os_sandbox": self.available(),
            "repo_root": str(self.repo_root),
            "deny_count": self._deny_count,
            "allow_count": self._allow_count,
            "note": "Content-aware FAN_DENY via enforce_content(); requires CAP_SYS_ADMIN.",
        })
        return d
