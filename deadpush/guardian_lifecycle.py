"""
deadpush Guardian Lifecycle

Daemon management, shadow process, stop/kill helpers, and the main
``run_guardian`` entry-point.
"""

from __future__ import annotations

import atexit
import fcntl
import logging
import os
import signal
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from .config import repo_id as _repo_id
from . import state as _state


# ---------------------------------------------------------------------------
# Path helpers (delegate to state; patchable in tests)
# ---------------------------------------------------------------------------

def _state_dir(hardened: bool = False) -> Path:
    return _state.state_dir(hardened)


def _scoped_pidfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_pidfile(repo_root, hardened)


def _scoped_lockfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_lockfile(repo_root, hardened)


def _scoped_portfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_portfile(repo_root, hardened)


def _scoped_plist_label(repo_root: Path) -> str:
    return _state.scoped_plist_label(repo_root)


def _scoped_plist_path(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_plist_path(repo_root, hardened)


def _scoped_systemd_unit_path(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_systemd_unit_path(repo_root, hardened)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(
    log_file: Optional[Path] = None,
    level=logging.INFO,
    daemon: bool = False,
    hardened: bool = False,
    repo_root: Path | None = None,
):
    """Setup logging.

    In daemon mode: ONLY file logging (headless/silent on stdout/stderr).
    Foreground: file + console.
    Uses RotatingFileHandler (10MB × 5 files) to prevent unbounded growth.
    """
    if log_file is None:
        if repo_root is None:
            log_file = _state_dir(hardened) / "guardian.log"
        else:
            log_file = _state.scoped_log_file(repo_root, hardened)
        log_file.parent.mkdir(parents=True, exist_ok=True)

    handlers = [RotatingFileHandler(log_file, maxBytes=10_000_000, backupCount=5, encoding="utf-8")]
    if not daemon:
        handlers.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )
    return logging.getLogger("deadpush.guardian")


# ---------------------------------------------------------------------------
# Daemon Manager
# ---------------------------------------------------------------------------

class DaemonManager:
    """Robust daemon management with file locking."""

    def __init__(self, pidfile: Path, lockfile: Optional[Path] = None):
        self.pidfile = pidfile
        self.lockfile = lockfile or pidfile.with_suffix(".lock")
        self.startfile = pidfile.with_suffix(".start")
        self.holderfile = pidfile.with_suffix(".holder")
        self.lock_fd = None
        self.logger = logging.getLogger("deadpush.guardian")

    def acquire_lock(self) -> bool:
        """Try to acquire exclusive lock."""
        try:
            self.lock_fd = open(self.lockfile, "w")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_fd.seek(0)
            self.lock_fd.write(str(os.getpid()))
            self.lock_fd.flush()
            return True
        except (IOError, OSError):
            if self.lock_fd:
                self.lock_fd.close()
            return False

    def write_pid(self, repo_root: Path | None = None):
        pid = os.getpid()
        with self.pidfile.open("w") as f:
            f.write(str(pid))
        start_time = time.clock_gettime(time.CLOCK_MONOTONIC)
        with self.startfile.open("w") as f:
            f.write(str(start_time))
        if repo_root is not None:
            resolved = repo_root.resolve()
            self.holderfile.write_text(str(resolved), encoding="utf-8")
            try:
                from .config import is_hardened_install
                _state.touch_registry(resolved, hardened=is_hardened_install(resolved), running=True)
            except Exception:
                pass
        self.logger.info(f"Daemon started with PID {pid}")

    def _state_files(self) -> tuple[Path, ...]:
        return (
            self.pidfile,
            self.lockfile,
            self.startfile,
            self.holderfile,
            self.pidfile.with_suffix(".repo"),
            self.pidfile.with_suffix(".shadow"),
        )

    def cleanup(self):
        if self.lock_fd:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                self.lock_fd.close()
            except Exception:
                pass
        for f in self._state_files():
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass

    def force_cleanup(self):
        """Force remove all daemon state files (for stale lock recovery)."""
        for f in self._state_files():
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass
        if self.lock_fd:
            try:
                self.lock_fd.close()
            except Exception:
                pass
        self.lock_fd = None

    def get_holder_pid(self) -> Optional[int]:
        """Get PID of current lock holder, if any."""
        if not self.lockfile.exists():
            return None
        try:
            with self.lockfile.open() as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def is_running(self) -> bool:
        if not self.pidfile.exists():
            return False
        try:
            with self.pidfile.open() as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
        except (OSError, ValueError):
            return False

        if not self.startfile.exists():
            return True
        try:
            with self.startfile.open() as f:
                recorded_start = float(f.read().strip())
        except (OSError, ValueError):
            return True

        try:
            elapsed = None
            for opt in ("etimes=", "etime="):
                r = subprocess.run(
                    ["ps", "-o", opt, "-p", str(pid)],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and r.stdout.strip():
                    out = r.stdout.strip()
                    try:
                        elapsed = int(out)
                    except ValueError:
                        parts = out.split("-")
                        if len(parts) == 2:
                            out = parts[1]
                        tparts = list(map(int, out.split(":")))
                        if len(tparts) == 3:
                            elapsed = tparts[0] * 3600 + tparts[1] * 60 + tparts[2]
                        elif len(tparts) == 2:
                            elapsed = tparts[0] * 60 + tparts[1]
                    break
            if elapsed is not None:
                current_monotonic = time.clock_gettime(time.CLOCK_MONOTONIC)
                actual_start = current_monotonic - elapsed
                if abs(actual_start - recorded_start) > 2:
                    return False
        except Exception:
            pass

        try:
            r = subprocess.run(
                ["ps", "-o", "command=", "-p", str(pid)],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and "deadpush" not in r.stdout:
                return False
        except Exception:
            pass

        return True


# ---------------------------------------------------------------------------
# Shadow Process — Re-spawns guardian if it crashes
# ---------------------------------------------------------------------------

_SHADOW_SCRIPT = r"""import os, sys, time, signal, subprocess
guardian_pid = int(sys.argv[1])
pidfile = sys.argv[2]
respawn_cmd = sys.argv[3:-1]
shadow_pidfile = sys.argv[-1]
# TAG: {tag}

def _handle_exit(signum, frame):
    os._exit(0)

signal.signal(signal.SIGTERM, _handle_exit)
signal.signal(signal.SIGINT, _handle_exit)

with open(shadow_pidfile, "w") as f:
    f.write(str(os.getpid()))

failure_count = 0
base_backoff = 3
max_backoff = 60
max_failures = 10

def _is_guardian_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        r = subprocess.run(
            ["ps", "-o", "command=", "-p", str(pid)],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0 and "deadpush" in r.stdout
    except Exception:
        return True

def _read_pidfile():
    try:
        with open(pidfile) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None

while True:
    if _is_guardian_alive(guardian_pid):
        failure_count = 0
        time.sleep(3)
        continue

    new_pid = _read_pidfile()
    if new_pid and new_pid != guardian_pid and _is_guardian_alive(new_pid):
        guardian_pid = new_pid
        failure_count = 0
        time.sleep(3)
        continue

    failure_count += 1
    if failure_count > max_failures:
        os._exit(1)

    backoff = min(base_backoff * (2 ** (failure_count - 1)), max_backoff)
    time.sleep(backoff)

    if _is_guardian_alive(guardian_pid):
        failure_count = 0
        continue
    new_pid = _read_pidfile()
    if new_pid and new_pid != guardian_pid and _is_guardian_alive(new_pid):
        guardian_pid = new_pid
        failure_count = 0
        continue

    pid = os.fork()
    if pid == 0:
        os.execvp(respawn_cmd[0], respawn_cmd)
        os._exit(1)
    else:
        guardian_pid = pid
"""

_SHADOW_TAG_PREFIX = "deadpush_shadow_watch."


def _shadow_tag(repo_root: Path) -> str:
    return f"{_SHADOW_TAG_PREFIX}{_repo_id(str(repo_root))}"


def stop_shadow_for_repo(repo_root: Path, hardened: bool = False) -> int:
    """Kill shadow process(es) scoped to one repo. Returns count killed."""
    tag = _shadow_tag(repo_root)
    killed = 0
    try:
        r = subprocess.run(
            ["pgrep", "-f", tag],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            my_pid = os.getpid()
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                pid = int(line.strip())
                if pid == my_pid:
                    continue
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed += 1
                except OSError:
                    pass
    except Exception:
        pass
    shadow_pidfile = _scoped_pidfile(repo_root, hardened).with_suffix(".shadow")
    shadow_pidfile.unlink(missing_ok=True)
    return killed


def start_shadow_process(
    guardian_pid: int,
    pidfile: Path,
    respawn_cmd: list[str],
    repo_root: Path,
) -> subprocess.Popen | None:
    """Launch a shadow subprocess that re-spawns the guardian if it dies.

    Only starts if no shadow is already running for this repo (checked via pgrep).
    """
    tag = _shadow_tag(repo_root)
    shadow_pidfile = pidfile.with_suffix(".shadow")
    try:
        r = subprocess.run(
            ["pgrep", "-f", tag],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            pids = [int(p) for p in r.stdout.strip().splitlines() if p.strip()]
            my_pid = os.getpid()
            pids = [pid for pid in pids if pid != my_pid]
            if pids:
                return None
    except Exception:
        pass

    script = _SHADOW_SCRIPT.replace("{tag}", tag)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", script, str(guardian_pid), str(pidfile)] + respawn_cmd + [str(shadow_pidfile)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        return proc
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Stop helpers
# ---------------------------------------------------------------------------

def stop_guardian_for_repo(
    repo_root: Path | str,
    *,
    hardened: bool = False,
    force: bool = False,
) -> bool:
    """Stop the guardian for one repo. Returns True if a process was stopped."""
    from .hooks import _make_mutable

    repo_root = Path(repo_root).resolve()
    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)
    portfile = _scoped_portfile(repo_root, hardened)
    plist_label = _scoped_plist_label(repo_root)
    plist_path = _scoped_plist_path(repo_root, hardened)
    shadow_pidfile = pidfile.with_suffix(".shadow")

    if force:
        dm = DaemonManager(pidfile, lockfile)
        dm.force_cleanup()
        if not hardened and plist_path.exists():
            plist_path.unlink(missing_ok=True)
        for f in (portfile, shadow_pidfile):
            f.unlink(missing_ok=True)
        _state.touch_registry(repo_root, hardened=hardened, running=False)
        return True

    stopped = False

    if not hardened:
        if stop_shadow_for_repo(repo_root, hardened):
            stopped = True
            time.sleep(0.2)

    guardian_pid = None
    if hardened:
        try:
            r = subprocess.run(
                ["sudo", "cat", str(pidfile)],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                guardian_pid = int(r.stdout.strip())
        except Exception:
            pass
    elif pidfile.exists():
        try:
            guardian_pid = int(pidfile.read_text().strip())
        except (ValueError, OSError):
            pass

    if guardian_pid:
        try:
            if hardened:
                r = subprocess.run(
                    ["sudo", "kill", "-0", str(guardian_pid)],
                    capture_output=True, timeout=5,
                )
                if r.returncode != 0:
                    raise OSError("not running")
                subprocess.run(["sudo", "kill", str(guardian_pid)], capture_output=True, timeout=5)
            else:
                os.kill(guardian_pid, 0)
                os.kill(guardian_pid, signal.SIGTERM)
            for _ in range(10):
                try:
                    if hardened:
                        r = subprocess.run(
                            ["sudo", "kill", "-0", str(guardian_pid)],
                            capture_output=True, timeout=5,
                        )
                        if r.returncode != 0:
                            break
                    else:
                        os.kill(guardian_pid, 0)
                    time.sleep(0.2)
                except OSError:
                    break
            else:
                try:
                    if hardened:
                        subprocess.run(["sudo", "kill", "-9", str(guardian_pid)], capture_output=True, timeout=5)
                    else:
                        os.kill(guardian_pid, signal.SIGKILL)
                except OSError:
                    pass
            stopped = True
        except OSError:
            pass

    try:
        if sys.platform == "darwin":
            if hardened:
                subprocess.run(["sudo", "launchctl", "bootout", "system", plist_label], capture_output=True, timeout=10)
            else:
                uid = os.getuid()
                subprocess.run(["launchctl", "bootout", f"gui/{uid}/{plist_label}"], capture_output=True, timeout=10)
    except Exception:
        pass

    try:
        if hardened:
            subprocess.run(["sudo", "rm", "-f", str(plist_path)], capture_output=True, timeout=10)
        elif plist_path.exists():
            plist_path.unlink()
    except OSError:
        pass

    for f in (pidfile, lockfile, portfile, shadow_pidfile):
        try:
            if hardened:
                subprocess.run(["sudo", "rm", "-f", str(f)], capture_output=True, timeout=10)
            elif f.exists():
                f.unlink()
        except OSError:
            pass

    if hardened:
        shared_port = repo_root / ".guardian" / "guardian.control.port"
        try:
            subprocess.run(["sudo", "rm", "-f", str(shared_port)], capture_output=True, timeout=10)
        except OSError:
            pass

    try:
        hooks_dir = repo_root / ".git" / "hooks"
        if hooks_dir.exists():
            for hook in hooks_dir.iterdir():
                if hook.is_file() and not hook.name.endswith(".sample"):
                    _make_mutable(hook)
    except Exception:
        pass

    _state.touch_registry(repo_root, hardened=hardened, running=False)
    return stopped


def stop_guardian_by_id(rid: str, *, hardened: bool = False) -> bool:
    """Stop guardian when only repo id is known (orphan / missing holder)."""
    stopped = False
    my_pid = os.getpid()
    patterns = (
        f"deadpush_shadow_watch.{rid}",
        f"guardian.{rid}.pid",
        f"repos/{rid}/",
    )
    pids: set[int] = set()
    for pattern in patterns:
        try:
            r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                try:
                    pid = int(line.strip())
                    if pid != my_pid:
                        pids.add(pid)
                except ValueError:
                    pass
        except Exception:
            pass

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            stopped = True
        except OSError:
            pass
    time.sleep(0.5)
    for pid in pids:
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
            stopped = True
        except OSError:
            pass

    root = _state.state_dir(hardened)
    for pidfile in (root / "repos" / rid / "guardian.pid", root / f"guardian.{rid}.pid"):
        if pidfile.exists():
            try:
                gpid = int(pidfile.read_text(encoding="utf-8").strip())
                if gpid != my_pid:
                    try:
                        os.kill(gpid, signal.SIGTERM)
                        stopped = True
                    except OSError:
                        pass
                    time.sleep(0.3)
                    try:
                        os.kill(gpid, signal.SIGKILL)
                    except OSError:
                        pass
            except (ValueError, OSError):
                pass
        pidfile.unlink(missing_ok=True)

    repos_dir = root / "repos" / rid
    for name in ("guardian.lock", "guardian.shadow", "control.port"):
        (repos_dir / name).unlink(missing_ok=True)
    (root / f"guardian.{rid}.shadow").unlink(missing_ok=True)
    sock = repos_dir / "gpc.sock"
    if sock.exists():
        sock.unlink(missing_ok=True)
    return stopped


def kill_orphan_guardian_processes() -> int:
    """SIGTERM stray guardian/shadow processes. Returns count killed."""
    patterns = (
        "deadpush_shadow_watch.",
        "-m deadpush.cli guard --daemon",
        "-m deadpush_bootstrap guard --daemon",
        "-m deadpush guard --daemon",
    )
    my_pid = os.getpid()
    killed = 0
    seen: set[int] = set()
    for pattern in patterns:
        try:
            r = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                continue
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                pid = int(line.strip())
                if pid == my_pid or pid in seen:
                    continue
                seen.add(pid)
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed += 1
                except OSError:
                    pass
        except Exception:
            pass
    time.sleep(0.5)
    for pid in list(seen):
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return killed


def count_running_guardians() -> int:
    """Return number of guardian processes still alive."""
    try:
        r = subprocess.run(
            ["pgrep", "-f", "deadpush_shadow_watch.|guard --daemon"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return 0
        return len([ln for ln in r.stdout.strip().splitlines() if ln.strip()])
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Persistence checks (use DaemonManager / path helpers)
# ---------------------------------------------------------------------------

def guardian_is_running(repo_root: Path, hardened: bool = False) -> bool:
    """Return True if the guardian daemon is running for this repo."""
    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)

    if not hardened:
        return DaemonManager(pidfile, lockfile).is_running()

    shared_port = repo_root / ".guardian" / "guardian.control.port"
    if shared_port.exists():
        try:
            import socket
            port = int(shared_port.read_text().strip())
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except Exception:
            pass

    label = _scoped_plist_label(repo_root)
    try:
        r = subprocess.run(
            ["sudo", "launchctl", "print", f"system/{label}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and "state = running" in r.stdout:
            return True
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["sudo", "cat", str(pidfile)],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            pid = int(r.stdout.strip())
            os.kill(pid, 0)
            return True
    except Exception:
        pass
    return False


def guardian_persistence_installed(repo_root: Path, hardened: bool = False) -> bool:
    """True when the guardian is set up to run persistently (launchd/systemd) or the
    repo is marked protected."""
    try:
        if _scoped_plist_path(repo_root, hardened).exists():
            return True
    except Exception:
        pass
    try:
        if _scoped_systemd_unit_path(repo_root, hardened).exists():
            return True
    except Exception:
        pass
    try:
        from .config import install_marker_path
        if install_marker_path(repo_root).exists():
            return True
    except Exception:
        pass
    return False


def guardian_killed_uncleanly(repo_root: Path, hardened: bool = False) -> bool:
    """True when a stale PID/start file remains but the guardian is not running.

    A clean stop removes these files via DaemonManager.cleanup(), so their
    presence while nothing is alive is evidence the daemon was killed or crashed.
    """
    if guardian_is_running(repo_root, hardened):
        return False
    pidfile = _scoped_pidfile(repo_root, hardened)
    try:
        return pidfile.exists() or pidfile.with_suffix(".start").exists()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_guardian(
    intervention: bool = True,
    daemon: bool = False,
    strict: bool = False,
    hardened: bool = False,
    *,
    allow_self_protect: bool = False,
    enable_fanotify: bool = True,
):
    # Read WATCHDOG_AVAILABLE from guard at runtime (not frozen at import)
    import deadpush.guard as _guard_mod
    if not _guard_mod.WATCHDOG_AVAILABLE:
        print("Error: watchdog package required. pip install deadpush[watch]")
        return

    from .config import load_config, dev_repo_guard_refusal
    from .control_plane import GuardianControlServer, _load_or_create_control_token
    from .guardian_handler import GuardianHandler

    config = load_config()

    refusal = dev_repo_guard_refusal(
        config.repo_root,
        allow_self_protect=allow_self_protect,
        persistent=bool(daemon or hardened),
    )
    if refusal:
        print(f"Error: {refusal}", file=sys.stderr)
        raise SystemExit(2)

    logger = setup_logging(
        daemon=daemon, hardened=hardened, repo_root=config.repo_root,
    )

    _state_dir(hardened).mkdir(parents=True, exist_ok=True)
    pidfile = _scoped_pidfile(config.repo_root, hardened)
    lockfile = _scoped_lockfile(config.repo_root, hardened)

    daemon_mgr = DaemonManager(pidfile, lockfile)

    if daemon_mgr.is_running():
        logger.warning("Guardian is already running.")
        return

    if not daemon_mgr.acquire_lock():
        logger.error("Could not acquire lock. Another instance may be running.")
        return

    try:
        prior_unclean = pidfile.exists() or daemon_mgr.startfile.exists()
    except Exception:
        prior_unclean = False

    def _note_unclean_restart(h) -> None:
        if not prior_unclean:
            return
        try:
            h.session_mgr.record_incident({"type": "guardian_unclean_restart"})
        except Exception:
            pass

    control_server = None

    if daemon:
        logger.info("Starting in DAEMON mode...")
        try:
            if os.fork() > 0:
                sys.exit(0)
            os.setsid()
            if os.fork() > 0:
                sys.exit(0)
            os.chdir("/")
            os.umask(0)

            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            with open(os.devnull, "w") as devnull:
                os.dup2(devnull.fileno(), sys.stdout.fileno())
                os.dup2(devnull.fileno(), sys.stderr.fileno())

            logger = setup_logging(daemon=True, hardened=hardened, repo_root=config.repo_root)

            import resource
            max_fd = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            if max_fd == resource.RLIM_INFINITY:
                max_fd = 1024
            log_fd = None
            for h in logging.getLogger().handlers:
                try:
                    if hasattr(h, 'stream') and hasattr(h.stream, 'fileno'):
                        log_fd = h.stream.fileno()
                except (OSError, AttributeError, ValueError):
                    pass
            for fd in range(3, max_fd):
                if fd == log_fd:
                    continue
                try:
                    os.close(fd)
                except OSError:
                    pass

            if prior_unclean:
                logger.warning(
                    "GUARDIAN RESTART (possible tamper): a previous guardian did not shut "
                    "down cleanly (stale PID file present). If you did not stop it, an agent "
                    "or process may have killed it. Soft mode cannot prevent a same-UID kill "
                    "— use hardened mode for an unkillable guardian."
                )
            daemon_mgr.write_pid(config.repo_root)
            atexit.register(daemon_mgr.cleanup)

            handler = GuardianHandler(
                config, intervention=intervention, strict_mode=strict, daemon=daemon,
                logger=logger, hardened=hardened, enable_fanotify=enable_fanotify,
            )
            _note_unclean_restart(handler)
            _control_token = _load_or_create_control_token(config.repo_root, hardened)
            control_server = GuardianControlServer(handler, repo_root=config.repo_root, hardened=hardened, token=_control_token)

            if not hardened:
                handler._start_shadow()

            _start_control_server(control_server, logger, config.repo_root, hardened)
            handler._start_fanotify()

            _run_observer(handler, logger, daemon_mgr)
        except Exception as e:
            logger.error(f"Daemon failed: {e}")
            daemon_mgr.cleanup()
    else:
        logger.info("Starting in FOREGROUND mode...")
        if prior_unclean:
            logger.warning(
                "GUARDIAN RESTART (possible tamper): a previous guardian did not shut "
                "down cleanly (stale PID file present). If you did not stop it, an agent "
                "or process may have killed it."
            )
        daemon_mgr.write_pid(config.repo_root)
        atexit.register(daemon_mgr.cleanup)

        handler = GuardianHandler(
            config, intervention=intervention, strict_mode=strict, daemon=daemon,
            logger=logger, hardened=hardened, enable_fanotify=enable_fanotify,
        )
        _note_unclean_restart(handler)
        _control_token = _load_or_create_control_token(config.repo_root, hardened)
        control_server = GuardianControlServer(handler, repo_root=config.repo_root, hardened=hardened, token=_control_token)

        if not hardened:
            handler._start_shadow()

        _start_control_server(control_server, logger, config.repo_root, hardened)
        handler._start_fanotify()

        _run_observer(handler, logger, daemon_mgr)


def _start_control_server(control_server, logger, repo_root, hardened):
    """Start the local HTTP control interface and log its status."""
    from .gpc import GpcServer

    gpc = GpcServer(repo_root, hardened=hardened)
    try:
        gpc.start()
        if control_server.guardian_handler:
            control_server.guardian_handler.gpc = gpc
        logger.info(f"Guardian Push Channel (GPC) on {gpc.socket_path}")
        atexit.register(gpc.stop)
    except Exception as e:
        logger.warning(f"GPC server could not start: {e}")

    control_server.start()
    if control_server.port:
        logger.info(f"Local control interface on http://127.0.0.1:{control_server.port} (port file: {control_server.port_file})")
        logger.info("AI agents can now query the guardian autonomously (GET /status, /quarantine-list, etc.)")
        atexit.register(control_server.stop)
        if hardened:
            try:
                shared_port = repo_root / ".guardian" / "guardian.control.port"
                shared_port.parent.mkdir(parents=True, exist_ok=True)
                shared_port.write_text(str(control_server.port))
                atexit.register(lambda p=shared_port: p.unlink(missing_ok=True))
            except Exception:
                pass
    else:
        logger.warning("Local control interface could not be started (agents can fall back to `deadpush status` / CLI)")


def _run_observer(handler, logger, daemon_mgr: DaemonManager | None = None):
    """Run the filesystem observer with automatic recovery on crashes."""
    try:
        from watchdog.observers import Observer as _Observer
    except ImportError:
        _Observer = None

    if _Observer is None:
        logger.error("Cannot start observer: watchdog not installed. Use `pip install deadpush[watch]`")
        return

    backoff = 1
    max_backoff = 30
    running = True

    def shutdown(signum, frame):
        nonlocal running
        if not running:
            return
        running = False
        logger.info("Guardian shutting down gracefully...")
        try:
            handler._stop_fanotify()
        except Exception:
            pass
        try:
            handler.safety_score.mark_clean_shutdown()
        except Exception:
            pass
        try:
            handler._stop_shadow()
        except Exception:
            pass
        try:
            handler._shutdown_workers()
        except Exception:
            pass
        if daemon_mgr is not None:
            try:
                daemon_mgr.cleanup()
            except Exception:
                pass

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    observer = None
    try:
        while running:
            try:
                if not running:
                    break
                if observer is None or not getattr(observer, 'is_alive', lambda: False)():
                    if observer is not None:
                        try:
                            observer.stop()
                            observer.join(timeout=2)
                        except Exception:
                            pass
                    observer = _Observer()
                    observer.schedule(handler, str(handler.config.repo_root), recursive=True)
                    observer.start()
                    logger.info(f"Guardian (re)watching: {handler.config.repo_root}")
                    logger.info(f"Safety Score: {handler.safety_score.get_summary()}")
                    backoff = 1

                handler._check_shadow()
                handler._check_suspension()
                handler._check_hook_integrity()
                handler._check_head_commit()
                time.sleep(1)
            except Exception as e:
                if not running:
                    break
                logger.error(f"Watcher error (auto-recovering in {backoff}s): {e}")
                if observer:
                    try:
                        observer.stop()
                    except Exception:
                        pass
                time.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
                observer = None
    except KeyboardInterrupt:
        logger.info("Guardian interrupted.")
        running = False
    finally:
        try:
            handler._stop_shadow()
        except Exception:
            pass
        try:
            handler._shutdown_workers()
        except Exception:
            pass
        if observer:
            try:
                observer.stop()
                observer.join(timeout=3)
            except Exception:
                pass
        if daemon_mgr is not None:
            try:
                daemon_mgr.cleanup()
            except Exception:
                pass
        logger.info("Observer stopped.")
        try:
            logger.info(f"SESSION SUMMARY: {handler.safety_score.get_session_summary()}")
            logger.info(f"FINAL SAFETY: {handler.safety_score.get_summary()}")
        except Exception:
            pass
        try:
            if handler and hasattr(handler, "safety_score"):
                summary = handler.safety_score.get_summary()
                incidents = handler.safety_score.incident_count()
                logger.info(f"SESSION SUMMARY: {summary} | Total incidents this session: {incidents}")
                print(f"\n[Guardian Session Summary]\n{summary}\nIncidents logged: {incidents}")
                print("Review full activity in ~/.deadpush/guardian.log")
        except Exception:
            pass
