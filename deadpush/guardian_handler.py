"""
deadpush GuardianHandler

Real-time filesystem event handler that enforces guardrails on every file
write, running as part of the guardian daemon.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from watchdog.events import FileSystemEventHandler
except ImportError:
    FileSystemEventHandler = None  # type: ignore[assignment,misc]

from .debris import DebrisDetector
from .event_pipeline import EventPipeline
from .quarantine import QuarantineManager
from .safety_score import SessionSafetyScore
from .session import SessionManager
from . import state as _state


# ---------------------------------------------------------------------------
# Path helpers (delegate to state; patchable in tests)
# ---------------------------------------------------------------------------

def _scoped_pidfile(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_pidfile(repo_root, hardened)


def _scoped_suspend_file(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_suspend_file(repo_root, hardened)


# ---------------------------------------------------------------------------
# GuardianHandler
# ---------------------------------------------------------------------------

class GuardianHandler(FileSystemEventHandler or object):
    """Real-time guardian with unified guardrail pipeline.

    Uses the full 7-category guardrails from intercept.py:
    - Watches the entire repo root via watchdog
    - Every file write goes through _run_guardrails
    - Block-level violations → quarantine + git restore + structured feedback
    """

    def __init__(
        self,
        config,
        intervention: bool = True,
        strict_mode: bool = False,
        daemon: bool = False,
        logger=None,
        hardened: bool = False,
        *,
        enable_fanotify: bool = True,
    ):
        self.config = config
        self.intervention = intervention
        self.strict_mode = strict_mode
        self.daemon = daemon
        self.hardened = hardened
        self.enable_fanotify = enable_fanotify
        self.logger = logger or logging.getLogger("deadpush.guardian")
        self.detector = DebrisDetector(config)
        self.quarantine = QuarantineManager(config.repo_root)
        self.safety_score = SessionSafetyScore(config.repo_root, hardened=hardened)
        self.safety_score.load_score()
        self.session_mgr = SessionManager()
        self.gpc = None  # GpcServer, started by run_guardian
        self._fanotify_backend = None

        # Dynamic rate limiting (based on safety score)
        self.last_intervention_ts = 0.0
        # Bound FS events: coalesce per-path, drop under backpressure
        self._pipeline = EventPipeline(
            process_fn=lambda path, event_type: self._worker_run(path, event_type),
            cooldown_fn=lambda: self._get_cooldown(),
            max_pending=2000,
            logger=self.logger,
        )
        self._last_hook_repair_ts = 0.0
        self._last_hook_problems_key = ""

        # Shadow process (watching for crashes)
        self.shadow_process: subprocess.Popen | None = None

        # Out-of-band commit detection
        self._last_head: str | None = None
        self._scanned_commits: set[str] = set()

    def fanotify_status(self) -> dict | None:
        if self._fanotify_backend is None:
            return None
        return self._fanotify_backend.describe()

    def pipeline_status(self) -> dict:
        return self._pipeline.describe()

    def gpc_status(self) -> dict | None:
        if self.gpc is None:
            return None
        return self.gpc.describe()

    def _start_fanotify(self) -> None:
        if not self.enable_fanotify or self._fanotify_backend is not None:
            return
        if not sys.platform.startswith("linux"):
            return
        try:
            from .backends.linux import LinuxEnforcementBackend

            backend = LinuxEnforcementBackend(
                self.config.repo_root,
                on_deny=self._handle_fanotify_deny,
            )
            if not backend.available():
                self.logger.info(
                    "fanotify pre-write deny unavailable (%s); watchdog-only on Linux",
                    backend._last_error or "needs Linux 5.13+ and CAP_SYS_ADMIN",
                )
                return
            backend.start(self.config.repo_root)
            self._fanotify_backend = backend
            self.logger.info(
                "fanotify pre-write deny listener starting (T2-max); "
                "watchdog remains as post-write fallback"
            )
        except Exception as e:
            self.logger.warning("Could not start fanotify backend: %s", e)

    def _stop_fanotify(self) -> None:
        if self._fanotify_backend is None:
            return
        try:
            self._fanotify_backend.stop()
        except Exception:
            pass
        self._fanotify_backend = None

    def _handle_fanotify_deny(self, rel: str, reason: str, source: str) -> None:
        """Record a kernel-level write denial (write never landed on disk)."""
        from .intercept import GuardrailResult, Violation, _write_feedback, FEEDBACK_DIR

        self.last_intervention_ts = time.time()
        score = self.safety_score.report_incident(
            15, f"Fanotify deny: {reason}", rel,
        )
        result = GuardrailResult()
        result.reject(Violation("fanotify", reason, 0, "critical"))

        self.logger.warning(
            f"FANOTIFY DENY [{source.upper()}] {rel} | {reason} | Safety: {score}/100"
        )

        try:
            _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
        except Exception:
            pass
        try:
            self.session_mgr.record_incident({
                "type": "fanotify_deny",
                "file": rel,
                "reason": reason,
                "source": source,
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass
        if self.gpc is not None:
            try:
                self.gpc.emit_incident(category="fanotify", description=reason, file=rel)
            except Exception:
                pass
        self._record_audit("fanotify.deny", {
            "file": rel,
            "reason": reason,
            "source": source,
            "score": score,
        })

    def _get_cooldown(self) -> float:
        """Dynamic cooldown based on safety score.

        Lower score = shorter cooldown = more vigilant checking.
        """
        score = self.safety_score.get_score()
        if score >= 80:
            return 1.0
        elif score >= 50:
            return 0.5
        elif score >= 20:
            return 0.2
        else:
            return 0.05

    def on_created(self, event):
        if event.is_directory:
            return
        self._enqueue(Path(event.src_path), event_type="created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._enqueue(Path(event.src_path), event_type="modified")

    def on_moved(self, event):
        # A rename/move can drop UN-SCANNED content into the repo: e.g. stage a
        # payload in a skipped dir then `mv` it into place, or rename a benign
        # file onto a dangerous path/name. on_created/on_modified never fire for
        # the destination, so evaluate it exactly like a fresh write.
        if event.is_directory:
            return
        dest = getattr(event, "dest_path", None)
        if not dest:
            return
        self._enqueue(Path(dest), event_type="moved")

    def on_deleted(self, event):
        # A deleted file's bytes are already gone (nothing to quarantine), and
        # auto-restoring would fight legitimate refactors/`git rm`. Treat rm as
        # forensic telemetry only: log it + record a session incident, without
        # touching the safety score.
        if event.is_directory:
            return
        self._handle_deletion(Path(event.src_path))

    # ------------------------------------------------------------------
    # Shadow process lifecycle
    # ------------------------------------------------------------------
    def _start_shadow(self):
        if not self.daemon:
            return
        if self.shadow_process is not None and self._shadow_alive():
            return
        pidfile = _scoped_pidfile(self.config.repo_root, self.hardened)
        respawn_cmd = [sys.executable, "-m", "deadpush_bootstrap", "guard", "--daemon"]
        if self.hardened:
            respawn_cmd.append("--hardened")
        from .guardian_lifecycle import start_shadow_process
        proc = start_shadow_process(os.getpid(), pidfile, respawn_cmd, self.config.repo_root)
        if proc is not None:
            self.shadow_process = proc
            self.logger.info("Shadow process started (will re-spawn guardian on crash)")

    def _shadow_alive(self) -> bool:
        if self.shadow_process is None:
            return False
        return self.shadow_process.poll() is None

    def _check_shadow(self):
        if not self.daemon:
            return
        if self.shadow_process is None:
            self._start_shadow()
        elif not self._shadow_alive():
            self.logger.warning("Shadow process died, restarting...")
            self._start_shadow()

    def _stop_shadow(self) -> None:
        """Terminate the per-repo shadow watchdog (prevents respawn after stop)."""
        if self.shadow_process is not None:
            try:
                if self.shadow_process.poll() is None:
                    self.shadow_process.terminate()
                    self.shadow_process.wait(timeout=3)
            except Exception:
                try:
                    self.shadow_process.kill()
                except Exception:
                    pass
            self.shadow_process = None
        from .guardian_lifecycle import stop_shadow_for_repo
        stop_shadow_for_repo(self.config.repo_root, self.hardened)

    def _check_hook_integrity(self) -> None:
        """Detect and repair tampered or missing deadpush git hooks."""
        try:
            from .hooks import repair_deadpush_hooks, verify_hooks_installed

            problems = verify_hooks_installed(self.config.repo_root)
            if not problems:
                self._last_hook_problems_key = ""
                return

            key = "|".join(sorted(problems))
            now = time.time()
            if (
                key == self._last_hook_problems_key
                and (now - self._last_hook_repair_ts) < 30.0
            ):
                return

            self.logger.warning(f"Hook integrity issue(s): {', '.join(problems)} — repairing")
            repaired = repair_deadpush_hooks(self.config.repo_root)
            self._last_hook_repair_ts = now
            self._last_hook_problems_key = key
            if repaired:
                self.logger.info(f"Reinstalled hooks: {', '.join(repaired)}")
            remaining = verify_hooks_installed(self.config.repo_root)
            if remaining and remaining == problems:
                self.logger.warning(
                    "Hook repair did not resolve: %s (will retry after cooldown)",
                    ", ".join(remaining),
                )
        except Exception as e:
            self.logger.debug(f"Hook integrity check skipped: {e}")

    # ------------------------------------------------------------------
    # Out-of-band commit detection (git plumbing / --no-verify bypass)
    # ------------------------------------------------------------------
    def _git_head(self) -> str | None:
        """Current HEAD commit sha, or None (unborn branch / not a repo)."""
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", "HEAD"],
                capture_output=True, text=True, timeout=5, cwd=self.config.repo_root,
            )
            return r.stdout.strip() or None
        except Exception:
            return None

    def _check_head_commit(self) -> None:
        """Detect commits that bypassed the hooks and re-enforce on them."""
        try:
            head = self._git_head()
            if not head:
                return
            if self._last_head is None:
                self._last_head = head
                return
            if head == self._last_head or head in self._scanned_commits:
                return
            prev = self._last_head
            self._scanned_commits.add(head)
            self._last_head = head
            self._inspect_commit(head, prev)
        except Exception as e:
            self.logger.debug(f"HEAD check error: {e}")

    def _commit_changed_paths(self, sha: str) -> list[str]:
        """Paths introduced/modified by a commit (root commits handled via --root)."""
        try:
            r = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha],
                capture_output=True, text=True, timeout=15, cwd=self.config.repo_root,
            )
            if r.returncode != 0:
                return []
            return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        except Exception:
            return []

    def _git_show_at(self, sha: str, rel: str) -> str | None:
        try:
            r = subprocess.run(
                ["git", "show", f"{sha}:{rel}"],
                capture_output=True, text=True, timeout=5, cwd=self.config.repo_root,
            )
            return r.stdout if r.returncode == 0 else None
        except Exception:
            return None

    def _scan_commit(self, sha: str) -> dict[str, Any]:
        """{rel_path: GuardrailResult} for files in a commit with BLOCK-level violations."""
        from .intercept import enforce_content, is_enforceable_path
        from .rules import RuntimeConfig

        runtime = RuntimeConfig(self.config.repo_root)
        offending: dict[str, Any] = {}
        for rel in self._commit_changed_paths(sha):
            if not is_enforceable_path(rel):
                continue
            content = self._git_show_at(sha, rel)
            if content is None:
                continue
            try:
                result = enforce_content(rel, content, self.config, runtime)
            except Exception:
                continue
            if not result.allowed:
                offending[rel] = result
        return offending

    def _is_linear_child(self, sha: str, prev: str) -> bool:
        """True when `sha` is a single-parent commit directly on top of `prev`."""
        try:
            r = subprocess.run(
                ["git", "rev-list", "--parents", "-n", "1", sha],
                capture_output=True, text=True, timeout=5, cwd=self.config.repo_root,
            )
            if r.returncode != 0:
                return False
            parts = r.stdout.split()
            return len(parts) == 2 and parts[1] == prev
        except Exception:
            return False

    def _reset_soft(self, target: str) -> bool:
        """Undo the tip commit non-destructively (all changes stay staged)."""
        try:
            r = subprocess.run(
                ["git", "reset", "--soft", target],
                capture_output=True, text=True, timeout=10, cwd=self.config.repo_root,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _inspect_commit(self, sha: str, prev: str) -> None:
        """Re-enforce a newly observed commit; act if it bypassed the hooks."""
        offending = self._scan_commit(sha)
        if not offending:
            return

        n_viol = sum(len(r.violations) for r in offending.values())
        top = next(iter(offending.values())).violations[0].description
        self.logger.critical(
            f"OUT-OF-BAND COMMIT {sha[:8]} bypassed git hooks: "
            f"{n_viol} block-level violation(s) in {len(offending)} file(s) — top: {top}"
        )
        score = self.safety_score.report_incident(
            min(50, 10 * len(offending)),
            f"Out-of-band commit {sha[:8]} bypassed hooks ({n_viol} violations)",
            sha,
        )

        reverted = False
        if self._is_linear_child(sha, prev):
            reverted = self._reset_soft(prev)
            if reverted:
                self._last_head = prev
                self._scanned_commits.add(prev)
                self.logger.warning(
                    f"Reverted out-of-band commit {sha[:8]} (git reset --soft {prev[:8]})"
                )

        for rel, result in offending.items():
            path = self.config.repo_root / rel
            try:
                self._quarantine_and_restore(path, rel, result)
            except Exception as e:
                self.logger.error(f"Failed to quarantine out-of-band file {rel}: {e}")

        try:
            self.session_mgr.record_incident({
                "type": "out_of_band_commit",
                "commit": sha,
                "reverted": reverted,
                "files": list(offending.keys()),
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # MCP suspension
    # ------------------------------------------------------------------
    def _record_audit(self, event: str, payload: dict) -> None:
        try:
            from .audit import append_audit_event
            append_audit_event(self.config.repo_root, event, payload)
        except Exception:
            pass

    def _gpc_policy_update(self, summary: str, **extra) -> None:
        self._record_audit("policy.update", {"summary": summary, **extra})
        if self.gpc is None:
            return
        try:
            self.gpc.emit_policy_update(summary, **extra)
        except Exception:
            pass

    def _gpc_maybe_instruction(self) -> None:
        """Emit INSTRUCTION when agents trigger repeated violations in a short window."""
        if self.gpc is None:
            return
        recent = self.safety_score.recent_incident_count()
        if recent < 3:
            return
        try:
            self.gpc.emit_instruction(
                "Repeated guardrail violations detected. Stop weakening protections; "
                "review feedback and restore quarantined files before continuing.",
                recent_incidents=recent,
                score=self.safety_score.get_score(),
            )
        except Exception:
            pass

    def _suspend_mcp(self, reason: str):
        """Write a suspension flag that the MCP server checks at startup."""
        suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
        try:
            suspend_file.parent.mkdir(parents=True, exist_ok=True)
            suspend_file.write_text(reason, encoding="utf-8")
            self.logger.warning(f"MCP suspended: {reason}")
            self._record_audit("session.pause", {"reason": reason, "score": self.safety_score.get_score()})
            if self.gpc is not None:
                try:
                    self.gpc.emit_session_pause(reason, score=self.safety_score.get_score())
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Failed to write MCP suspension file: {e}")

    def _unsuspend_mcp(self):
        """Remove the suspension flag so MCP can start again."""
        suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
        try:
            if suspend_file.exists():
                suspend_file.unlink()
                self.logger.info("MCP unsuspended")
                self._gpc_policy_update(
                    "MCP access restored",
                    score=self.safety_score.get_score(),
                )
        except Exception as e:
            self.logger.error(f"Failed to remove MCP suspension file: {e}")

    def _check_suspension(self):
        """Periodic check: suspend MCP if score <= 5, unsuspend if recovered."""
        if self.safety_score.get_score() <= 5:
            suspend_file = _scoped_suspend_file(self.config.repo_root, self.hardened)
            if not suspend_file.exists():
                self._suspend_mcp(
                    f"Safety score dropped to {self.safety_score.get_score()}/100. "
                    "Agent weakened guardrails repeatedly."
                )
        elif self.safety_score.get_score() > 10:
            self._unsuspend_mcp()

    # ------------------------------------------------------------------
    # Git helpers for old-source retrieval and file restoration
    # ------------------------------------------------------------------
    def _git_show(self, rel: str) -> str:
        """Get file content from git HEAD. Returns empty string if missing."""
        try:
            result = subprocess.run(
                ["git", "show", f"HEAD:{rel}"],
                capture_output=True, text=True, timeout=5,
                cwd=self.config.repo_root,
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
        return ""

    def _safe_git_source(self, rel: str) -> str | None:
        """Return HEAD content only if it passes guardrails (safe to restore)."""
        source = self._git_show(rel)
        if not source:
            return None
        from .intercept import enforce_content
        from .rules import RuntimeConfig

        runtime = RuntimeConfig(self.config.repo_root)
        result = enforce_content(rel, source, self.config, runtime)
        if not result.allowed:
            self.logger.warning(
                f"Refusing git restore for {rel}: HEAD content also violates guardrails"
            )
            return None
        return source

    def _unstage_if_staged(self, rel: str) -> None:
        """Remove a file from the git index if it is staged."""
        try:
            check = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--", rel],
                capture_output=True, text=True, timeout=5,
                cwd=self.config.repo_root,
            )
            if check.returncode != 0 or rel not in {
                line.strip() for line in check.stdout.splitlines() if line.strip()
            }:
                return
            subprocess.run(
                ["git", "rm", "--cached", "-f", "--", rel],
                capture_output=True, text=True, timeout=5,
                cwd=self.config.repo_root,
            )
            self.logger.info(f"Unstaged {rel} from git index")
        except Exception as e:
            self.logger.debug(f"Unstage skipped for {rel}: {e}")

    def _restore_from_git(self, rel: str) -> bool:
        """Restore a file from git HEAD when HEAD content is safe."""
        old = self._safe_git_source(rel)
        if old is None:
            try:
                dest = self.config.repo_root / rel
                if dest.exists():
                    dest.unlink()
                    self.logger.info(f"Removed {rel} (no safe git version to restore)")
            except Exception as e:
                self.logger.debug(f"Could not remove unsafe file {rel}: {e}")
            return False
        try:
            dest = self.config.repo_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(old, encoding="utf-8")
            self.logger.info(f"Restored {rel} from git HEAD (reverted agent write)")
            return True
        except Exception as e:
            self.logger.error(f"Failed to restore {rel} from git: {e}")
            return False

    # ------------------------------------------------------------------
    # Main evaluation pipeline
    # ------------------------------------------------------------------
    # H-04: post-write quarantine always has a race. Keep the stability wait
    # short so finished writes are evaluated quickly; editors that finish via
    # atomic rename are handled immediately (event_type == "moved").
    STABILITY_SECONDS = 0.10
    STABILITY_POLL = 0.02
    FAST_STABLE_MAX_BYTES = 65536

    def _enqueue(self, path: Path, event_type: str):
        try:
            if not path.exists():
                return
            skip_names = {"__pycache__", ".git", "node_modules", ".deadpush",
                          ".deadpush-quarantine", ".deadpush-archive",
                          ".deadpush-config-backups"}
            if any(part in skip_names for part in path.parts):
                return
            try:
                rel = path.relative_to(self.config.repo_root).as_posix()
            except ValueError:
                return
            self._pipeline.enqueue(path, event_type, rel=rel)
        except Exception as e:
            self.logger.debug(f"Enqueue error on {path}: {e}")

    def _stability_required(self, path: Path, event_type: str) -> float:
        """How long size+mtime must stay unchanged before scanning."""
        if event_type == "moved":
            return 0.0
        try:
            if path.stat().st_size <= self.FAST_STABLE_MAX_BYTES:
                return min(self.STABILITY_SECONDS, 0.05)
        except OSError:
            pass
        return self.STABILITY_SECONDS

    def _worker_run(self, path: Path, event_type: str):
        try:
            if self._is_stable(path, required=self._stability_required(path, event_type)):
                self._process_event(path, event_type)
        except Exception as e:
            self.logger.debug(f"Worker error on {path}: {e}")

    def _is_stable(
        self,
        path: Path,
        timeout: float = 1.0,
        *,
        required: float | None = None,
    ) -> bool:
        """Return True when size+mtime stay unchanged for ``required`` seconds."""
        need = self.STABILITY_SECONDS if required is None else max(0.0, float(required))
        if need <= 0:
            return path.exists()
        deadline = time.time() + timeout
        stable_key: tuple[int, int] | None = None
        stable_since: float | None = None
        while time.time() < deadline:
            try:
                st = path.stat()
                key = (st.st_size, st.st_mtime_ns)
            except OSError:
                return False
            now = time.time()
            if key == stable_key and stable_since is not None:
                if (now - stable_since) >= need:
                    return True
            else:
                stable_key = key
                stable_since = now
            time.sleep(self.STABILITY_POLL)
        return False

    def _shutdown_workers(self) -> None:
        try:
            self._pipeline.shutdown(wait=True)
        except Exception as e:
            self.logger.debug(f"Worker shutdown skipped: {e}")

    @staticmethod
    def _looks_transient(name: str) -> bool:
        """True for editor/tool scratch files whose deletion is normal churn."""
        n = name.lower()
        if n == ".ds_store":
            return True
        if n.startswith(".#") or n.startswith("~$"):
            return True
        if n.isdigit():
            return True
        return n.endswith((".tmp", ".temp", ".swp", ".swx", ".swo", "~", ".bak", ".orig"))

    def _handle_deletion(self, path: Path):
        """Record a deletion as forensic telemetry."""
        try:
            skip_names = {"__pycache__", ".git", "node_modules", ".deadpush",
                          ".deadpush-quarantine", ".deadpush-archive",
                          ".deadpush-config-backups"}
            if any(part in skip_names for part in path.parts):
                return
            if self._looks_transient(path.name):
                return
            try:
                rel = path.relative_to(self.config.repo_root).as_posix()
            except (ValueError, Exception):
                return
            self.logger.info(f"DELETE {rel} (recorded; not restored)")
            try:
                self.session_mgr.record_incident({"type": "file_deleted", "file": rel})
            except Exception:
                pass
        except Exception as e:
            self.logger.debug(f"Deletion handling error on {path}: {e}")

    def _process_event(self, path: Path, event_type: str):
        """Core single-event evaluation pipeline."""
        now = time.time()
        try:
            rel = path.relative_to(self.config.repo_root).as_posix()
        except (ValueError, Exception):
            return

        self.last_intervention_ts = now

        from .bootstrap import is_bootstrap_path

        if is_bootstrap_path(rel, self.config.repo_root):
            try:
                self.session_mgr.record_file_change(rel)
            except Exception:
                pass
            return

        # Lockdown: at score 0, quarantine every write (no pass-through)
        if self.intervention and self.safety_score.get_score() <= 0 and path.exists():
            from .intercept import GuardrailResult, Violation, _write_feedback, FEEDBACK_DIR

            result = GuardrailResult()
            result.reject(Violation(
                "lockdown",
                "Guardian lockdown active (safety score 0): all writes quarantined",
                0,
                "critical",
            ))
            self._quarantine_and_restore(path, rel, result)
            self.safety_score.report_incident(5, f"Lockdown quarantine: {rel}", str(path))
            try:
                _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
            except Exception:
                pass
            self.logger.critical(f"LOCKDOWN [{event_type.upper()}] quarantined {rel}")
            if self.gpc is not None:
                try:
                    self.gpc.emit_lockdown(
                        "Guardian lockdown active (safety score 0): all writes quarantined",
                        file=rel,
                        score=self.safety_score.get_score(),
                    )
                except Exception:
                    pass
            self._record_audit("guardrail.lockdown", {
                "file": rel,
                "description": "Guardian lockdown active (safety score 0)",
                "score": self.safety_score.get_score(),
            })
            return

        # STEP 1: Check blocked files
        if self.config.is_blocked(rel):
            self._intervene_blocked(path, rel, event_type)
            return

        # STEP 2: Run full guardrail pipeline
        from .intercept import _run_guardrails, _write_feedback, FEEDBACK_DIR

        old_source = self._git_show(rel)

        result = _run_guardrails(
            path, self.config.repo_root, self.config,
            old_source=old_source or None, rel_path_override=rel,
        )

        # STEP 3: Enforce guardrail results
        if not result.allowed:
            self._intervene_guardrails(path, rel, result, event_type)
            return

        if result.violations:
            for v in result.violations:
                penalty = 8 if v.severity == "high" else 4
                self.safety_score.report_incident(penalty, f"Warn: {v.description}", str(path))
            self.logger.warning(
                f"WARN [{event_type.upper()}] {rel} | "
                f"{len(result.violations)} warn-level violation(s) | "
                f"Safety: {self.safety_score.get_score()}/100"
            )
            try:
                _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
            except Exception:
                pass
            self.session_mgr.record_incident({
                "type": "guardrail_warn", "file": rel,
                "count": len(result.violations),
            })

        # STEP 4: Debris scan (secondary, in addition to guardrails)
        try:
            from .types import FileInfo
            fi = FileInfo(
                path=path,
                rel_path=path.relative_to(self.config.repo_root),
                size=path.stat().st_size,
                is_text=True,
                mtime=time.time(),
            )
            debris = self.detector.scan([fi])
            blocking = [d for d in debris if d.block_push]
            if blocking:
                self._intervene_blocking_debris(path, blocking, event_type)
        except Exception:
            pass

        # STEP 5: Record in session
        try:
            self.session_mgr.record_file_change(rel)
            self.session_mgr.update_safety_score(self.safety_score.get_score())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Intervention actions
    # ------------------------------------------------------------------
    def _intervene_blocked(self, path: Path, rel: str, event_type: str):
        """Intervene when a blocked file is written (claude.md, etc.)."""
        from .intercept import GuardrailResult, Violation

        self.last_intervention_ts = time.time()
        score = self.safety_score.report_incident(25, f"Blocked file written: {rel}", str(path))

        result = GuardrailResult()
        result.reject(Violation("blocked_file", f"File {rel} is in the blocked list and cannot be written", 0, "critical"))

        self._quarantine_and_restore(path, rel, result)

        self.logger.warning(
            f"INTERVENTION [{event_type.upper()}] BLOCKED FILE: {rel} | "
            f"Moved to quarantine + restored from git | Safety: {score}/100"
        )
        try:
            self.session_mgr.record_incident({
                "type": "blocked_file", "file": rel, "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass

    def _intervene_guardrails(self, path: Path, rel: str, result, event_type: str):
        """Intervene when guardrails detect block-level violations."""
        from .intercept import _write_feedback, FEEDBACK_DIR

        self.last_intervention_ts = time.time()
        penalty = min(25, 5 * len(result.violations))
        score = self.safety_score.report_incident(penalty, f"Guardrail block: {result.violations[0].description}", str(path))

        self._quarantine_and_restore(path, rel, result)

        self.logger.warning(
            f"INTERVENTION [{event_type.upper()}] GUARDRAIL BLOCK: {rel} | "
            f"{len(result.violations)} violation(s) | "
            f"Top: {result.violations[0].description} | "
            f"Safety: {score}/100"
        )

        try:
            _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
        except Exception:
            pass

        try:
            self.session_mgr.record_incident({
                "type": "guardrail_block", "file": rel,
                "violations": [v.to_dict() for v in result.violations],
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass

        self._gpc_maybe_instruction()

    def _quarantine_and_restore(self, path: Path, rel: str, result) -> None:
        """Quarantine the violating file, unstage if needed, restore safe git version."""
        if self.intervention and path.exists():
            reason = result.violations[0].description if result.violations else "guardrail violation"
            try:
                quarantined = self.quarantine.quarantine(path, reason)
                self.logger.info(f"Quarantined: {quarantined}")
                if self.gpc is not None:
                    try:
                        self.gpc.emit_incident(
                            category=result.violations[0].category if result.violations else "guardrail",
                            description=reason,
                            file=rel,
                        )
                    except Exception:
                        pass
                self._record_audit("guardrail.quarantine", {
                    "file": rel,
                    "description": reason,
                    "category": result.violations[0].category if result.violations else "guardrail",
                    "violations": [v.to_dict() for v in result.violations[:5]],
                })
            except Exception as e:
                self.logger.error(f"Failed to quarantine {path}: {e}")
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass

        self._unstage_if_staged(rel)
        self._restore_from_git(rel)

    def _intervene_blocking_debris(self, path: Path, blocking_items, event_type: str):
        """Quarantine files with block_push debris (secrets, LLM context, etc.)."""
        from .intercept import GuardrailResult, Violation, _write_feedback, FEEDBACK_DIR

        self.last_intervention_ts = time.time()
        rel = path.relative_to(self.config.repo_root).as_posix()
        top = max(blocking_items, key=lambda d: (d.block_push, d.confidence))
        score = self.safety_score.report_incident(12, top.reason, str(path))

        result = GuardrailResult()
        result.reject(Violation("debris", top.reason, 0, "critical"))

        self.logger.warning(
            f"INTERVENTION [{event_type.upper()}] {top.category} in {path.name} | "
            f"{top.reason} | Safety: {score}/100"
        )

        if self.intervention:
            self._quarantine_and_restore(path, rel, result)

        try:
            _write_feedback(self.config.repo_root / FEEDBACK_DIR, rel, result)
        except Exception:
            pass
        try:
            self.session_mgr.record_incident({
                "type": "blocking_debris",
                "reason": top.reason,
                "file": rel,
                "score": score,
            })
            self.session_mgr.update_safety_score(score)
        except Exception:
            pass
