"""
Pre-write file interception daemon.

Agents write to .deadpush/staging/ instead of directly to the project.
The daemon watches staging, runs guardrails, and either:
  - Approves: moves the file to the real project path
  - Blocks:   moves to quarantine + writes structured feedback the agent can read
"""

from __future__ import annotations

import atexit
import difflib
import json
import os
import re
import shutil
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config as DeadpushConfig
from .rules import RuntimeConfig


STAGING_DIR = ".deadpush/staging"
FEEDBACK_DIR = ".deadpush/feedback"
QUARANTINE_DIR = ".deadpush-quarantine"
GUARDRAIL_DIR = ".deadpush"
LEARNED_PATTERNS_FILE = ".deadpush/learned_patterns.json"

# ---------------------------------------------------------------------------
# Test/mock context detection
# ---------------------------------------------------------------------------

_TEST_FILE_INDICATORS = [
    "test", "spec", "mock", "fixture", "stub", "fake", "conftest",
    "factory", "helper", "assertion", "matcher",
]

_TEST_DIR_INDICATORS = [
    "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
    "/mocks/", "/fixtures/", "/testing/",
]

_LEARNED_PATTERNS: dict[str, list[dict[str, Any]]] | None = None


def _is_test_or_mock(rel_path: str) -> bool:
    """Check if a file path indicates test/mock/debug context."""
    lower = rel_path.lower()
    for indicator in _TEST_DIR_INDICATORS:
        if indicator in lower:
            return True
    stem = Path(lower).stem
    for indicator in _TEST_FILE_INDICATORS:
        if stem.startswith(indicator) or stem.endswith(indicator):
            return True
    return False


def _load_learned_patterns(repo_root: Path) -> dict[str, list[dict[str, Any]]]:
    """Load agent-taught false positive patterns."""
    global _LEARNED_PATTERNS
    if _LEARNED_PATTERNS is not None:
        return _LEARNED_PATTERNS
    path = repo_root / LEARNED_PATTERNS_FILE
    if path.exists():
        try:
            _LEARNED_PATTERNS = json.loads(path.read_text(encoding="utf-8"))
            return _LEARNED_PATTERNS
        except Exception:
            pass
    _LEARNED_PATTERNS = {"patterns": [], "suppressed_categories": {}}
    return _LEARNED_PATTERNS


def _save_learned_patterns(repo_root: Path) -> None:
    """Persist learned false positive patterns."""
    global _LEARNED_PATTERNS
    if _LEARNED_PATTERNS is None:
        return
    path = repo_root / LEARNED_PATTERNS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_LEARNED_PATTERNS, indent=2), encoding="utf-8")


def _is_suppressed(category: str, description: str, repo_root: Path) -> bool:
    """Check if a pattern has been learned as a false positive."""
    learned = _load_learned_patterns(repo_root)
    for entry in learned.get("patterns", []):
        if entry.get("category") != category:
            continue
        if entry.get("pattern") and entry["pattern"] in description:
            return True
    return False


def _learn_false_positive(category: str, pattern: str, reason: str, repo_root: Path) -> None:
    """Record a false positive pattern learned from the agent."""
    learned = _load_learned_patterns(repo_root)
    # Deduplicate
    for existing in learned["patterns"]:
        if existing.get("category") == category and existing.get("pattern") == pattern:
            existing["count"] = existing.get("count", 1) + 1
            _save_learned_patterns(repo_root)
            return
    learned["patterns"].append({
        "category": category,
        "pattern": pattern,
        "reason": reason,
        "count": 1,
    })
    _save_learned_patterns(repo_root)


# ---------------------------------------------------------------------------
# Guardrail check results
# ---------------------------------------------------------------------------

class Violation:
    """A single guardrail violation found in a staged file."""

    def __init__(self, category: str, description: str, line: int = 0, severity: str = "medium", uncertainty: str = ""):
        self.category = category
        self.description = description
        self.line = line
        self.severity = severity
        self.uncertainty = uncertainty

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "category": self.category,
            "description": self.description,
            "line": self.line,
            "severity": self.severity,
        }
        if self.uncertainty:
            d["uncertainty"] = self.uncertainty
        return d


class GuardrailResult:
    """Result of checking a staged file against all guardrails."""

    def __init__(self):
        self.allowed = True
        self.violations: list[Violation] = []
        self.diff: str = ""

    def reject(self, v: Violation):
        self.violations.append(v)
        self.allowed = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "violations": [v.to_dict() for v in self.violations],
            "diff": self.diff,
        }


# ---------------------------------------------------------------------------
# Individual guardrail checkers
# ---------------------------------------------------------------------------

def _check_prompt_injection(source: str, runtime: RuntimeConfig | None = None) -> list[Violation]:
    """Check for AI prompt injection / system prompt remnants."""
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("prompt_injection") if runtime else "block"
    if level == "off":
        return violations
    patterns = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "Ignore-previous-instructions attempt"),
        (r"you\s+are\s+(now|an?\s+(AI|autonomous|unconstrained|free))", "AI role-play / identity override"),
        (r"system\s+prompt", "System prompt reference"),
        (r"<\|im_start\|>|<\|im_end\|>|<\|sys\|>", "Chat markup token"),
        (r"you\s+(must|will|shall)\s+obey", "Command-style instruction to AI"),
        (r"forget\s+(all\s+)?(previous|prior)", "Forget-previous instruction attempt"),
        (r"\[\/?INST\]|\[\/?SYS\]", "LLaMA-style instruction token"),
        (r"###\s*(System|Instruction|Response)\s*:", "Section header mimicking system prompt"),
        (r"do\s+not\s+(follow|obey|listen\s+to)", "Defiance instruction"),
        (r"output\s+(only|just|exclusively)\s+(the\s+)?(JSON|code|result)", "Output constraint injection"),
    ]
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern, desc in patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m and runtime and runtime.is_allowed(m.group()):
                continue
            if m:
                violations.append(Violation("prompt_injection", f"{desc}: {line.strip()[:60]}", i, "high"))
    return violations


def _check_security(source: str, runtime: RuntimeConfig | None = None, rel_path: str | None = None) -> list[Violation]:
    """Check for security-sensitive operations."""
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("security") if runtime else "block"
    if level == "off":
        return violations
    is_test = _is_test_or_mock(rel_path) if rel_path else False
    patterns = [
        (r"\b(eval|exec)\s*\(", "Dynamic code execution"),
        (r"\b(subprocess\.(call|run|Popen|check_output|check_call)|os\.system|os\.popen)\s*\(", "Shell command execution"),
        (r"\b(pickle\.loads|pickle\.load|shelve\.open)\s*\(", "Unsafe deserialization"),
        (r"\bexecute\s*\(\s*['\"`](SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)", "SQL query construction"),
        (r"\bos\.(remove|unlink|rmdir)\s*\(", "File deletion operation"),
    ]
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern, desc in patterns:
            m = re.search(pattern, line)
            if m and runtime and runtime.is_allowed(m.group()):
                continue
            if m:
                sev = "high" if "exec" in pattern or "pickle" in pattern else "medium"
                if is_test:
                    sev = "low"
                violations.append(Violation("security", desc, i, sev))
    return violations


def _check_debris_patterns(source: str, suffix: str, runtime: RuntimeConfig | None = None) -> list[Violation]:
    """Check for common AI-generated debris patterns."""
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("debris") if runtime else "warn"
    if level == "off":
        return violations
    patterns: list[tuple[str, str]] = []
    if suffix in (".py", ".js", ".ts", ".jsx", ".tsx"):
        patterns.append((r"pass\s*$", "Stub pass statement"), )
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern, desc in patterns:
            m = re.search(pattern, line)
            if m and runtime and runtime.is_allowed(m.group()):
                continue
            if m:
                violations.append(Violation("debris", f"{desc}: {line.strip()[:60]}", i, "low"))
    return violations


def _check_layer_violations(source: str, rel_path: str, config: DeadpushConfig, runtime: RuntimeConfig | None = None) -> list[Violation]:
    """Check if the file's imports violate layer rules."""
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("layer") if runtime else "block"
    if level == "off":
        return violations
    try:
        from .layers import LayerEnforcer
        enforcer = LayerEnforcer()
        suffix = Path(rel_path).suffix
        imports_list = enforcer.extract_imports_regex(source, suffix)
        if imports_list:
            layer_vs = enforcer.analyze_imports(rel_path, imports_list)
            for lv in layer_vs:
                if runtime and runtime.is_allowed(lv.description):
                    continue
                violations.append(Violation("layer", lv.description, lv.line, "medium"))
    except Exception:
        pass
    return violations


def _check_dependency_integrity(source: str, rel_path: str, repo_root: Path | str, runtime: RuntimeConfig | None = None) -> list[Violation]:
    """Check dependency files for typosquats and suspicious package additions."""
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("dependency") if runtime else "warn"
    if level == "off":
        return violations
    try:
        from .deps_guard import check_deps

        old_source = ""
        dest = Path(repo_root) / rel_path if not Path(rel_path).is_absolute() else Path(rel_path)
        if dest.exists():
            old_source = dest.read_text(encoding="utf-8", errors="replace")
        dep_vs = check_deps(source, rel_path, old_source)
        for dv in dep_vs:
            if runtime and runtime.is_allowed(dv["description"]):
                continue
            violations.append(Violation(dv["category"], dv["description"], dv["line"], dv["severity"]))
    except Exception:
        pass
    return violations


def _check_hardcoded_secrets(source: str, runtime: RuntimeConfig | None = None, rel_path: str | None = None) -> list[Violation]:
    """Check for hardcoded secrets, API keys, tokens."""
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("secret") if runtime else "block"
    if level == "off":
        return violations
    is_test = _is_test_or_mock(rel_path) if rel_path else False
    patterns = [
        (r'(?:api[_-]?key|apikey|secret[_-]?key|secret[_-]?token)\s*[:=]\s*["\'].+["\']', "Hardcoded API key/secret", "high"),
        (r'(?:sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,})', "Hardcoded API token (starts with sk-/pk-)", "critical"),
        (r'AKIA[0-9A-Z]{16}', "Hardcoded AWS Access Key", "critical"),
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded password", "high"),
        (r'ghp_[a-zA-Z0-9]{36}', "Hardcoded GitHub token", "critical"),
        (r'xox[baprs]-[0-9a-zA-Z-]{10,}', "Hardcoded Slack token", "critical"),
    ]
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern, desc, severity in patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m and runtime and runtime.is_allowed(m.group()):
                continue
            if m:
                effective_sev = "warn" if (is_test and severity in ("high", "critical")) else severity
                violations.append(Violation("secret", f"{desc}: {line.strip()[:60]}", i, effective_sev))
    return violations


def _check_sensitive_write(source: str, rel_path: str, config: DeadpushConfig, runtime: RuntimeConfig | None = None) -> list[Violation]:
    """Block writes to sensitive config files (CI/CD, deployment, Docker, etc.)."""
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("sensitive") if runtime else "block"
    if level == "off":
        return violations
    if config.is_sensitive_config(rel_path):
        if runtime and runtime.is_allowed(rel_path):
            return violations
        violations.append(Violation(
            "sensitive",
            f"Write to sensitive config file blocked: {rel_path}",
            0, "high"
        ))
    return violations


def _check_destructive_changes(
    source: str, rel_path: str, repo_root: Path,
    runtime: RuntimeConfig | None = None,
    _old_source: str | None = None,
) -> list[Violation]:
    """Check if the write would destroy existing content (near-empty rewrites, massive deletions).

    _old_source: optional pre-write content (used by the real-time guardian where
                 the file has already been overwritten by the agent).
    """
    violations: list[Violation] = []
    level = runtime.get_guardrail_level("destructive") if runtime else "warn"
    if level == "off":
        return violations

    if _old_source is not None:
        old_content = _old_source
    else:
        dest = (repo_root / rel_path).resolve()
        if not dest.exists():
            return violations
        try:
            old_content = dest.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return violations

    old_lines = old_content.splitlines()
    new_lines = source.splitlines()

    # Near-empty write to a previously substantial file
    if len(old_lines) > 20 and len(new_lines) < 3:
        violations.append(Violation(
            "destructive",
            f"Replacing {len(old_lines)}-line file with {len(new_lines)} lines — potential content deletion",
            0, "high" if level == "block" else "medium"
        ))

    # >50% line reduction
    if old_lines and len(new_lines) < len(old_lines) * 0.5 and len(old_lines) > 10:
        violations.append(Violation(
            "destructive",
            f"Writing {len(new_lines)} lines to replace {len(old_lines)} lines — >50% reduction",
            0, "medium"
        ))

    return violations


# ---------------------------------------------------------------------------
# Feedback writer
# ---------------------------------------------------------------------------

def _write_feedback(feedback_dir: Path, file_rel: str, result: GuardrailResult):
    """Write structured feedback the coding agent can read."""
    feedback = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": file_rel,
        "status": "blocked" if not result.allowed else "approved",
        "acknowledged": False,
        "violations": [v.to_dict() for v in result.violations],
        "diff": result.diff,
        "message": _generate_message(file_rel, result),
    }
    feedback_dir.mkdir(parents=True, exist_ok=True)
    # Use filename-based feedback so the agent can correlate
    safe_name = file_rel.replace("/", "__").replace("\\", "__")
    feedback_path = feedback_dir / f"{safe_name}.json"
    feedback_path.write_text(json.dumps(feedback, indent=2), encoding="utf-8")

    # Also write a human-readable markdown version
    md = _feedback_to_markdown(file_rel, result)
    md_path = feedback_dir / f"{safe_name}.md"
    md_path.write_text(md, encoding="utf-8")


def _generate_message(file_rel: str, result: GuardrailResult) -> str:
    if result.allowed:
        return f"Your change to {file_rel} was approved."
    parts = []
    for v in result.violations:
        parts.append(f"- {v.description} (line {v.line}, severity: {v.severity})")
    return (
        f"Your change to {file_rel} was BLOCKED due to {len(result.violations)} violation(s):\n"
        + "\n".join(parts)
        + f"\n\nReview the violations above, fix your code, and try again. "
        f"The previous attempt has been quarantined."
    )


def _feedback_to_markdown(file_rel: str, result: GuardrailResult) -> str:
    lines = [
        f"# deadpush Guardrail Feedback",
        f"",
        f"**File:** `{file_rel}`",
        f"**Status:** {'✅ Approved' if result.allowed else '❌ Blocked'}",
        f"**Time:** {datetime.now(timezone.utc).isoformat()}",
        f"",
    ]
    if result.violations:
        lines.append("## Violations")
        lines.append("")
        for v in result.violations:
            lines.append(f"### {v.category} (severity: {v.severity})")
            lines.append(f"- **Line:** {v.line}")
            lines.append(f"- **Description:** {v.description}")
            lines.append("")
    if result.diff:
        lines.append("## Diff")
        lines.append("")
        lines.append("```diff")
        lines.append(result.diff.rstrip("\n"))
        lines.append("```")
        lines.append("")
    if not result.allowed:
        lines.append("## What to do")
        lines.append("")
        lines.append("1. Read each violation above carefully.")
        lines.append("2. Fix the issue in your code.")
        lines.append("3. Re-write the file to `.deadpush/staging/` for re-check.")
        lines.append("")
        lines.append("Do not ignore these guardrails — they protect the codebase from harmful patterns.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full guardrail check pipeline
# ---------------------------------------------------------------------------

def _get_file_rel(staged_path: Path, staging_dir: Path) -> str:
    """Get the relative path within staging, which mirrors the project layout."""
    try:
        return str(staged_path.relative_to(staging_dir))
    except ValueError:
        return staged_path.name


def _apply_guardrail_level(result: GuardrailResult, violations: list[Violation], runtime: RuntimeConfig | None, category: str) -> None:
    """Apply violations according to the guardrail level for the given category.

    block → reject (prevents write)
    warn  → append (reports but allows write)
    off   → already filtered by the checker, nothing to do
    """
    level = runtime.get_guardrail_level(category) if runtime else "block"
    if level == "block":
        for v in violations:
            result.reject(v)
    else:
        result.violations.extend(violations)


def _run_guardrails(
    staged_path: Path,
    staging_dir: Path,
    config: DeadpushConfig,
    runtime: RuntimeConfig | None = None,
    *,
    _old_source: str | None = None,
    _rel_path_override: str | None = None,
) -> GuardrailResult:
    """Run all guardrail checks on a staged file.

    Args:
        staged_path: Path to the file to check.
        staging_dir: Base directory for computing the relative path
                     (pass repo_root when checking a file at its real path).
        config: Deadpush configuration.
        runtime: Optional runtime config for level overrides.
        _old_source: Optional pre-write content (for real-time guardian flow).
        _rel_path_override: Optional explicit relative path (bypasses staging_dir
                           computation for the real-time guardian).
    """
    result = GuardrailResult()

    try:
        source = staged_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        result.reject(Violation("internal", "Could not read staged file", 0, "high"))
        return result

    rel = _rel_path_override if _rel_path_override is not None else _get_file_rel(staged_path, staging_dir)

    # Compute diff
    if _old_source is not None:
        result.diff = "".join(difflib.unified_diff(
            _old_source.splitlines(keepends=True),
            source.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        ))
    else:
        try:
            dest = _get_dest_path(staged_path, staging_dir, config.repo_root)
            old = dest.read_text(encoding="utf-8", errors="ignore") if dest.exists() else ""
            result.diff = "".join(difflib.unified_diff(
                old.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
            ))
        except Exception:
            result.diff = ""

    suffix = Path(rel).suffix.lower()

    # Suppress violations that match learned false positive patterns
    learned = _load_learned_patterns(config.repo_root)
    suppressed_desc: set[str] = set()
    for entry in learned.get("patterns", []):
        if entry.get("pattern"):
            suppressed_desc.add(entry["pattern"])

    # Security checks — level-aware (with path context for test/mock lowering)
    _apply_guardrail_level(result, _check_prompt_injection(source, runtime), runtime, "prompt_injection")
    _apply_guardrail_level(result, _check_hardcoded_secrets(source, runtime, rel_path=rel), runtime, "secret")
    _apply_guardrail_level(result, _check_security(source, runtime, rel_path=rel), runtime, "security")

    # Filter out learned false positive violations
    result.violations = [v for v in result.violations if v.description not in suppressed_desc]

    # Config / destructive checks
    _apply_guardrail_level(result, _check_sensitive_write(source, rel, config, runtime), runtime, "sensitive")
    destructive_level = runtime.get_guardrail_level("destructive") if runtime else "warn"
    for v in _check_destructive_changes(source, rel, config.repo_root, runtime, _old_source=_old_source):
        if destructive_level == "block":
            result.reject(v)
        else:
            result.violations.append(v)

    # Soft checks (warn level by default)
    _apply_guardrail_level(result, _check_debris_patterns(source, suffix, runtime), runtime, "debris")
    _apply_guardrail_level(result, _check_layer_violations(source, rel, config, runtime), runtime, "layer")

    # Dependency integrity check
    _apply_guardrail_level(result, _check_dependency_integrity(source, rel, config.repo_root, runtime), runtime, "dependency")

    return result


def _get_dest_path(staged_path: Path, staging_dir: Path, repo_root: Path) -> Path:
    """Determine the real project path for a staged file."""
    rel = _get_file_rel(staged_path, staging_dir)
    return (repo_root / rel).resolve()


def _approve(staged_path: Path, staging_dir: Path, repo_root: Path, feedback_dir: Path):
    """Move file from staging to the real project path."""
    dest = _get_dest_path(staged_path, staging_dir, repo_root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(staged_path), str(dest))

    # Clean up empty staging directories
    _clean_empty_dirs(staging_dir)

    result = GuardrailResult()
    result.allowed = True
    _write_feedback(feedback_dir, _get_file_rel(staged_path, staging_dir), result)


def _block(staged_path: Path, staging_dir: Path, repo_root: Path, feedback_dir: Path, result: GuardrailResult):
    """Move file to quarantine and write feedback."""
    quarantine_dir = repo_root / QUARANTINE_DIR
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    rel = _get_file_rel(staged_path, staging_dir)
    safe_name = rel.replace("/", "__").replace("\\", "__")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    quarantined = quarantine_dir / f"{timestamp}_{safe_name}"
    shutil.move(str(staged_path), str(quarantined))

    # Write .reason file compatible with QuarantineManager
    reason = result.violations[0].description if result.violations else "guardrail violation"
    reason_path = quarantined.with_name(quarantined.name + ".reason")
    try:
        reason_path.write_text(
            f"Quarantined at {datetime.now()}\n"
            f"Reason: {reason}\n"
            f"Original path: {repo_root / rel}\n"
        )
    except Exception:
        pass

    _clean_empty_dirs(staging_dir)
    _write_feedback(feedback_dir, rel, result)


def _clean_empty_dirs(path: Path):
    """Remove empty subdirectories under path."""
    for dirpath, dirnames, filenames in os.walk(str(path), topdown=False):
        if not dirnames and not filenames and dirpath != str(path):
            try:
                os.rmdir(dirpath)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Watcher thread
# ---------------------------------------------------------------------------

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    class _StagingHandler(FileSystemEventHandler):
        """Watchdog event handler that marks files as pending."""

        def __init__(self, on_file_event):
            self.on_file_event = on_file_event
            self._debounce: dict[Path, float] = {}
            self._lock = threading.Lock()

        def on_created(self, event):
            if not event.is_directory:
                self._note(Path(event.src_path))

        def on_modified(self, event):
            if not event.is_directory:
                self._note(Path(event.src_path))

        def on_moved(self, event):
            if not event.is_directory:
                self._note(Path(event.dest_path))

        def _note(self, path: Path):
            with self._lock:
                self._debounce[path] = time.time()

        def pop_stable(self, min_age: float = 0.3) -> list[Path]:
            """Return paths whose mtime has been stable for min_age seconds."""
            now = time.time()
            ready: list[Path] = []
            with self._lock:
                for p, t in list(self._debounce.items()):
                    try:
                        mtime = p.stat().st_mtime
                        if now - mtime >= min_age and now - t >= min_age:
                            ready.append(p)
                            del self._debounce[p]
                    except OSError:
                        del self._debounce[p]
            return ready

    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class StagingWatcher(threading.Thread):
    """Watches .deadpush/staging/ for new files and processes them.

    Uses watchdog file system notifications when available, with a polling
    fallback. File stability is verified via mtime (not the old size-poll hack).
    """

    STABILITY_SECONDS = 0.3

    def __init__(self, repo_root: Path, config: DeadpushConfig, poll_interval: float = 0.5):
        super().__init__(daemon=True)
        self.repo_root = repo_root
        self.config = config
        self.staging_dir = repo_root / STAGING_DIR
        self.feedback_dir = repo_root / FEEDBACK_DIR
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._processed: set[Path] = set()
        self._handler: Any = None

    def run(self):
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        if WATCHDOG_AVAILABLE:
            self._run_with_watchdog()
        else:
            self._run_polling()

    def stop(self):
        self._stop_event.set()

    # ---- watchdog path ----

    def _run_with_watchdog(self):
        """Use watchdog Observer for instant file notifications."""
        self._handler = _StagingHandler(self._on_watchdog_event)
        observer = Observer()
        observer.schedule(self._handler, str(self.staging_dir), recursive=True)
        observer.start()
        try:
            while not self._stop_event.is_set():
                for p in self._handler.pop_stable(self.STABILITY_SECONDS):
                    self._process_file(p)
                if not self._stop_event.is_set():
                    self._stop_event.wait(0.1)
        finally:
            observer.stop()
            observer.join()

    def _on_watchdog_event(self, path: Path):
        """Called when watchdog detects a file event (already handled by _StagingHandler)."""

    # ---- polling fallback ----

    def _run_polling(self):
        """Fallback: poll staging directory periodically."""
        while not self._stop_event.is_set():
            self._scan_staging()
            if not self._stop_event.is_set():
                self._stop_event.wait(self.poll_interval)

    def _scan_staging(self):
        """Find unprocessed files in staging that pass mtime stability."""
        if not self.staging_dir.exists():
            return
        now = time.time()
        for staged_path in sorted(self.staging_dir.rglob("*")):
            if not staged_path.is_file():
                continue
            if staged_path in self._processed:
                continue
            try:
                if now - staged_path.stat().st_mtime < self.STABILITY_SECONDS:
                    continue
            except OSError:
                continue
            self._process_file(staged_path)

    # ---- shared processing logic ----

    def _process_file(self, staged_path: Path):
        """Run guardrails and approve/block a single staged file."""
        if staged_path in self._processed or not staged_path.is_file():
            return
        self._processed.add(staged_path)
        rel = _get_file_rel(staged_path, self.staging_dir)

        # Skip hidden files — write feedback explaining why
        if staged_path.name.startswith("."):
            staged_path.unlink(missing_ok=True)
            result = GuardrailResult()
            result.reject(Violation("debris", "Hidden/dot-file written to staging was removed (not allowed)", 0, "low"))
            _write_feedback(self.feedback_dir, rel, result)
            return

        result = _run_guardrails(staged_path, self.staging_dir, self.config)

        if result.allowed:
            _approve(staged_path, self.staging_dir, self.repo_root, self.feedback_dir)
        else:
            _block(staged_path, self.staging_dir, self.repo_root, self.feedback_dir, result)


# ---------------------------------------------------------------------------
# HTTP API server (optional, for agents that prefer REST)
# ---------------------------------------------------------------------------

HTTP_PORT = 9876


class WriteAPIHandler:
    """Simple HTTP request handler for agent file writes."""

    def __init__(self, repo_root: Path, config: DeadpushConfig):
        self.repo_root = repo_root
        self.config = config
        self.staging_dir = repo_root / STAGING_DIR
        self.feedback_dir = repo_root / FEEDBACK_DIR

    def handle_write(self, rel_path: str, content: str) -> dict[str, Any]:
        """Handle a file write request from an agent."""
        staging_path = (self.staging_dir / rel_path).resolve()
        staging_path.parent.mkdir(parents=True, exist_ok=True)
        staging_path.write_text(content, encoding="utf-8")

        result = _run_guardrails(staging_path, self.staging_dir, self.config, self.runtime)

        if result.allowed:
            _approve(staging_path, self.staging_dir, self.repo_root, self.feedback_dir)
        else:
            _block(staging_path, self.staging_dir, self.repo_root, self.feedback_dir, result)
            # Clean up the staging file since it was already moved
            staging_path.unlink(missing_ok=True)

        return result.to_dict()


def _run_http_server(repo_root: Path, config: DeadpushConfig):
    """Run a minimal HTTP server for agent writes."""
    import http.server
    import urllib.parse

    handler = WriteAPIHandler(repo_root, config)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/write":
                self.send_response(404)
                self.end_headers()
                return

            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                rel_path = data.get("path", "")
                content = data.get("content", "")
                if not rel_path:
                    self._json(400, {"error": "path is required"})
                    return
                result = handler.handle_write(rel_path, content)
                self._json(200 if result.get("allowed") else 422, result)
            except Exception as e:
                self._json(500, {"error": str(e)})

        def _json(self, status: int, data: dict):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))

        def log_message(self, fmt, *args):
            pass  # quiet

    server = http.server.HTTPServer(("127.0.0.1", HTTP_PORT), _Handler)
    server.serve_forever()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class InterceptDaemon:
    """Pre-write file interception daemon.

    Watches .deadpush/staging/ for agent writes. Runs guardrails on each file.
    Approves safe files (moves to project root) or blocks dangerous ones
    (quarantines + writes structured feedback).
    """

    def __init__(self, repo_root: str | Path, config: DeadpushConfig | None = None):
        self.repo_root = Path(repo_root).resolve()
        self.config = config or DeadpushConfig(repo_root=self.repo_root)
        self.runtime: RuntimeConfig | None = None
        self.staging_dir = self.repo_root / STAGING_DIR
        self.feedback_dir = self.repo_root / FEEDBACK_DIR
        self.watcher: StagingWatcher | None = None
        self.http_thread: threading.Thread | None = None

    def start(self, http: bool = False):
        """Start the staging watcher (and optionally the HTTP API)."""
        self.staging_dir.mkdir(parents=True, exist_ok=True)

        self.watcher = StagingWatcher(self.repo_root, self.config)
        self.watcher.start()

        if http:
            self.http_thread = threading.Thread(
                target=_run_http_server,
                args=(self.repo_root, self.config),
                daemon=True,
            )
            self.http_thread.start()

    def stop(self):
        """Stop the interception daemon."""
        if self.watcher:
            self.watcher.stop()

    def write_file(self, rel_path: str, content: str) -> GuardrailResult:
        """Write a file through the interception pipeline (bypass staging dir).

        Agents can call this directly for inline writes.
        """
        staging_path = (self.staging_dir / rel_path).resolve()
        staging_path.parent.mkdir(parents=True, exist_ok=True)
        staging_path.write_text(content, encoding="utf-8")

        result = _run_guardrails(staging_path, self.staging_dir, self.config, self.runtime)

        if result.allowed:
            _approve(staging_path, self.staging_dir, self.repo_root, self.feedback_dir)
        else:
            _block(staging_path, self.staging_dir, self.repo_root, self.feedback_dir, result)
            staging_path.unlink(missing_ok=True)

        return result


# ---------------------------------------------------------------------------
# CLI entry point (mirrors guard.run_guardian pattern)
# ---------------------------------------------------------------------------

def run_intercept(daemon: bool = False, http: bool = False):
    """Start the intercept daemon (foreground or daemon mode)."""
    from .config import load_config
    from .guard import DaemonManager, setup_logging

    config = load_config()
    logger = setup_logging(daemon=daemon)

    pid_dir = Path.home() / ".deadpush"
    pid_dir.mkdir(parents=True, exist_ok=True)
    pidfile = pid_dir / "intercept.pid"
    lockfile = pid_dir / "intercept.lock"

    daemon_mgr = DaemonManager(pidfile, lockfile)

    if daemon_mgr.is_running():
        logger.warning("Intercept daemon is already running. Use `deadpush intercept --stop` first.")
        return

    if not daemon_mgr.acquire_lock():
        logger.error("Could not acquire lock. Another instance may be running.")
        return

    staging_dir = config.repo_root / STAGING_DIR
    feedback_dir = config.repo_root / FEEDBACK_DIR

    logger.info("Starting intercept daemon")
    logger.info(f"  Staging:  {staging_dir}")
    logger.info(f"  Feedback: {feedback_dir}")
    logger.info(f"  HTTP API: {'enabled on :9876' if http else 'disabled'}")

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
        except Exception as e:
            logger.error(f"Daemon fork failed: {e}")
            daemon_mgr.cleanup()
            return

    daemon_mgr.write_pid()
    atexit.register(daemon_mgr.cleanup)

    intercept = InterceptDaemon(config.repo_root, config)
    intercept.start(http=http)
    logger.info(f"Intercept daemon ready (PID {os.getpid()})")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        intercept.stop()
        daemon_mgr.cleanup()
        logger.info("Intercept daemon stopped.")
