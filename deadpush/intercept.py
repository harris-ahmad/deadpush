"""
Guardrail checkers and enforcement kernel for deadpush.

The watchdog-based guardian (not staging) is the primary intercept mechanism.
This module provides the guardrail checkers, the enforcement content pipeline,
and InterceptDaemon.write_file() for MCP agents that want sync feedback.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import Config as DeadpushConfig
from .rules import RuntimeConfig


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
    global _LEARNED_PATTERNS
    if _LEARNED_PATTERNS is not None:
        return _LEARNED_PATTERNS
    from .config import policy_dir
    path = policy_dir(repo_root) / "learned_patterns.json"
    if path.exists():
        try:
            _LEARNED_PATTERNS = json.loads(path.read_text(encoding="utf-8"))
            return _LEARNED_PATTERNS
        except Exception:
            pass
    _LEARNED_PATTERNS = {"patterns": [], "suppressed_categories": {}}
    return _LEARNED_PATTERNS


def _save_learned_patterns(repo_root: Path) -> None:
    global _LEARNED_PATTERNS
    if _LEARNED_PATTERNS is None:
        return
    from .config import policy_dir
    path = policy_dir(repo_root) / "learned_patterns.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_LEARNED_PATTERNS, indent=2), encoding="utf-8")
    except OSError:
        # In hardened mode the policy dir is root-owned; a same-UID write is
        # denied by design (suppressions must go through the privileged path).
        pass


def _is_suppressed(category: str, description: str, repo_root: Path) -> bool:
    learned = _load_learned_patterns(repo_root)
    for entry in learned.get("patterns", []):
        if entry.get("category") != category:
            continue
        if entry.get("pattern") and entry["pattern"] in description:
            return True
    return False


def _learn_false_positive(category: str, pattern: str, reason: str, repo_root: Path) -> None:
    learned = _load_learned_patterns(repo_root)
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
    """A single guardrail violation found in a file."""

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
    """Result of checking a file against all guardrails."""

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


# ---------------------------------------------------------------------------
# Sensitive write checker
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Destructive change checker
# ---------------------------------------------------------------------------

def _check_destructive_changes(
    source: str, rel_path: str, repo_root: Path,
    runtime: RuntimeConfig | None = None,
    _old_source: str | None = None,
) -> list[Violation]:
    """Check if the write would destroy existing content (near-empty rewrites, massive deletions)."""
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

    if len(old_lines) > 20 and len(new_lines) < 3:
        violations.append(Violation(
            "destructive",
            f"Replacing {len(old_lines)}-line file with {len(new_lines)} lines — potential content deletion",
            0, "high" if level == "block" else "medium"
        ))

    if old_lines and len(new_lines) < len(old_lines) * 0.5 and len(old_lines) > 10:
        violations.append(Violation(
            "destructive",
            f"Writing {len(new_lines)} lines to replace {len(old_lines)} lines — >50% reduction",
            0, "medium"
        ))

    return violations


# ---------------------------------------------------------------------------
# Full guardrail check pipeline
# ---------------------------------------------------------------------------

def _apply_guardrail_level(result: GuardrailResult, violations: list[Violation], runtime: RuntimeConfig | None, category: str) -> None:
    level = runtime.get_guardrail_level(category) if runtime else "block"
    if level == "block":
        for v in violations:
            result.reject(v)
    else:
        result.violations.extend(violations)


_ENFORCEABLE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".go", ".java", ".rb", ".php",
    ".sh", ".bash", ".yaml", ".yml", ".json", ".toml", ".md",
})


def enforce_content(
    rel_path: str,
    source: str,
    config: DeadpushConfig,
    runtime: RuntimeConfig | None = None,
    *,
    old_source: str | None = None,
) -> GuardrailResult:
    """Unified enforcement kernel for MCP, guardian, and git hooks."""
    result = GuardrailResult()
    rel = rel_path.replace("\\", "/")

    if config.is_blocked(rel):
        result.reject(Violation("blocked_file", f"File {rel} is blocked by config", 0, "critical"))
        return result

    from .debris import LLM_CONTEXT_FILES

    name_lower = Path(rel).name.lower()
    if name_lower in LLM_CONTEXT_FILES:
        result.reject(Violation(
            "debris",
            f"Known LLM/AI coding assistant context file: {Path(rel).name}",
            0,
            "critical",
        ))
        return result

    suffix = Path(rel).suffix.lower()

    learned = _load_learned_patterns(config.repo_root)
    suppressed_desc: set[str] = set()
    for entry in learned.get("patterns", []):
        if entry.get("pattern"):
            suppressed_desc.add(entry["pattern"])

    _apply_guardrail_level(result, _check_prompt_injection(source, runtime), runtime, "prompt_injection")
    _apply_guardrail_level(result, _check_hardcoded_secrets(source, runtime, rel_path=rel), runtime, "secret")
    _apply_guardrail_level(result, _check_security(source, runtime, rel_path=rel), runtime, "security")

    result.violations = [v for v in result.violations if v.description not in suppressed_desc]

    _apply_guardrail_level(result, _check_sensitive_write(source, rel, config, runtime), runtime, "sensitive")
    destructive_level = runtime.get_guardrail_level("destructive") if runtime else "warn"
    for v in _check_destructive_changes(source, rel, config.repo_root, runtime, _old_source=old_source):
        if destructive_level == "block":
            result.reject(v)
        else:
            result.violations.append(v)

    _apply_guardrail_level(result, _check_debris_patterns(source, suffix, runtime), runtime, "debris")
    _apply_guardrail_level(result, _check_layer_violations(source, rel, config, runtime), runtime, "layer")
    _apply_guardrail_level(result, _check_dependency_integrity(source, rel, config.repo_root, runtime), runtime, "dependency")

    return result


def violations_from_result(rel_path: str, result: GuardrailResult) -> list[dict[str, Any]]:
    if result.allowed:
        return []
    return [
        {
            "file": rel_path,
            "line": v.line,
            "category": v.category,
            "description": v.description,
            "severity": v.severity,
        }
        for v in result.violations
    ]


def _run_guardrails(
    path: Path,
    repo_root: Path,
    config: DeadpushConfig,
    runtime: RuntimeConfig | None = None,
    *,
    old_source: str | None = None,
    rel_path_override: str | None = None,
) -> GuardrailResult:
    """Run all guardrail checks on a file.

    Args:
        path: Path to the file to check.
        repo_root: Repository root directory (for computing relative path).
        config: Deadpush configuration.
        runtime: Optional runtime config for level overrides.
        old_source: Optional pre-write content (for diff computation).
        rel_path_override: Optional explicit relative path.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        result = GuardrailResult()
        result.reject(Violation("internal", "Could not read file", 0, "high"))
        return result

    if rel_path_override is not None:
        rel = rel_path_override
    else:
        try:
            rel = path.relative_to(repo_root).as_posix()
        except ValueError:
            result = GuardrailResult()
            result.reject(Violation("security", f"Path traversal blocked: {path}", 0, "critical"))
            return result
    result = enforce_content(rel, source, config, runtime, old_source=old_source)

    if old_source is not None:
        result.diff = "".join(difflib.unified_diff(
            old_source.splitlines(keepends=True),
            source.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        ))
    else:
        try:
            dest = repo_root / rel
            old = dest.read_text(encoding="utf-8", errors="ignore") if dest.exists() else ""
            result.diff = "".join(difflib.unified_diff(
                old.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
            ))
        except Exception:
            result.diff = ""

    return result


# ---------------------------------------------------------------------------
# Feedback writer
# ---------------------------------------------------------------------------

def _write_feedback(feedback_dir: Path, rel_path: str, result: GuardrailResult) -> Path | None:
    """Write structured feedback so the agent can self-correct."""
    safe_name = rel_path.replace("/", "__").replace("\\", "__")
    feedback_dir.mkdir(parents=True, exist_ok=True)

    status = "blocked" if not result.allowed else "approved"
    feedback = {
        "file": rel_path,
        "status": status,
        "violations": [v.to_dict() for v in result.violations],
        "diff": result.diff,
        "timestamp": datetime.now().isoformat(),
        "acknowledged": False,
    }

    json_path = feedback_dir / f"{safe_name}.json"
    json_path.write_text(json.dumps(feedback, indent=2), encoding="utf-8")

    md_path = feedback_dir / f"{safe_name}.md"
    md_content = _format_feedback_md(feedback)
    md_path.write_text(md_content, encoding="utf-8")

    return json_path


def _format_feedback_md(feedback: dict[str, Any]) -> str:
    """Format feedback as markdown for agent consumption."""
    lines = [
        "# deadpush Guardrail Feedback",
        "",
        f"- **File**: `{feedback.get('file', 'unknown')}`",
        f"- **Status**: {feedback['status']}",
        f"- **Time**: {feedback.get('timestamp', 'unknown')}",
        "",
    ]
    if feedback.get("violations"):
        lines.append("## Violations")
        lines.append("")
        for v in feedback["violations"]:
            lines.append(f"- **{v['category']}** (line {v.get('line', '?')}, {v.get('severity', '?')}): {v['description']}")
        lines.append("")
    if feedback.get("diff"):
        lines.append("## Diff")
        lines.append("")
        lines.append("```diff")
        lines.append(feedback["diff"])
        lines.append("```")
        lines.append("")
    lines.append("---")
    lines.append("*To acknowledge this feedback, call `acknowledge_feedback` with the safe filename.*")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# InterceptDaemon — public API for MCP agents needing sync feedback
# ---------------------------------------------------------------------------

class InterceptDaemon:
    """File interception daemon for MCP agents that want sync guardrail feedback.

    write_file() writes directly to the real path and runs guardrails.
    If violations block the write, the file is quarantined and restored from git.
    The watchdog-based guardian provides the same enforcement for all other writes.
    """

    def __init__(self, repo_root: str | Path, config: DeadpushConfig | None = None):
        self.repo_root = Path(repo_root).resolve()
        self.config = config or DeadpushConfig(repo_root=self.repo_root)
        self.runtime: RuntimeConfig | None = None

    def write_file(self, rel_path: str, content: str) -> GuardrailResult:
        """Write a file directly and run guardrails. Returns sync feedback.

        If violations block the write, the file is quarantined and restored
        from git (or deleted if new). The watchdog guardian covers all other writes.
        """
        dest = (self.repo_root / rel_path).resolve()
        # Reject path traversal
        try:
            dest.relative_to(self.repo_root)
        except ValueError:
            result = GuardrailResult()
            result.reject(Violation("security", f"Path traversal blocked: {rel_path}", 0, "critical"))
            return result

        old_source = dest.read_text(encoding="utf-8", errors="ignore") if dest.exists() else ""
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

        result = _run_guardrails(dest, self.repo_root, self.config, self.runtime, old_source=old_source)

        if not result.allowed:
            self._quarantine_and_restore(dest, rel_path, result)
            _write_feedback(self.repo_root / FEEDBACK_DIR, rel_path, result)

        return result

    def _quarantine_and_restore(self, dest: Path, rel_path: str, result: GuardrailResult):
        """Move file to quarantine and restore from git if available."""
        quarantine_dir = self.repo_root / QUARANTINE_DIR
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        safe_name = rel_path.replace("/", "__").replace("\\", "__")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantined = quarantine_dir / f"{timestamp}_{safe_name}"

        if dest.exists():
            shutil.move(str(dest), str(quarantined))

        reason = result.violations[0].description if result.violations else "guardrail violation"
        (quarantined.with_name(quarantined.name + ".reason")).write_text(
            f"Quarantined at {datetime.now()}\n"
            f"Reason: {reason}\n"
            f"Original path: {dest}\n"
        )

        try:
            git_show = subprocess.run(
                ["git", "show", f"HEAD:{rel_path}"],
                capture_output=True, text=True,
                cwd=str(self.repo_root),
            )
            if git_show.returncode == 0 and git_show.stdout:
                dest.write_text(git_show.stdout, encoding="utf-8")
        except Exception:
            pass
