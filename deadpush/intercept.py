"""
Guardrail checkers and enforcement kernel for deadpush.

The watchdog-based guardian (not staging) is the primary intercept mechanism.
This module provides the guardrail checkers, the enforcement content pipeline,
and InterceptDaemon.write_file() for MCP agents that want sync feedback.
"""

from __future__ import annotations

import difflib
import json
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

_LEARNED_PATTERNS: dict[str, list[dict[str, Any]]] | None = None


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
        pass


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
# Full guardrail check pipeline
# ---------------------------------------------------------------------------

_ENFORCEABLE_EXTENSIONS = frozenset({
    # Scripting / application code
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".rb", ".php", ".pl", ".pm", ".lua", ".r", ".dart", ".go", ".rs", ".java",
    ".kt", ".kts", ".scala", ".groovy", ".clj", ".cljs", ".ex", ".exs", ".erl",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".m", ".mm", ".cs", ".swift",
    # Shells / automation
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd",
    ".mk", ".cmake", ".gradle", ".sql", ".graphql", ".proto",
    # Config / infra as code (prime spots for injected commands & secrets)
    ".yaml", ".yml", ".json", ".json5", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".properties", ".xml", ".plist", ".tf", ".tfvars", ".hcl", ".nix", ".dockerfile",
    ".service", ".env",
    # Docs / text (prompt injection, exfil instructions, pasted secrets)
    ".md", ".markdown", ".mdx", ".rst", ".txt",
    # Credential-bearing text formats (detect a committed key/cert)
    ".pem", ".crt", ".cer", ".key", ".pub", ".asc",
})

# Binary / non-text formats: never worth reading for content checks, and can be
# large. Excluded even if some odd extension collision would otherwise match.
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".ogg", ".webm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".jar",
    ".pyc", ".pyo", ".wasm", ".node",
    ".p12", ".pfx", ".jks", ".keystore",  # binary keystores
    ".db", ".sqlite", ".sqlite3", ".mo", ".dat",
})

# Sensitive files that carry no extension (or a misleading one). Matched on the
# lowercased basename so hooks scan them the same way the daemon already does.
_ENFORCEABLE_NAMES = frozenset({
    "dockerfile", "containerfile", "makefile", "gnumakefile", "jenkinsfile",
    "vagrantfile", "gemfile", "rakefile", "procfile", "brewfile", "justfile",
    "taskfile", "cmakelists.txt", "berksfile", "guardfile", "capfile",
    ".gitignore", ".gitattributes", ".gitmodules", ".dockerignore",
    ".npmrc", ".yarnrc", ".nvmrc", ".ruby-version", ".python-version",
    ".bashrc", ".zshrc", ".bash_profile", ".bash_aliases", ".profile",
    ".netrc", ".pypirc", ".condarc", ".curlrc", ".wgetrc",
    ".gitconfig", ".terraformrc", ".htaccess", ".editorconfig",
})

# deadpush's own state dirs (and git internals): never content-scan these.
_DEADPUSH_OWN_DIRS = frozenset({
    ".git", ".deadpush", ".deadpush-quarantine", ".deadpush-archive",
    ".deadpush-config-backups", ".guardian",
})


def is_enforceable_path(rel_path: str) -> bool:
    """Whether a path should be content-scanned by the git hooks.

    The watchdog daemon already scans every write; this mirrors that coverage on
    the git-hook side, which previously gated purely on a small extension set and
    so silently skipped extensionless/config files an agent can abuse (Dockerfile,
    Makefile, .env, .npmrc, CI shell configs, and LLM-context files like
    .cursorrules / .claude_instructions). Binary formats are always excluded.
    """
    name = Path(rel_path).name
    lower = name.lower()
    suffix = Path(rel_path).suffix.lower()

    # Never scan deadpush's own bookkeeping (feedback records quote the very secrets
    # deadpush caught) or the git internals — scanning them produces self-referential
    # violations and lets `git add -A` weaponize deadpush's own logs.
    parts = {p for p in Path(rel_path).parts}
    if parts & _DEADPUSH_OWN_DIRS:
        return False

    if suffix in _BINARY_EXTENSIONS:
        return False
    if suffix in _ENFORCEABLE_EXTENSIONS:
        return True
    if lower in _ENFORCEABLE_NAMES:
        return True
    # `.env`, `.env.local`, `.env.production`, ... and Dockerfile variants
    # (`Dockerfile.prod`, `app.dockerfile`).
    if lower.startswith(".env") or lower.startswith("dockerfile") or lower.endswith(".dockerfile"):
        return True
    # Known LLM/AI-assistant context files (many are extensionless).
    from .debris import LLM_CONTEXT_FILES
    if lower in LLM_CONTEXT_FILES:
        return True
    return False


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

    from .bootstrap import is_bootstrap_path

    bootstrap = is_bootstrap_path(rel, config.repo_root)

    if not bootstrap and config.is_blocked(rel):
        result.reject(Violation("blocked_file", f"File {rel} is blocked by config", 0, "critical"))
        return result

    from .debris import LLM_CONTEXT_FILES

    name_lower = Path(rel).name.lower()
    if not bootstrap and name_lower in LLM_CONTEXT_FILES:
        result.reject(Violation(
            "debris",
            f"Known LLM/AI coding assistant context file: {Path(rel).name}",
            0,
            "critical",
        ))
        return result

    from .plugins import run_plugins
    plugin_violations = run_plugins(rel, source, config, runtime)
    for v in plugin_violations:
        cat = v.category or "plugin"
        level = runtime.get_guardrail_level(cat) if runtime else "block"
        if level == "block":
            result.reject(v)
        elif level == "warn":
            result.violations.append(v)

    reachability_level = runtime.get_guardrail_level("reachability") if runtime else "warn"
    if reachability_level != "off":
        try:
            from .reachability import check_reachability, violations_from_reachability
            reach_violations = check_reachability(rel, source, config)
            if reach_violations:
                for rv in reach_violations:
                    desc = f"Transitive reachability: {rv.file} reaches {rv.sensitive_op.category} via {rv.path}"
                    v = Violation("reachability", desc, rv.sensitive_op.line, "medium")
                    if reachability_level == "block":
                        result.reject(v)
                    else:
                        result.violations.append(v)
        except Exception:
            pass

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
