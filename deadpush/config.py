"""
Configuration loading for deadpush guardian.

Supports:
- Auto-detection of repo root (.git, pyproject.toml, etc.)
- Debris blocking/warning rules
- Blocked file patterns (LLM context files, etc.)
- Custom ignore patterns (merged with .gitignore etc.)
- Optional loading from pyproject.toml [tool.deadpush] or deadpush.toml
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pathspec


@dataclass
class DebrisConfig:
    """Rules for guardian debris categories."""
    block_categories: set[str] = field(default_factory=lambda: {
        "hardcoded_secret", "llm_context_file", "chat_export",
    })
    warn_categories: set[str] = field(default_factory=lambda: {
        "vibe_scratchpad", "prompt_injection",
    })


@dataclass
class TestConfig:
    """Configuration for post-write test verification."""
    command: str = "pytest"
    timeout_seconds: int = 30
    enabled: bool = True


@dataclass
class BlockConfig:
    """Files/patterns that should always be blocked from writes."""
    blocked_files: list[str] = field(default_factory=lambda: [
        "claude.md",
        ".cursorrules",
        ".claude_instructions",
        ".copilot-instructions.md",
        "windsurf_rules.md",
        "agents.md",
    ])
    blocked_patterns: list[str] = field(default_factory=list)


def _load_deadpush_toml(root: Path) -> dict[str, Any]:
    """Load .deadpush.toml from project root. Returns {} if missing."""
    dp_paths = [
        root / "deadpush.toml",
        root / ".deadpush.toml",
        root / ".deadpush" / "config.toml",
    ]
    for dp in dp_paths:
        if dp.exists():
            try:
                return tomllib.loads(dp.read_text(encoding="utf-8"))
            except Exception:
                return {}
    return {}


@dataclass
class Config:
    """Main deadpush configuration object passed around the system."""
    repo_root: Path
    debris: DebrisConfig = field(default_factory=DebrisConfig)
    test: TestConfig = field(default_factory=TestConfig)
    block: BlockConfig = field(default_factory=BlockConfig)
    ignore_patterns: list[str] = field(default_factory=lambda: [
        "__pycache__/", ".git/", "node_modules/", ".deadpush-archive/",
        ".venv/", "venv/", "dist/", "build/", "*.pyc", ".mypy_cache/",
        "target/", "Cargo.lock", "package-lock.json",
        ".deadpush-quarantine/", ".deadpush/",
    ])
    max_file_size_mb: int = 5
    control_port: int = 14242
    sensitive_config_patterns: list[str] = field(default_factory=lambda: [
        "Dockerfile*", "docker-compose*", ".dockerignore",
        ".github/workflows/*", ".gitlab-ci.yml", "Jenkinsfile*",
        "k8s/*.yaml", "k8s/*.yml", "deploy/*.yaml", "deploy/*.yml",
        "terraform/*.tf", "*.tfvars",
        "cloudbuild.yaml", "app.yaml", "cron.yaml",
        "Procfile", "systemd/*.service", "*.plist",
        "nginx.conf", "nginx/*.conf", ".env.production", ".env.staging",
    ])

    def should_block_debris_category(self, category: str) -> bool:
        return category in self.debris.block_categories

    def should_warn_debris_category(self, category: str) -> bool:
        return category in self.debris.warn_categories

    def is_sensitive_config(self, rel_path: str) -> bool:
        """Check if a relative file path matches a sensitive config pattern."""
        from fnmatch import fnmatch
        rp = rel_path.replace("\\", "/")
        for pat in self.sensitive_config_patterns:
            if fnmatch(rp, pat) or fnmatch(rp, "**/" + pat):
                return True
        return False

    def get_effective_ignore_spec(self) -> "pathspec.PathSpec":
        """Build a pathspec for filtering."""
        import pathspec
        patterns = list(self.ignore_patterns)
        gi = self.repo_root / ".gitignore"
        if gi.exists():
            try:
                for line in gi.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
            except Exception:
                pass
        return pathspec.PathSpec.from_lines("gitwildmatch", patterns)

    def is_blocked(self, rel_path: str) -> bool:
        """Check if a relative file path matches any blocked file/pattern."""
        rp = rel_path.replace("\\", "/")
        name = Path(rp).name
        if name.lower() in (b.lower() for b in self.block.blocked_files):
            return True
        from fnmatch import fnmatch
        for pat in self.block.blocked_patterns:
            pat_lower = pat.lower()
            if fnmatch(rp.lower(), pat_lower) or fnmatch(name.lower(), pat_lower):
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_root": str(self.repo_root),
            "block": {
                "blocked_files": self.block.blocked_files,
                "blocked_patterns": self.block.blocked_patterns,
            },
        }


INSTALL_MARKER_REL = ".deadpush/installed"


def install_marker_path(repo_root: Path) -> Path:
    """Path to the local marker recording that this repo was protected.

    The presence of this file is what lets git hooks *fail closed* when the
    deadpush interpreter later goes missing (deleted venv, moved install):
    a protected repo must refuse the operation rather than silently allow it.
    The file is intentionally machine-local (records an absolute interpreter
    path) and is added to .gitignore so it is never committed.
    """
    return repo_root / ".deadpush" / "installed"


def write_install_marker(repo_root: Path, *, hardened: bool = False) -> Path:
    """Record that this repo is protected, pinning the interpreter to use.

    Returns the marker path. Best-effort ignore-list maintenance ensures the
    marker (which contains a machine-specific interpreter path) is not
    accidentally committed.
    """
    import json
    import sys
    import time

    marker = install_marker_path(repo_root)
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": _package_version(),
        "python": sys.executable,
        "mode": "hardened" if hardened else "default",
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "platform": sys.platform,
    }
    marker.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _ensure_gitignored(repo_root, INSTALL_MARKER_REL)
    return marker


def read_install_marker(repo_root: Path) -> dict[str, Any] | None:
    """Return the parsed install marker, or None if the repo isn't protected."""
    import json

    marker = install_marker_path(repo_root)
    if not marker.exists():
        return None
    try:
        return json.loads(marker.read_text(encoding="utf-8"))
    except Exception:
        # A present-but-unreadable marker still means "this repo was protected".
        return {}


def remove_install_marker(repo_root: Path) -> None:
    """Remove the protection marker (used by `uninstall`)."""
    try:
        install_marker_path(repo_root).unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Hardened-mode policy locations (root/_deadpush-owned, tamper-resistant).
#
# In soft mode the guardrail *policy* an agent could weaken (rules.json,
# learned_patterns.json) and the fail-closed marker live in the in-repo
# `.deadpush/` directory — writable by the same-UID agent (soft mode is
# deterrence, not a hard boundary). In hardened mode they must live somewhere
# the agent cannot write. They are stored under a root/_deadpush-owned tree
# that the user can *traverse and read* but not modify, so user-run git hooks
# still read the authoritative policy while the agent cannot tamper with it.
# ---------------------------------------------------------------------------

HARDENED_STATE_DIR = Path("/var/db/deadpush")
HARDENED_POLICY_ROOT = HARDENED_STATE_DIR / "policy"
HARDENED_VENV_DIR = HARDENED_STATE_DIR / "venv"


def hardened_python() -> Path:
    """Path to the root/_deadpush-owned interpreter used by hardened hooks.

    Hardened git hooks execute this interpreter (and thus the root-owned
    deadpush package inside the venv) rather than the user's interpreter, so a
    same-UID agent cannot neuter enforcement by editing a user-writable package.
    """
    return HARDENED_VENV_DIR / "bin" / "python"


def repo_id(repo_root: Path | str) -> str:
    """Stable 12-char id for a repo path (matches the guardian's scoping)."""
    return hashlib.sha256(str(repo_root).encode()).hexdigest()[:12]


def hardened_policy_dir(repo_root: Path) -> Path:
    """Root-owned per-repo policy directory used in hardened mode."""
    return HARDENED_POLICY_ROOT / repo_id(repo_root)


def hardened_install_marker(repo_root: Path) -> Path:
    """Root-owned marker whose presence means 'this repo is a hardened install'."""
    return hardened_policy_dir(repo_root) / "installed"


def is_hardened_install(repo_root: Path) -> bool:
    """True when a trustworthy (root-owned) hardened marker exists for this repo.

    The marker lives under a root/_deadpush-owned tree that a same-UID agent
    can neither create (can't forge a hardened install) nor delete (can't
    downgrade enforcement), so its presence is authoritative.
    """
    try:
        return hardened_install_marker(repo_root).exists()
    except Exception:
        return False


def policy_dir(repo_root: Path) -> Path:
    """Authoritative directory for runtime policy files (rules/learned patterns).

    Hardened installs read policy from the root-owned tree so a same-UID agent
    cannot weaken enforcement by editing in-repo `.deadpush/` files. Soft
    installs (and anything not hardened) use the in-repo `.deadpush/` directory
    exactly as before, so soft-mode behavior is unchanged.
    """
    if is_hardened_install(repo_root):
        return hardened_policy_dir(repo_root)
    return repo_root / ".deadpush"


def _package_version() -> str:
    try:
        from . import __version__

        return __version__
    except Exception:
        return "unknown"


def _ensure_gitignored(repo_root: Path, rel_pattern: str) -> None:
    """Idempotently ensure `rel_pattern` is present in the repo's .gitignore."""
    gitignore = repo_root / ".gitignore"
    try:
        existing = ""
        if gitignore.exists():
            existing = gitignore.read_text(encoding="utf-8")
            lines = {line.strip() for line in existing.splitlines()}
            if rel_pattern in lines:
                return
        prefix = "" if (not existing or existing.endswith("\n")) else "\n"
        with gitignore.open("a", encoding="utf-8") as f:
            f.write(f"{prefix}{rel_pattern}\n")
    except Exception:
        pass


def is_guardian_dev_repo(repo_root: Path) -> bool:
    """True when repo is the deadpush package source tree (not a consumer project)."""
    if not (repo_root / "deadpush" / "__init__.py").is_file():
        return False
    pyproj = repo_root / "pyproject.toml"
    if not pyproj.is_file():
        return False
    try:
        data = tomllib.loads(pyproj.read_text(encoding="utf-8"))
        return data.get("project", {}).get("name") == "deadpush"
    except Exception:
        return True


_DEV_REPO_HINT = (
    "Test in a throwaway clone instead:\n"
    "  git clone . /tmp/deadpush-e2e && cd /tmp/deadpush-e2e && deadpush protect\n"
    "Or pass --allow-self-protect to override (not recommended)."
)


def dev_repo_guard_refusal(
    repo_root: Path,
    *,
    allow_self_protect: bool = False,
    persistent: bool = False,
    full_setup: bool = False,
) -> str | None:
    """Return a user-facing refusal message, or None if the operation is allowed.

    * ``full_setup`` — block ``protect`` / ``init`` (hooks + optional daemon).
    * ``persistent`` — block ``guard --daemon``, ``guard --hardened``, etc.
    Foreground ``deadpush guard`` (no daemon) is still allowed for local testing.
    """
    if allow_self_protect or not is_guardian_dev_repo(repo_root):
        return None
    if full_setup:
        return (
            "Refusing to protect the deadpush development repository.\n"
            "Running protect/init here installs git hooks and a filesystem guardian that "
            "will block your own commits and quarantine source files.\n"
            + _DEV_REPO_HINT
        )
    if persistent:
        return (
            "Refusing to start a persistent guardian on the deadpush development repository.\n"
            "A background daemon (or hardened guardian) here will fight your own edits, "
            "survive terminal close, and pollute ~/.deadpush with dev-repo state.\n"
            + _DEV_REPO_HINT
        )
    return None


def _find_repo_root(start: Path | None = None) -> Path:
    """Walk up to find likely repo root."""
    if start is None:
        try:
            start = Path.cwd()
        except FileNotFoundError:
            start = Path.home()
    p = start.resolve()
    markers = {".git", "pyproject.toml", "package.json", "Cargo.toml", "go.mod", ".deadpush"}
    while True:
        if any((p / m).exists() for m in markers):
            return p
        if p.parent == p:
            return start.resolve()
        p = p.parent


def load_config(explicit_root: Path | None = None) -> Config:
    """Load config, merging file-based overrides if present."""
    root = explicit_root or _find_repo_root()
    cfg = Config(repo_root=root)

    pyproj = root / "pyproject.toml"
    if pyproj.exists():
        try:
            data = tomllib.loads(pyproj.read_text(encoding="utf-8"))
            tool = data.get("tool", {}).get("deadpush", {})
            if "ignore" in tool:
                cfg.ignore_patterns.extend(tool["ignore"])
            if "max_file_size_mb" in tool:
                cfg.max_file_size_mb = int(tool["max_file_size_mb"])
            if "control_port" in tool:
                cfg.control_port = int(tool["control_port"])
            block_data = tool.get("block", {})
            if "blocked_files" in block_data:
                cfg.block.blocked_files = list(block_data["blocked_files"])
            if "blocked_patterns" in block_data:
                cfg.block.blocked_patterns = list(block_data["blocked_patterns"])
        except Exception:
            pass

    dpt_data = _load_deadpush_toml(root)
    if dpt_data:
        block_data = dpt_data.get("block", {})
        if "blocked_files" in block_data:
            cfg.block.blocked_files = list(block_data["blocked_files"])
        if "blocked_patterns" in block_data:
            cfg.block.blocked_patterns = list(block_data["blocked_patterns"])
        test_data = dpt_data.get("tests", {})
        if "command" in test_data:
            cfg.test.command = str(test_data["command"])
        if "timeout_seconds" in test_data:
            cfg.test.timeout_seconds = int(test_data["timeout_seconds"])
        if "enabled" in test_data:
            cfg.test.enabled = bool(test_data["enabled"])

    return cfg
