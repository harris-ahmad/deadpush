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

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import tomllib


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
