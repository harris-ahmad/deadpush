"""
Configuration loading for deadpush.

Supports:
- Auto-detection of repo root (.git, pyproject.toml, etc.)
- Language enablement
- Entrypoint configuration
- Debris blocking/warning rules
- Custom ignore patterns (merged with .gitignore etc.)
- Optional loading from pyproject.toml [tool.deadpush] or .deadpush.toml
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import tomllib
import pathspec


SUPPORTED_LANGUAGES = [
    "python",
    "typescript",
    "javascript",
    "go",
    "rust",
    "cpp",
    "java",
]


@dataclass
class EntrypointsConfig:
    """Configuration for entry point detection."""
    include: list[str] = field(default_factory=list)
    dynamic_patterns: list[str] = field(default_factory=lambda: [
        r"main\b", r"__main__", r"if __name__",
        r"app\.run", r"server\.(start|listen)", r"cli\."
    ])


@dataclass
class DebrisConfig:
    """Rules for debris categories."""
    block_categories: set[str] = field(default_factory=lambda: {
        "hardcoded_secret", "llm_context_file", "chat_export"
    })
    warn_categories: set[str] = field(default_factory=lambda: {
        "vibe_scratchpad", "duplicate_file", "ai_regenerated_duplicate",
        "dev_artifact", "env_file", "silent_failure", "hallucinated_import",
        "weak_test", "no_assertions", "tautology", "empty_test",
        "prompt_injection",
    })


@dataclass
class Config:
    """Main deadpush configuration object passed around the system."""
    repo_root: Path
    languages: list[str] = field(default_factory=lambda: list(SUPPORTED_LANGUAGES))
    entrypoints: EntrypointsConfig = field(default_factory=EntrypointsConfig)
    debris: DebrisConfig = field(default_factory=DebrisConfig)
    ignore_patterns: list[str] = field(default_factory=lambda: [
        "__pycache__/", ".git/", "node_modules/", ".deadpush-archive/",
        ".venv/", "venv/", "dist/", "build/", "*.pyc", ".mypy_cache/",
        "target/", "Cargo.lock", "package-lock.json"
    ])
    max_file_size_mb: int = 5
    control_port: int = 14242
    # Sensitive config files that trigger warnings when modified
    sensitive_config_patterns: list[str] = field(default_factory=lambda: [
        "Dockerfile*", "docker-compose*", ".dockerignore",
        ".github/workflows/*", ".gitlab-ci.yml", "Jenkinsfile*",
        "k8s/*.yaml", "k8s/*.yml", "deploy/*.yaml", "deploy/*.yml",
        "terraform/*.tf", "*.tfvars",
        "cloudbuild.yaml", "app.yaml", "cron.yaml",
        "Procfile", "systemd/*.service", "*.plist",
        "nginx.conf", "nginx/*.conf", ".env.production", ".env.staging",
    ])

    def is_language_enabled(self, name: str) -> bool:
        name = name.lower()
        if name == "ts":
            name = "typescript"
        if name == "js":
            name = "javascript"
        if name == "c++":
            name = "cpp"
        enabled = [l.lower() for l in self.languages]
        return name in enabled or name in [l.split()[0] for l in enabled]

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
        """Build a pathspec for filtering. (lazy import to avoid hard dep at top)"""
        import pathspec
        patterns = list(self.ignore_patterns)
        # Merge .gitignore if present
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_root": str(self.repo_root),
            "languages": self.languages,
            "entrypoints": {
                "include": self.entrypoints.include,
                "dynamic_patterns": self.entrypoints.dynamic_patterns,
            },
        }


def _find_repo_root(start: Path | None = None) -> Path:
    """Walk up to find likely repo root. Robust to deleted cwd (e.g. during tests or rm -rf while in dir)."""
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

    # Try pyproject.toml [tool.deadpush]
    pyproj = root / "pyproject.toml"
    if pyproj.exists():
        try:
            data = tomllib.loads(pyproj.read_text(encoding="utf-8"))
            tool = data.get("tool", {}).get("deadpush", {})
            if "languages" in tool:
                cfg.languages = [str(x) for x in tool["languages"]]
            if "entrypoints" in tool:
                ep = tool["entrypoints"]
                if "include" in ep:
                    cfg.entrypoints.include = list(ep["include"])
                if "dynamic_patterns" in ep:
                    cfg.entrypoints.dynamic_patterns = list(ep["dynamic_patterns"])
            if "ignore" in tool:
                cfg.ignore_patterns.extend(tool["ignore"])
            if "max_file_size_mb" in tool:
                cfg.max_file_size_mb = int(tool["max_file_size_mb"])
            if "control_port" in tool:
                cfg.control_port = int(tool["control_port"])
        except Exception:
            pass  # ignore bad toml, use defaults

    # .deadpush.toml override (simple)
    dpt = root / ".deadpush.toml"
    if dpt.exists():
        try:
            data = tomllib.loads(dpt.read_text(encoding="utf-8"))
            if "languages" in data:
                cfg.languages = [str(x) for x in data["languages"]]
            # ... other keys could be merged
        except Exception:
            pass

    # Env var overrides for quick use
    if os.environ.get("DEADPUSH_LANGUAGES"):
        cfg.languages = [x.strip() for x in os.environ["DEADPUSH_LANGUAGES"].split(",") if x.strip()]

    return cfg


# Convenience for tests / direct use
def get_default_languages() -> list[str]:
    return list(SUPPORTED_LANGUAGES)
