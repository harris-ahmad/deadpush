"""
Runtime configuration for deadpush — agent-configurable rules.

Agents can modify guardrail behavior at runtime via MCP tools.
Changes persist in .deadpush/rules.json and survive server restarts.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from .config import policy_dir


RULES_FILE = ".deadpush/rules.json"

GUARDRAIL_LEVELS = ["off", "warn", "block"]

DEFAULT_RULES: dict[str, Any] = {
    "allowed_patterns": [],
    "ignored_paths": [],
    "guardrail_levels": {
        "prompt_injection": "block",
        "secret": "block",
        "security": "block",
        "layer": "block",
        "sensitive": "block",
        "destructive": "warn",
        "debris": "warn",
        "dependency": "warn",
        "reachability": "warn",
    },
}


class RuntimeConfig:
    """Persistent runtime configuration for agent-customizable guardrails.

    Stored in .deadpush/rules.json. Survives server restarts.
    Merged with base config (pyproject.toml) at load time.
    """

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        # Hardened installs read/write policy from a root-owned dir the agent
        # cannot modify; soft installs use the in-repo `.deadpush/` as before.
        self.rules_path = policy_dir(repo_root) / "rules.json"
        self._data: dict[str, Any] = {}
        self._compiled: list[tuple[re.Pattern, str]] = []  # (compiled_regex, description)
        self._load()

    @classmethod
    def from_dict(cls, repo_root: Path, data: dict[str, Any]) -> RuntimeConfig:
        """Create a RuntimeConfig from a dict without file I/O (primarily for tests)."""
        rc = cls.__new__(cls)
        rc.repo_root = repo_root
        rc.rules_path = policy_dir(repo_root) / "rules.json"
        rc._data = copy.deepcopy(data)
        rc._merge_defaults()
        rc._rebuild_cache()
        return rc

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self):
        if self.rules_path.exists():
            try:
                self._data = json.loads(self.rules_path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}
        self._merge_defaults()
        self._rebuild_cache()

    def _save(self):
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        self.rules_path.write_text(json.dumps(self._data, indent=2, default=str), encoding="utf-8")

    def _merge_defaults(self):
        defaults = copy.deepcopy(DEFAULT_RULES)
        for key, default_val in defaults.items():
            if key not in self._data:
                self._data[key] = default_val
            elif isinstance(default_val, dict):
                for subkey, subval in default_val.items():
                    if subkey not in self._data[key]:
                        self._data[key][subkey] = subval

    def _rebuild_cache(self):
        self._compiled = []
        for entry in self._data.get("allowed_patterns", []):
            pattern = entry.get("pattern", "")
            desc = entry.get("description", "")
            try:
                self._compiled.append((re.compile(pattern), desc))
            except re.error:
                pass

    # ------------------------------------------------------------------
    # Allowlist — patterns to skip during guardrail checks
    # ------------------------------------------------------------------
    def is_allowed(self, matched_text: str) -> bool:
        """Check if a matched pattern is in the allowlist."""
        for compiled_re, _ in self._compiled:
            if compiled_re.search(matched_text):
                return True
        return False

    def add_allowed_pattern(self, pattern: str, description: str = "") -> None:
        """Add a regex pattern to the allowlist."""
        # Validate the regex
        re.compile(pattern)
        patterns = self._data.setdefault("allowed_patterns", [])
        # Avoid duplicates
        for entry in patterns:
            if entry.get("pattern") == pattern:
                entry["description"] = description
                self._rebuild_cache()
                self._save()
                return
        patterns.append({"pattern": pattern, "description": description})
        self._rebuild_cache()
        self._save()

    def remove_allowed_pattern(self, pattern: str) -> bool:
        """Remove a pattern from the allowlist. Returns True if found."""
        patterns = self._data.get("allowed_patterns", [])
        before = len(patterns)
        self._data["allowed_patterns"] = [p for p in patterns if p.get("pattern") != pattern]
        if len(self._data["allowed_patterns"]) != before:
            self._rebuild_cache()
            self._save()
            return True
        return False

    # ------------------------------------------------------------------
    # Path ignore list
    # ------------------------------------------------------------------
    def is_path_ignored(self, rel_path: str) -> bool:
        """Check if a relative path is in the ignore list."""
        ignored = self._data.get("ignored_paths", [])
        for ign in ignored:
            if ign.endswith("*") and rel_path.startswith(ign.rstrip("*")):
                return True
            if rel_path == ign:
                return True
        return False

    def ignore_path(self, rel_path: str) -> None:
        """Add a path to the ignore list."""
        ignored = self._data.setdefault("ignored_paths", [])
        if rel_path not in ignored:
            ignored.append(rel_path)
            self._save()

    def remove_ignored_path(self, rel_path: str) -> bool:
        """Remove a path from the ignore list."""
        ignored = self._data.get("ignored_paths", [])
        if rel_path in ignored:
            self._data["ignored_paths"] = [p for p in ignored if p != rel_path]
            self._save()
            return True
        return False

    # ------------------------------------------------------------------
    # Guardrail levels
    # ------------------------------------------------------------------
    def get_guardrail_level(self, category: str) -> str:
        """Get the level for a guardrail category: off, warn, block."""
        return self._data.get("guardrail_levels", {}).get(category, "block")

    def set_guardrail_level(self, category: str, level: str) -> None:
        """Set the level for a guardrail category."""
        if level not in GUARDRAIL_LEVELS:
            raise ValueError(f"Level must be one of: {', '.join(GUARDRAIL_LEVELS)}")
        levels = self._data.setdefault("guardrail_levels", {})
        levels[category] = level
        self._save()

    # ------------------------------------------------------------------
    # Full state
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)

    def reset(self) -> None:
        """Reset all runtime config to defaults."""
        self._data = {}
        self._merge_defaults()
        self._rebuild_cache()
        self._save()
