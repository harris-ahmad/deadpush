"""
Dependency Diff Review — detects new dependencies added in a session.

AI agents frequently add unnecessary dependencies. This module compares
current dependency files with the committed versions, showing what's new
with registry metadata (package age, downloads) to help evaluate risk.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEPS_CACHE_FILE = Path.home() / ".deadpush" / "deps_cache.json"
DEPS_CACHE_MAX_AGE = 86400  # 24 hours
REGISTRY_TIMEOUT = 5


@dataclass
class Dependency:
    """A single dependency entry."""
    name: str
    version: str
    source_file: str  # e.g., "pyproject.toml", "package.json"


@dataclass
class DepDiff:
    """Result of comparing dependency files."""
    added: list[Dependency] = field(default_factory=list)
    removed: list[Dependency] = field(default_factory=list)
    changed: list[tuple[Dependency, Dependency]] = field(default_factory=list)  # (old, new)


class DepsReviewer:
    """Reviews dependencies by comparing current files with HEAD and checking registries."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self._cache: dict[str, Any] = {}
        self._load_cache()

    # ------------------------------------------------------------------
    # Cache for registry lookups
    # ------------------------------------------------------------------
    def _load_cache(self):
        if DEPS_CACHE_FILE.exists():
            try:
                data = json.loads(DEPS_CACHE_FILE.read_text(encoding="utf-8"))
                now = time.time()
                self._cache = {
                    k: v for k, v in data.items()
                    if now - v.get("cached_at", 0) < DEPS_CACHE_MAX_AGE
                }
            except Exception:
                self._cache = {}

    def _save_cache(self):
        try:
            DEPS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            DEPS_CACHE_FILE.write_text(
                json.dumps(self._cache, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Parsing dependency files
    # ------------------------------------------------------------------
    def _parse_pyproject(self, content: str) -> list[Dependency]:
        """Parse pyproject.toml dependencies."""
        deps: list[Dependency] = []
        try:
            import tomllib
            data = tomllib.loads(content)
        except Exception:
            # Fallback to regex
            for m in re.finditer(r'"([^"]+)"\s*=\s*"([^"]*)"', content):
                deps.append(Dependency(name=m.group(1), version=m.group(2), source_file="pyproject.toml"))
            return deps

        for section in ("project.dependencies", "project.optional-dependencies"):
            keys = section.split(".")
            d = data
            for k in keys:
                d = d.get(k, {}) if isinstance(d, dict) else {}
            if isinstance(d, list):
                for dep_str in d:
                    if isinstance(dep_str, str):
                        m = re.match(r'^([\w.-]+)\s*(.+)?', dep_str)
                        if m:
                            deps.append(Dependency(name=m.group(1), version=(m.group(2) or "").strip(), source_file="pyproject.toml"))
        return deps

    def _parse_requirements(self, content: str) -> list[Dependency]:
        """Parse requirements.txt."""
        deps: list[Dependency] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r'^([\w.-]+)\s*([><=!]+\s*\S+)?', line)
            if m:
                deps.append(Dependency(name=m.group(1), version=(m.group(2) or "").strip(), source_file="requirements.txt"))
        return deps

    def _parse_package_json(self, content: str) -> list[Dependency]:
        """Parse package.json dependencies."""
        deps: list[Dependency] = []
        try:
            data = json.loads(content)
        except Exception:
            return deps

        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append(Dependency(name=name, version=str(version), source_file="package.json"))
        return deps

    def _parse_cargo(self, content: str) -> list[Dependency]:
        """Parse Cargo.toml dependencies."""
        deps: list[Dependency] = []
        try:
            import tomllib
            data = tomllib.loads(content)
        except Exception:
            for m in re.finditer(r'(\w+)\s*=\s*\{?\s*version\s*=\s*"([^"]+)"', content):
                deps.append(Dependency(name=m.group(1), version=m.group(2), source_file="Cargo.toml"))
            return deps

        for name, info in data.get("dependencies", {}).items():
            if isinstance(info, str):
                deps.append(Dependency(name=name, version=info, source_file="Cargo.toml"))
            elif isinstance(info, dict):
                deps.append(Dependency(name=name, version=info.get("version", "*"), source_file="Cargo.toml"))
        return deps

    def _parse_gomod(self, content: str) -> list[Dependency]:
        """Parse go.mod dependencies."""
        deps: list[Dependency] = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require (") or line.startswith(")"):
                continue
            m = re.match(r'^([\w./-]+)\s+v?([\w.+-]+)', line)
            if m and not m.group(1).startswith("go ") and m.group(1) != "require":
                deps.append(Dependency(name=m.group(1), version="v" + m.group(2).lstrip("v"), source_file="go.mod"))
        return deps

    def _parse_file(self, content: str, path: Path) -> list[Dependency]:
        """Dispatch to the appropriate parser based on filename."""
        name = path.name
        if name == "pyproject.toml":
            return self._parse_pyproject(content)
        elif name == "requirements.txt" or name.endswith("-requirements.txt"):
            return self._parse_requirements(content)
        elif name == "package.json":
            return self._parse_package_json(content)
        elif name == "Cargo.toml":
            return self._parse_cargo(content)
        elif name == "go.mod":
            return self._parse_gomod(content)
        return []

    # ------------------------------------------------------------------
    # Git comparison
    # ------------------------------------------------------------------
    def _get_head_version(self, rel_path: str) -> str | None:
        """Get the committed version of a file from git HEAD."""
        try:
            result = subprocess.run(
                ["git", "show", f"HEAD:{rel_path}"],
                capture_output=True, text=True, timeout=5,
                cwd=self.repo_root,
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Registry metadata
    # ------------------------------------------------------------------
    def _lookup_pypi(self, package: str) -> dict[str, Any] | None:
        """Look up package metadata from PyPI."""
        cache_key = f"pypi:{package.lower()}"
        if cache_key in self._cache:
            return self._cache[cache_key]["data"]

        try:
            url = f"https://pypi.org/pypi/{package}/json"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "deadpush/0.2.0")
            resp = urllib.request.urlopen(req, timeout=REGISTRY_TIMEOUT)
            data = json.loads(resp.read().decode("utf-8"))
            info = data.get("info", {})
            releases = data.get("releases", {})
            first_release = min(releases.keys()) if releases else None
            result = {
                "name": info.get("name", package),
                "latest_version": info.get("version", ""),
                "summary": (info.get("summary", "") or "")[:120],
                "first_release": first_release,
                "home_page": info.get("home_page") or info.get("project_urls", {}).get("Homepage", ""),
            }
            self._cache[cache_key] = {"data": result, "cached_at": time.time()}
            self._save_cache()
            return result
        except Exception:
            self._cache[cache_key] = {"data": None, "cached_at": time.time()}
            self._save_cache()
            return None

    def _lookup_npm(self, package: str) -> dict[str, Any] | None:
        """Look up package metadata from npm."""
        cache_key = f"npm:{package.lower()}"
        if cache_key in self._cache:
            return self._cache[cache_key]["data"]

        try:
            url = f"https://registry.npmjs.org/{package}/latest"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "deadpush/0.2.0")
            resp = urllib.request.urlopen(req, timeout=REGISTRY_TIMEOUT)
            data = json.loads(resp.read().decode("utf-8"))
            result = {
                "name": data.get("name", package),
                "latest_version": data.get("version", ""),
                "description": (data.get("description", "") or "")[:120],
                "home_page": data.get("homepage", ""),
            }
            self._cache[cache_key] = {"data": result, "cached_at": time.time()}
            self._save_cache()
            return result
        except Exception:
            self._cache[cache_key] = {"data": None, "cached_at": time.time()}
            self._save_cache()
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_dep_files(self) -> list[Path]:
        """Find dependency files in the repo."""
        dep_files = []
        for name in ("pyproject.toml", "requirements.txt", "package.json", "Cargo.toml", "go.mod"):
            p = self.repo_root / name
            if p.exists():
                dep_files.append(p)
        return dep_files

    def get_current_deps(self) -> list[Dependency]:
        """Parse all current dependency files."""
        all_deps: list[Dependency] = []
        for path in self.get_dep_files():
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                all_deps.extend(self._parse_file(content, path))
            except Exception:
                pass
        return all_deps

    def diff_with_head(self) -> DepDiff:
        """Compare current dependencies with the committed versions."""
        current = self.get_current_deps()
        current_set = {(d.name, d.source_file) for d in current}

        # Parse HEAD versions
        head_deps: list[Dependency] = []
        for path in self.get_dep_files():
            rel = path.relative_to(self.repo_root).as_posix()
            head_content = self._get_head_version(rel)
            if head_content is not None:
                head_deps.extend(self._parse_file(head_content, path))

        head_set = {(d.name, d.source_file) for d in head_deps}
        head_by_key = {(d.name, d.source_file): d for d in head_deps}
        current_by_key = {(d.name, d.source_file): d for d in current}

        added_keys = current_set - head_set
        removed_keys = head_set - current_set
        common_keys = current_set & head_set

        added = [current_by_key[k] for k in added_keys]
        removed = [head_by_key[k] for k in removed_keys]
        changed = []
        for k in common_keys:
            old = head_by_key[k]
            new = current_by_key[k]
            if old.version != new.version:
                changed.append((old, new))

        return DepDiff(added=added, removed=removed, changed=changed)

    def review_added(self, added: list[Dependency]) -> list[dict[str, Any]]:
        """Look up registry metadata for newly added dependencies."""
        reviews: list[dict[str, Any]] = []
        for dep in added:
            info = None
            source = dep.source_file
            if "pyproject" in source or "requirements" in source:
                info = self._lookup_pypi(dep.name)
            elif "package" in source:
                info = self._lookup_npm(dep.name)

            review = {
                "name": dep.name,
                "version": dep.version,
                "source_file": dep.source_file,
                "registry_info": info,
            }
            reviews.append(review)
        return reviews
