"""
Multi-hop reachability analysis — traces import chains to find paths to sensitive operations.

An agent can evade direct scanning by putting dangerous code in a utility file
that is then imported by the written file. This module builds an import graph
of the repo and checks whether a file can transitively reach sensitive operations
(eval, subprocess, file I/O, network, etc.) through its import chain.
"""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config

logger = logging.getLogger("deadpush.reachability")

MAX_HOPS = 10
CACHE_TTL = 5.0

_SOURCE_EXTENSIONS = frozenset({
    ".py", ".pyw", ".pyx",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts",
    ".go", ".rs",
    ".rb", ".php", ".pl", ".pm", ".lua",
    ".sh", ".bash", ".zsh", ".fish",
    ".java", ".kt", ".scala",
    ".swift", ".m", ".mm",
    ".ex", ".exs",
})

_JS_PATTERNS = [
    re.compile(r'''^\s*import\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+(?:\s*,\s*\{[^}]*\})?)\s+from\s+['"]([^'"]+)['"]'''),
    re.compile(r'''^\s*(?:const|let|var)\s+\w+\s*=\s*require\s*\(['"]([^'"]+)['"]'''),
    re.compile(r'''require\s*\(['"]([^'"]+)['"]\)'''),
]

IMPORT_PATTERNS: dict[str, list[re.Pattern]] = {
    ".py": [
        re.compile(r'^\s*import\s+(\S+)'),
        re.compile(r'^\s*from\s+(\S+)\s+import'),
    ],
    ".js": _JS_PATTERNS,
    ".jsx": _JS_PATTERNS,
    ".ts": _JS_PATTERNS,
    ".tsx": _JS_PATTERNS,
    ".go": [
        re.compile(r'^\s*import\s+[\'"]([^\'"]+)[\'"]'),
        re.compile(r'^\s*[\'"]([^\'"]+)[\'"]'),
    ],
    ".rs": [
        re.compile(r'^\s*use\s+(\S+)'),
    ],
}

for ext in (".mjs", ".cjs", ".mts", ".cts"):
    IMPORT_PATTERNS[ext] = _JS_PATTERNS

# Default sensitive operation patterns — configurable per-category.
SENSITIVE_OP_PATTERNS: dict[str, list[re.Pattern]] = {
    "code_execution": [
        re.compile(r'\beval\s*\('),
        re.compile(r'\bexec\s*\('),
        re.compile(r'\bcompile\s*\('),
    ],
    "shell_execution": [
        re.compile(r'\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\('),
        re.compile(r'\bos\.(?:system|popen)\s*\('),
        re.compile(r'\bshutil\.(?:rmtree|move|copy)\s*\('),
        re.compile(r'\b(?:execSync|exec|execFile|spawn|fork)\s*\('),
        re.compile(r'child_process\.'),
    ],
    "file_io": [
        re.compile(r'\bopen\s*\('),
        re.compile(r'\bPath\.(?:read_text|write_text|unlink|rename)\s*\('),
        re.compile(r'\bos\.(?:remove|unlink|rmdir|rename)\s*\('),
    ],
    "network": [
        re.compile(r'\brequests\.'),
        re.compile(r'\burllib\.'),
        re.compile(r'\bhttplib\.'),
        re.compile(r'\bsocket\.'),
        re.compile(r'\bhttp\.client'),
        re.compile(r'\baiohttp\.'),
    ],
    "deserialization": [
        re.compile(r'\bpickle\.(?:loads|load|dumps|dump)\s*\('),
        re.compile(r'\bshelve\.open\s*\('),
        re.compile(r'\byaml\.(?:load|dump)\s*\('),
    ],
    "native_code": [
        re.compile(r'\bctypes\.'),
        re.compile(r'\bcffi\.'),
        re.compile(r'\bffi\.'),
    ],
}

_SKIP_DIRS = frozenset({
    ".git", ".deadpush", ".deadpush-quarantine", ".deadpush-archive",
    ".deadpush-config-backups", ".guardian", "__pycache__", "node_modules",
    "venv", ".venv", "env", ".env", ".tox", ".eggs", "eggs",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "target", ".next", ".nuxt",
})


@dataclass
class SensitiveOp:
    category: str
    description: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "description": self.description, "line": self.line}


@dataclass
class ReachabilityViolation:
    file: str
    path: list[str]
    sensitive_op: SensitiveOp
    hops: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "path": " → ".join(self.path),
            "hops": self.hops,
            "sensitive_op": self.sensitive_op.to_dict(),
        }


class ImportGraph:
    """Directed import graph of a repo, with known sensitive operations per node."""

    def __init__(self, repo_root: Path):
        self._repo_root = repo_root
        self._graph: dict[str, set[str]] = {}
        self._sensitive_ops: dict[str, list[SensitiveOp]] = {}
        self._mtimes: dict[str, float] = {}
        self._built = False
        self._last_build = 0.0

    def rebuild(self) -> None:
        self._graph.clear()
        self._sensitive_ops.clear()
        self._mtimes.clear()
        self._built = False
        self._build()

    def _build(self) -> None:
        self._graph = {}
        self._sensitive_ops = {}
        self._mtimes = {}

        source_files = self._find_source_files()
        # First pass: extract imports and sensitive ops from each file
        file_imports: dict[str, list[str]] = {}
        for rel_path in source_files:
            full_path = self._repo_root / rel_path
            source = self._read_file(full_path)
            if source is None:
                continue
            ext = full_path.suffix.lower()
            imports = self._extract_imports(source, rel_path, ext)
            file_imports[rel_path] = imports
            ops = self._scan_sensitive_ops(source, ext)
            if ops:
                self._sensitive_ops[rel_path] = ops
            try:
                self._mtimes[rel_path] = full_path.stat().st_mtime_ns
            except OSError:
                pass

        # Second pass: resolve imports to file paths within the repo
        for rel_path, import_names in file_imports.items():
            resolved = set()
            for name in import_names:
                target = self._resolve_import(rel_path, name)
                if target:
                    resolved.add(target)
            self._graph[rel_path] = resolved

        self._built = True
        self._last_build = time.time()

    def _find_source_files(self) -> list[str]:
        source_files: list[str] = []
        try:
            for f in self._repo_root.rglob("*"):
                if f.is_dir():
                    continue
                try:
                    rel = f.relative_to(self._repo_root).as_posix()
                except ValueError:
                    continue
                parts = set(f.relative_to(self._repo_root).parts)
                if parts & _SKIP_DIRS:
                    continue
                if f.suffix.lower() in _SOURCE_EXTENSIONS:
                    source_files.append(rel)
        except PermissionError:
            pass
        return sorted(source_files)

    def _read_file(self, path: Path) -> str | None:
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                return None
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

    def _extract_imports(self, source: str, rel_path: str, ext: str) -> list[str]:
        imports: list[str] = []
        patterns = IMPORT_PATTERNS.get(ext, [])
        for pattern in patterns:
            for m in pattern.finditer(source):
                raw = m.group(1).strip()
                if ext == ".py":
                    name = raw.split(".")[0]
                elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"):
                    if raw.startswith("."):
                        name = self._resolve_relative_js_import(rel_path, raw)
                    else:
                        name = raw.split("/")[0]
                elif ext == ".go":
                    name = raw.split("/")[0]
                elif ext == ".rs":
                    name = raw.split("::")[0]
                else:
                    name = raw.split("/")[0]
                if name:
                    imports.append(name)
        return imports

    def _resolve_relative_js_import(self, rel_path: str, raw: str) -> str:
        dir_part = Path(rel_path).parent
        try:
            resolved = (self._repo_root / dir_part / raw).resolve(strict=False)
        except OSError:
            resolved = self._repo_root / dir_part / raw
        try:
            return resolved.relative_to(self._repo_root).as_posix()
        except ValueError:
            return raw.lstrip("./")

    def _resolve_import(self, importer_rel: str, name: str) -> str | None:
        candidates: list[str] = []

        if name.startswith("."):
            dir_part = Path(importer_rel).parent
            try:
                resolved = (self._repo_root / dir_part / name).resolve(strict=False)
            except OSError:
                resolved = self._repo_root / dir_part / name
            try:
                rel = resolved.relative_to(self._repo_root).as_posix()
            except ValueError:
                return None
            candidates = self._candidates_for_rel(rel)
        else:
            for ext in (".py", ".pyw", ".pyx"):
                candidates.append(f"{name}{ext}")
            candidates.append(str(Path(name) / "__init__.py"))
            candidates.append(str(Path(name) / "__init__.pyw"))
            for ext in (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"):
                candidates.append(f"{name}{ext}")
            candidates.append(str(Path(name) / "index.ts"))
            candidates.append(str(Path(name) / "index.js"))
            candidates.append(str(Path(name) / "index.tsx"))
            candidates.append(str(Path(name) / "index.jsx"))
            candidates.append(str(Path(name) / "mod.rs"))
            candidates.append(str(Path(name) / "lib.rs"))
            candidates.append(f"{name}.go")
            candidates.append(f"{name}.rs")

        for c in candidates:
            full = self._repo_root / c
            if full.exists() and full.is_file():
                return c.replace("\\", "/")
        return None

    def _candidates_for_rel(self, rel: str) -> list[str]:
        candidates = [rel]
        p = Path(rel)
        if p.suffix:
            return candidates
        for ext in (".py", ".pyw", ".pyx"):
            candidates.append(f"{rel}{ext}")
        candidates.append(str(p / "__init__.py"))
        for ext in (".js", ".ts", ".tsx", ".jsx"):
            candidates.append(f"{rel}{ext}")
            candidates.append(str(p / f"index{ext}"))
        candidates.append(str(p / "mod.rs"))
        candidates.append(f"{rel}.go")
        return candidates

    def _scan_sensitive_ops(self, source: str, ext: str) -> list[SensitiveOp]:
        ops: list[SensitiveOp] = []
        lines = source.splitlines()
        for category, patterns in SENSITIVE_OP_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    if pattern.search(line):
                        ops.append(SensitiveOp(
                            category=category,
                            description=pattern.pattern[:60],
                            line=i,
                        ))
                        break
        return ops

    def is_stale(self) -> bool:
        if not self._built:
            return True
        if time.time() - self._last_build > CACHE_TTL:
            return True
        for rel_path, cached_mtime in list(self._mtimes.items()):
            full = self._repo_root / rel_path
            try:
                current = full.stat().st_mtime_ns
                if current != cached_mtime:
                    return True
            except OSError:
                return True
        return False


_SHARED_GRAPHS: dict[str, ImportGraph] = {}


def _get_graph(repo_root: Path) -> ImportGraph:
    key = str(repo_root.resolve())
    graph = _SHARED_GRAPHS.get(key)
    if graph is None:
        graph = ImportGraph(repo_root)
        graph.rebuild()
        _SHARED_GRAPHS[key] = graph
    return graph


def clear_cache() -> None:
    _SHARED_GRAPHS.clear()


def check_reachability(
    rel_path: str,
    source: str,
    config: Config,
    *,
    max_hops: int = MAX_HOPS,
    config_overrides: dict[str, Any] | None = None,
) -> list[ReachabilityViolation]:
    """Check whether a file can transitively reach sensitive operations.

    Builds (or reuses) the import graph for the repo, then BFS-traces from
    the given file's imports to find any path to a file with sensitive ops.
    """
    violations: list[ReachabilityViolation] = []
    try:
        graph = _get_graph(config.repo_root)
    except Exception as e:
        logger.debug("Could not build import graph: %s", e)
        return violations

    ext = Path(rel_path).suffix.lower()
    content = source
    if not content:
        try:
            full_path = config.repo_root / rel_path
            if full_path.exists():
                content = full_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass

    imports = []
    try:
        imports = ImportGraph._extract_imports(graph, content, rel_path, ext)
    except Exception:
        pass

    resolved_imports: set[str] = set()

    if imports:
        for name in imports:
            target = graph._resolve_import(rel_path, name)
            if target:
                resolved_imports.add(target)

    if not resolved_imports and rel_path in graph._graph:
        resolved_imports = graph._graph[rel_path]

    visited: set[str] = set()
    # BFS through import graph
    queue: deque[tuple[str, list[str], int]] = deque()
    for imp in resolved_imports:
        queue.append((imp, [imp], 1))

    while queue:
        current, path, hops = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        ops = graph._sensitive_ops.get(current, [])
        if ops:
            for op in ops:
                violations.append(ReachabilityViolation(
                    file=current,
                    path=[rel_path] + path,
                    sensitive_op=op,
                    hops=hops,
                ))
            continue

        if hops >= max_hops:
            continue

        for neighbor in graph._graph.get(current, set()):
            if neighbor not in visited:
                queue.append((neighbor, path + [neighbor], hops + 1))

    return violations


def violations_from_reachability(
    rel_path: str,
    violations: list[ReachabilityViolation],
) -> list[dict[str, Any]]:
    return [v.to_dict() for v in violations]
