"""
Entry point resolution using plugins + config + heuristics + framework-aware route detection.

This integrates language plugins deeply: each plugin can contribute
detect_entry_points + we also honor explicit config + common conventions.
Framework route registrations (Flask, FastAPI, Express, etc.) are detected
via pattern scanning across source files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .config import Config
from .graph import CallGraph, Symbol


# ---------------------------------------------------------------------------
# Framework-aware route pattern detection
# ---------------------------------------------------------------------------

_FRAMEWORK_PATTERNS: list[tuple[str, str, list[str]]] = [
    ("flask", r'@\w+\.route\([\'"]([^\'"]+)[\'"]', [".py"]),
    ("flask_blueprint", r'@\w+\.(?:route|get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]', [".py"]),
    ("fastapi", r'@\w+\.(?:get|post|put|delete|patch|options|head|trace)\([\'"]([^\'"]+)[\'"]', [".py"]),
    ("django_url", r"path\([\'\"]([^\'\"]+)[\'\"],\s*(\w+)", [".py"]),
    ("django_re_path", r"re_path\([\'\"]([^\'\"]+)[\'\"],\s*(\w+)", [".py"]),
    ("django_include", r"include\([\'\"]([^\'\"]+)[\'\"]", [".py"]),
    ("express_get", r"\.(?:get|post|put|delete|patch|use)\s*\(\s*[\'\"]([^\'\"]*)[\'\"],\s*(\w+)", [".js", ".jsx", ".ts", ".tsx"]),
    ("express_route", r"(?:app|router)\.route\([\'\"]([^\'\"]+)[\'\"][^)]*\)\s*\.(?:get|post|put|delete|patch)\s*\((\w+)", [".js", ".jsx", ".ts", ".tsx"]),
    ("nextjs_page", r"export\s+default\s+(?:function|const|async\s+function)\s+(\w+)", [".js", ".jsx", ".ts", ".tsx"]),
    ("go_http", r"http\.HandleFunc\([\'\"]([^\'\"]+)[\'\"],\s*(\w+)", [".go"]),
    ("go_gin", r"(?:router|r|gin\.Default\(\))\.(?:GET|POST|PUT|DELETE|PATCH|Handle)\([\'\"]([^\'\"]+)[\'\"],\s*(\w+)", [".go"]),
    ("rust_axum", r"\.route\([\'\"]([^\'\"]+)[\'\"],\s*(\w+)", [".rs"]),
    ("rust_actix", r"\.route\([\'\"]([^\'\"]+)[\'\"],\s*\w+\.\w+\(\)\.to\((\w+)", [".rs"]),
]


def _scan_file_for_routes(path: Path) -> list[str]:
    """Scan a single source file for framework route handler references."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    handlers: list[str] = []
    for name, pattern, extensions in _FRAMEWORK_PATTERNS:
        if path.suffix.lower() in extensions:
            for match in re.finditer(pattern, text, re.MULTILINE):
                if match.lastindex and match.lastindex >= 2:
                    handlers.append(match.group(match.lastindex))
                elif match.lastindex == 1:
                    # Some patterns only capture the route, not the handler
                    pass
    return handlers


def detect_framework_entry_points(
    files: list[Any],
    graph: CallGraph,
) -> list[str]:
    """Detect entry points from framework route registrations.

    Scans source files for common framework routing patterns (Flask, FastAPI,
    Express, Django, Gin, Axum, etc.) and returns symbol IDs for handler
    functions referenced in route definitions.

    This catches cases like Flask @app.route, FastAPI @app.get, Express app.get(),
    Django urlpatterns, etc. — all of which are "entry points" from the
    framework's perspective even if they don't have a traditional main().
    """
    roots: set[str] = set()

    # Collect handler names from all source files
    handler_names: set[str] = set()
    for f in files:
        if not getattr(f, "is_text", True):
            continue
        handlers = _scan_file_for_routes(f.path)
        handler_names.update(handlers)

    if not handler_names:
        return []

    # Match handler names to symbol IDs in the graph
    name_index: dict[str, list[str]] = {}
    for sid, sym in graph.symbols.items():
        name_index.setdefault(sym.name, []).append(sid)

    for name in handler_names:
        ids = name_index.get(name, [])
        for sid in ids:
            roots.add(sid)

        # Try stem of file (e.g., for Django views)
        for sid, sym in graph.symbols.items():
            if name in sid and sym.name == name:
                roots.add(sid)

    return list(roots)


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

def resolve_entry_points(
    graph: CallGraph,
    files: list[Any],  # list of FileInfo or similar
    plugins: dict[str, Any],
    config: Config,
) -> list[str]:
    """
    Return list of symbol IDs that are considered roots / entry points.
    """
    roots: set[str] = set()

    # 1. Explicit --entry / config include (names or paths)
    for inc in config.entrypoints.include:
        inc = inc.strip()
        if not inc:
            continue
        # try exact symbol match by id suffix or name
        for sym_id, sym in graph.symbols.items():
            if sym.name == inc or inc in sym_id or str(sym.path).endswith(inc):
                roots.add(sym_id)

    # 2. Plugin-provided detection (the good stuff)
    dynamic_pats = config.entrypoints.dynamic_patterns
    for f in files:
        if not getattr(f, "is_text", True):
            continue
        lang_plug = None
        for p in plugins.values():
            if f.path.suffix.lower() in getattr(p, "extensions", []):
                lang_plug = p
                break
        if not lang_plug or not hasattr(lang_plug, "detect_entry_points"):
            continue
        try:
            tree = lang_plug.parse(f.path.read_bytes(), str(f.path))
            detected = lang_plug.detect_entry_points(tree, str(f.path), dynamic_pats)
            for det in detected:
                # match against symbols we have for this file
                matched = False
                for sym_id, sym in graph.symbols.items():
                    if sym.path != str(f.path):
                        continue
                    if sym.name == det:
                        roots.add(sym_id)
                        matched = True
                        break
                if not matched:
                    for sym_id, sym in graph.symbols.items():
                        if sym.path == str(f.path) and det in sym.name:
                            roots.add(sym_id)
                            break
                # fallback synthetic if not parsed as symbol
                if det in ("main", "__main__", "default", "app"):
                    candidate = f"{Path(f.path).as_posix()}::{det}"
                    if candidate in graph.symbols:
                        roots.add(candidate)
        except Exception:
            pass

    # 3. Heuristics: anything marked is_entry_point=True by a plugin
    for sym_id, sym in graph.symbols.items():
        if sym.is_entry_point:
            roots.add(sym_id)

    # 4. Framework-aware route detection
    try:
        framework_roots = detect_framework_entry_points(files, graph)
        roots.update(framework_roots)
    except Exception:
        pass

    # 5. Common fallbacks if nothing found
    if not roots:
        for sym_id, sym in graph.symbols.items():
            if sym.name in ("main", "Main", "__main__", "index", "app", "server"):
                roots.add(sym_id)
            if "main" in str(sym.path).lower() and sym.kind == "file":
                roots.add(sym_id)

    # Always treat file symbols of "entry-ish" files as soft roots
    for sym_id, sym in graph.symbols.items():
        if sym.kind == "file" and any(k in str(sym.path).lower() for k in ("main", "app", "index", "cli", "cmd")):
            roots.add(sym_id)

    return sorted(roots)
