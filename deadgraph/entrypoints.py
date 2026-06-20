"""
Entry point resolution using plugins + config + heuristics.

This integrates language plugins deeply: each plugin can contribute
detect_entry_points + we also honor explicit config + common conventions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import Config
from .graph import CallGraph, Symbol


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
                for sym_id, sym in graph.symbols.items():
                    if sym.path == str(f.path) and (sym.name == det or det in sym.name):
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

    # 4. Common fallbacks if nothing found
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
