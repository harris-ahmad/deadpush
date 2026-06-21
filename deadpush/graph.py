# Full advanced implementation of Symbol, Edge, CallGraph, DeadSymbol, DebrisFile etc.
# Inspired by BlastRadius's callgraph_model.py for proper function-scoped call graphs
# with qualified names, cross-file resolution, snippets, bindings, and entry points.
# This makes dead code reachability and impact analysis much more accurate
# down to individual function/symbol calls.

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

SCHEMA_VERSION = 3
MODULE_SCOPE = "<module>"

SymbolKind = Literal["function", "class", "method", "variable", "export", "file", "module"]
EdgeKind = Literal["calls", "imports", "inherits", "re-exports", "decorates", "contains"]


@dataclass(frozen=True, slots=True)
class FunctionDef:
    """Rich function/method definition, similar to BlastRadius."""
    id: str
    name: str
    qualified_name: str
    line_start: int
    line_end: int
    is_entry_point: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "is_entry_point": self.is_entry_point,
        }


@dataclass(frozen=True, slots=True)
class CallEdge:
    """Rich call edge with resolution info, snippet, usage, binding, package.
    Directly modeled on BlastRadius CallEdge for proper symbol-level calls."""
    caller_id: str
    callee_name: str
    line: int
    snippet: str = ""
    usage: str = "call"
    callee_id: str | None = None
    package: str | None = None
    binding: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "callee_name": self.callee_name,
            "callee_id": self.callee_id,
            "line": self.line,
            "snippet": self.snippet,
            "usage": self.usage,
            "package": self.package,
            "binding": self.binding,
        }


# Legacy flat structures kept for backward compat in existing plugins / reachability
@dataclass(frozen=True, slots=True)
class Symbol:
    id: str
    name: str
    kind: SymbolKind
    path: str
    line: int
    is_entry_point: bool = False
    dynamic_risk: float = 0.0
    qualified_name: str | None = None
    line_end: int | None = None


@dataclass(frozen=True, slots=True)
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    confidence: float = 1.0


@dataclass
class CallGraph:
    symbols: dict[str, Symbol] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    # New rich data for proper call graphs
    files_graph: dict[str, dict[str, Any]] = field(default_factory=dict)
    function_index: dict[str, dict[str, Any]] = field(default_factory=dict)
    call_edges: list[dict[str, Any]] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)

    def add_symbol(self, symbol: Symbol) -> None:
        self.symbols[symbol.id] = symbol

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def outgoing(self, symbol_id: str) -> list[Edge]:
        return [e for e in self.edges if e.src == symbol_id]

    def incoming(self, symbol_id: str) -> list[Edge]:
        return [e for e in self.edges if e.dst == symbol_id]

    def get_symbol(self, symbol_id: str) -> Symbol | None:
        return self.symbols.get(symbol_id)

    def add_rich_call_edge(self, edge: dict[str, Any]) -> None:
        self.call_edges.append(edge)

    def add_file_graph(self, path: str, file_graph: dict[str, Any]) -> None:
        self.files_graph[path] = file_graph


def make_symbol_id(
    path: str, name: str, qualified_name: str | None = None, line: int | None = None
) -> str:
    """Create a deterministic unique identifier for a symbol.

    Enhanced to support qualified_name and line (inspired by BlastRadius
    make_function_id) to avoid collisions and enable precise call resolution
    down to specific function/symbol definitions and calls.
    """
    normalized = Path(path).as_posix().lstrip("./")
    qname = qualified_name or name
    safe = qname.strip().replace(" ", "_")
    if line is not None:
        return f"{normalized}::{safe}@{line}"
    return f"{normalized}::{safe}"


def module_caller_id(file_path: str) -> str:
    """Id for the module-level scope (like BlastRadius)."""
    normalized = Path(file_path).as_posix().lstrip("./")
    return f"{normalized}::{MODULE_SCOPE}"


def dedupe_calls(items: list[CallEdge]) -> list[CallEdge]:
    """Dedupe call edges (from BlastRadius)."""
    seen: set[tuple[str, str, int, str | None]] = set()
    out: list[CallEdge] = []
    for item in items:
        key = (item.caller_id, item.callee_name, item.line, item.package)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return sorted(out, key=lambda x: (x.caller_id, x.line, x.callee_name))


def dedupe_imports(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedupe import records (from BlastRadius)."""
    seen: set[tuple[str, int]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = (str(item.get("name", "")), int(item.get("line", 1)))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return sorted(out, key=lambda x: (str(x.get("name")), int(x.get("line", 1))))


def legacy_calls_from_edges(calls: list[CallEdge]) -> list[dict[str, Any]]:
    """Flatten for backward compat with older deadpush consumers."""
    return [
        {
            "name": edge.callee_name,
            "line": edge.line,
            "snippet": edge.snippet,
            "binding": edge.binding,
            "package": edge.package,
            "usage": edge.usage,
            "caller_id": edge.caller_id,
            "callee_id": edge.callee_id,
        }
        for edge in calls
    ]


def content_hash(path: Path | str) -> str | None:
    """Compute SHA256 content hash for duplicate/debris detection. Returns None on I/O error."""
    try:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return None
        data = p.read_bytes()
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return None


def _index_functions(files_graph: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build id -> function meta index (from BlastRadius _index_functions)."""
    index: dict[str, dict[str, Any]] = {}
    for file_path, meta in files_graph.items():
        raw_funcs = meta.get("functions", [])
        if not isinstance(raw_funcs, list):
            continue
        for fn in raw_funcs:
            if not isinstance(fn, dict):
                continue
            fn_id = str(fn.get("id") or "")
            if fn_id:
                index[fn_id] = {**fn, "file_path": file_path}
    return index


def _resolve_cross_file_callees(files_graph: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Best-effort cross-file callee resolution (inspired by BlastRadius).

    Uses simple name and qualified_name fallbacks to set callee_id on edges.
    This enables proper function-to-function call graphs instead of only
    name strings, dramatically improving reachability accuracy for dead code
    and blast radius.
    """
    func_index = _index_functions(files_graph)
    by_simple_name: dict[str, list[str]] = {}
    for fn_id, fn in func_index.items():
        name = str(fn.get("name") or "")
        if name:
            by_simple_name.setdefault(name, []).append(fn_id)

    resolved_edges: list[dict[str, Any]] = []

    for file_path, meta in files_graph.items():
        raw_calls = meta.get("calls", [])
        if not isinstance(raw_calls, list):
            continue
        for call in raw_calls:
            if not isinstance(call, dict):
                continue
            caller_id = str(call.get("caller_id") or "")
            callee_name = str(call.get("callee_name") or "")
            callee_id = call.get("callee_id")
            if not caller_id or not callee_name:
                continue

            if not callee_id:
                root = callee_name.split(".", 1)[0]
                candidates = by_simple_name.get(root, [])
                if len(candidates) == 1:
                    callee_id = candidates[0]
                elif root != callee_name:
                    qualified_candidates = [
                        fid
                        for fid, fn in func_index.items()
                        if str(fn.get("qualified_name") or "").endswith(callee_name)
                        or str(fn.get("qualified_name") or "") == callee_name
                    ]
                    if len(qualified_candidates) == 1:
                        callee_id = qualified_candidates[0]

            edge = {
                "file_path": file_path,
                "caller_id": caller_id,
                "callee_id": callee_id,
                "callee_name": callee_name,
                "line": int(call.get("line") or 1),
                "package": call.get("package"),
                "binding": call.get("binding"),
                "usage": call.get("usage") or "call",
            }
            resolved_edges.append(edge)

    return resolved_edges


def build_repo_call_graph(files_graph: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Assemble repo-wide call graph with resolved cross-file edges.

    Direct port/adaptation of BlastRadius build_repo_call_graph + helpers.
    Used by the analysis pipeline (cli.py) after language plugins emit per-file
    FileGraph data. This gives deadpush proper function-level call graphs.
    """
    func_index = _index_functions(files_graph)
    call_edges = _resolve_cross_file_callees(files_graph)
    entry_points = [
        fn_id for fn_id, fn in func_index.items() if bool(fn.get("is_entry_point"))
    ]

    total_calls = sum(
        len(meta.get("calls", []))
        for meta in files_graph.values()
        if isinstance(meta.get("calls"), list)
    )
    total_imports = sum(
        len(meta.get("imports", []))
        for meta in files_graph.values()
        if isinstance(meta.get("imports"), list)
    )
    total_bindings = sum(
        len(meta.get("bindings", {}))
        for meta in files_graph.values()
        if isinstance(meta.get("bindings"), dict)
    )

    return {
        "files": files_graph,
        "function_index": func_index,
        "call_edges": call_edges,
        "entry_points": entry_points,
        "summary": {
            "file_count": len(files_graph),
            "function_count": len(func_index),
            "call_count": total_calls,
            "import_count": total_imports,
            "binding_count": total_bindings,
            "entry_point_count": len(entry_points),
        },
        "schema_version": SCHEMA_VERSION,
    }


def build_forward_adjacency(call_edges: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Build caller -> [callee_ids] adjacency for reachability (from BlastRadius)."""
    adj: dict[str, list[str]] = {}
    for edge in call_edges:
        caller = str(edge.get("caller_id") or "")
        callee = edge.get("callee_id")
        if not caller or not isinstance(callee, str) or not callee:
            continue
        adj.setdefault(caller, [])
        if callee not in adj[caller]:
            adj[caller].append(callee)
    return adj


@dataclass
class DeadSymbol:
    symbol: Symbol
    tier: Literal["definite", "probable", "suspicious", "uncertain"]
    confidence: float
    reasons: list[str]
    safe_to_delete: bool = True
    delete_order: int = 0
    alive_score: float = 0.0
    tier_new: str = "uncertain"
    factor_breakdown: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DebrisFile:
    path: str
    category: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    block_push: bool = False
    suggestion: str = ""
@dataclass
class FileGraph:
    """Per-file call graph data (imports, bindings, functions, calls).

    Matches the shape emitted by deadpush language plugins (now aligned
    with BlastRadius callgraph_model for proper cross-file resolution).
    """
    language: str
    imports: list[dict[str, Any]] = field(default_factory=list)
    bindings: dict[str, str] = field(default_factory=dict)
    functions: list[FunctionDef] = field(default_factory=list)
    calls: list[CallEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "imports": self.imports,
            "bindings": self.bindings,
            "functions": [f.to_dict() for f in self.functions],
            "calls": [c.to_dict() for c in self.calls],
        }


__all__ = [
    "SymbolKind",
    "EdgeKind",
    "Symbol",
    "Edge",
    "CallGraph",
    "FunctionDef",
    "CallEdge",
    "FileGraph",
    "make_symbol_id",
    "module_caller_id",
    "dedupe_calls",
    "dedupe_imports",
    "legacy_calls_from_edges",
    "build_repo_call_graph",
    "build_forward_adjacency",
    "_index_functions",
    "_resolve_cross_file_callees",
    "DeadSymbol",
    "DebrisFile",
    "content_hash",
]
