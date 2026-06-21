"""
Reachability analysis for dead code detection.

Given the (partial) call graph built from language plugins, compute
what is reachable from the entry point roots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .graph import CallGraph


@dataclass
class ReachabilityResult:
    reachable: set[str] = field(default_factory=set)
    unreachable: set[str] = field(default_factory=set)
    uncertain: set[str] = field(default_factory=set)  # dynamic / risk / unresolved calls


def compute_reachability(
    graph: CallGraph,
    roots: list[str],
    config: Any,
) -> ReachabilityResult:
    """
    Naive but effective DFS/BFS reachability.

    Because call sites from plugins currently record raw callee *text*, we do
    fuzzy matching to symbol names. Real prod would do proper name resolution.
    """
    reachable: set[str] = set()
    uncertain: set[str] = set()

    # Build quick name -> ids index (last wins for simplicity, or collect)
    name_to_ids: dict[str, list[str]] = {}
    for sid, sym in graph.symbols.items():
        name_to_ids.setdefault(sym.name, []).append(sid)
        # also basename of path for file symbols etc
        base = Path(sym.path).name
        if base != sym.name:
            name_to_ids.setdefault(base, []).append(sid)

    from collections import deque
    q = deque(roots)
    for r in roots:
        reachable.add(r)

    # Also add edges if they were added (future proof)
    adj: dict[str, list[str]] = {sid: [] for sid in graph.symbols}
    for edge in getattr(graph, "edges", []):
        if edge.src in adj:
            adj[edge.src].append(edge.dst)

    # Prefer rich resolved call_edges from the new BlastRadius-style graph assembly
    rich_edges = getattr(graph, "call_edges", []) or []
    for e in rich_edges:
        src = str(e.get("caller_id") or e.get("src") or "")
        dst = e.get("callee_id") or e.get("dst")
        if src and dst and src in adj:
            adj.setdefault(src, [])
            if dst not in adj[src]:
                adj[src].append(str(dst))

    visited = set(reachable)

    def resolve_callee(callee_text: str) -> list[str]:
        """Very heuristic resolution of a raw callee string to symbol ids."""
        c = callee_text.strip().strip("()[]{}; ")
        if not c:
            return []
        # direct name match
        if c in name_to_ids:
            return name_to_ids[c]
        # last segment after . (method calls)
        last = c.split(".")[-1].split("(")[0]
        if last in name_to_ids:
            return name_to_ids[last]
        # bare function
        bare = c.split("(")[0].split("::")[-1]
        if bare in name_to_ids:
            return name_to_ids[bare]
        return []

    # Traverse from graph edges first (if present)
    while q:
        cur = q.popleft()
        # explicit edges
        for dst in adj.get(cur, []):
            if dst not in visited:
                visited.add(dst)
                reachable.add(dst)
                q.append(dst)

        # also from symbols that have outgoing? we didn't populate many edges yet
        sym = graph.get_symbol(cur)
        if not sym:
            continue

    # Second pass: use the raw call_sites that were collected in plugins but not wired.
    # In current cli the calls are parsed but not added to graph; we simulate here using all known calls.
    # To make plugins contribute, we scan again? For now do a global pass using symbols.
    # Simpler: consider every symbol that is called by a reachable one.
    # We do this by iterating call data? Since calls aren't stored on graph, we re-walk? Skip for perf.
    # For integration, we mark high dynamic_risk symbols as uncertain even if named match.

    # Second pass: use stored raw call edges (from plugins) to reach more symbols.
    # We do fuzzy name resolution on the dst side.
    name_index: dict[str, list[str]] = {}
    for sid, s in graph.symbols.items():
        name_index.setdefault(s.name, []).append(sid)
        base = Path(s.path).stem
        name_index.setdefault(base, []).append(sid)

    def _resolve(dst: str) -> list[str]:
        d = dst.strip().strip("()[]{};, ")
        if not d:
            return []
        if d in name_index:
            return name_index[d]
        last = d.split(".")[-1].split("::")[-1].split("(")[0]
        if last in name_index:
            return name_index[last]
        return []

    # Walk the call edges recorded in the graph (prefer rich resolved ones)
    rich_edges = getattr(graph, "call_edges", []) or []
    for e in rich_edges:
        src = str(e.get("caller_id") or e.get("src") or "")
        if src in reachable:
            dst = e.get("callee_id") or e.get("dst") or e.get("callee_name")
            if dst:
                for target in _resolve(str(dst)):
                    if target not in visited:
                        visited.add(target)
                        reachable.add(target)
                        q.append(target)

    for edge in getattr(graph, "edges", []):
        if edge.src in reachable:
            for target in _resolve(edge.dst):
                if target not in visited:
                    visited.add(target)
                    reachable.add(target)
                    q.append(target)  # continue DFS from here

    # Drain any newly enqueued from raw calls
    while q:
        cur = q.popleft()
        for edge in getattr(graph, "edges", []):
            if edge.src == cur:
                for target in _resolve(edge.dst):
                    if target not in visited:
                        visited.add(target)
                        reachable.add(target)
                        q.append(target)

    # Now compute unreachable
    all_sym_ids = set(graph.symbols.keys())
    unreachable = all_sym_ids - reachable

    # Promote some to uncertain if they had dynamic risk or were only reachable via raw text that didn't resolve cleanly
    for sid in list(unreachable):
        sym = graph.get_symbol(sid)
        if sym and sym.dynamic_risk > 0.3:
            uncertain.add(sid)
            unreachable.discard(sid)

    # Files themselves are rarely "dead" unless whole module
    for sid in list(unreachable):
        sym = graph.get_symbol(sid)
        if sym and sym.kind == "file":
            # don't report the file as dead code usually
            unreachable.discard(sid)

    return ReachabilityResult(
        reachable=reachable,
        unreachable=unreachable,
        uncertain=uncertain,
    )
