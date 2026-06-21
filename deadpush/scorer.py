"""
Scoring + classification of dead symbols into tiers.

Integrates:
- reachability info
- per-symbol dynamic_risk from language plugins
- simple heuristics for "suspicious" / AI generated surface
"""

from __future__ import annotations

from typing import Any

from .graph import CallGraph, DeadSymbol, Symbol


def score_symbol(
    sym: Symbol,
    graph: CallGraph,
    reachability: Any,
    config: Any,
) -> DeadSymbol | None:
    """Return a DeadSymbol wrapper or None if we decide not to report it."""
    if sym.kind == "file":
        # Files are reported via debris, not usually as dead symbols
        return None

    reasons: list[str] = []
    tier = "uncertain"
    confidence = 0.6
    safe = True
    order = 10

    # Base from reachability buckets
    sid = sym.id
    if sid in getattr(reachability, "unreachable", set()):
        tier = "definite"
        confidence = 0.92
        reasons.append("No path from any detected entry point")
        order = 1
    elif sid in getattr(reachability, "uncertain", set()):
        tier = "suspicious"
        confidence = 0.65
        reasons.append("Only reachable via dynamic or hard-to-resolve call")
    else:
        # reachable - shouldn't normally be called here but guard
        return None

    # Boost with language plugin risk signal
    if sym.dynamic_risk > 0.4:
        confidence = min(0.98, confidence + 0.15)
        reasons.append(f"High dynamic risk ({sym.dynamic_risk:.0%}) from language analysis")
        if sym.dynamic_risk > 0.7:
            tier = "probable" if tier == "definite" else tier
            safe = False  # risky to delete unsafe / reflection heavy code

    # Kind-based
    if sym.kind in ("method", "function") and "test" in sym.name.lower():
        # tests are often dead by design from main analysis; lower priority
        confidence *= 0.6
        reasons.append("Likely test/helper (low priority)")

    if sym.kind == "class" and confidence > 0.8:
        order = 2

    # Very simple "looks AI generated" bonus for dead classification (name heuristics)
    low_quality_names = {"foo", "bar", "baz", "temp", "tmp", "unused", "deadcode", "placeholder"}
    if sym.name.lower() in low_quality_names:
        confidence = min(0.99, confidence + 0.1)
        reasons.append("Suspicious placeholder name often seen in generated code")

    ds = DeadSymbol(
        symbol=sym,
        tier=tier,
        confidence=round(confidence, 3),
        reasons=reasons or ["Unreachable from entry points"],
        safe_to_delete=safe,
        delete_order=order,
    )
    return ds
