"""
Scoring + classification of dead symbols using multi-factor deadness analysis.

Integrates:
- MultiFactorDeadnessScorer (6-factor analysis)
- reachability info
- per-symbol dynamic_risk from language plugins
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import Config
from .graph import CallGraph, DeadSymbol, Symbol
from .deadness import DeadnessResult, MultiFactorDeadnessScorer
from .registration import RegistrationDetector
from .importgraph import ImportAnalyzer


def score_symbol(
    sym: Symbol,
    graph: CallGraph,
    reachability: Any,
    config: Config,
    scorer: MultiFactorDeadnessScorer | None = None,
) -> DeadSymbol | None:
    """Return a DeadSymbol wrapper or None if we decide not to report it."""
    if sym.kind == "file":
        return None

    reasons: list[str] = []
    tier = "uncertain"
    confidence = 0.6
    safe = True
    order = 10
    alive_score = 0.0
    factor_breakdown: dict[str, float] = {}

    # Multi-factor scoring first (if available)
    if scorer is not None:
        result = scorer.score(sym)
        if result is None:
            return None  # abstention

        alive_score = result.alive_score
        factor_breakdown = result.factors
        if result.reasons:
            reasons.extend(result.reasons)

        # Map deadness tier to legacy tier
        match result.tier:
            case "high":
                tier = "definite"
                confidence = 0.95
                order = 1
                safe = True
            case "medium":
                tier = "probable"
                confidence = 0.85
                order = 3
                safe = True
            case "low":
                tier = "suspicious"
                confidence = 0.65
                order = 5
                safe = True
            case "uncertain":
                tier = "uncertain"
                confidence = 0.4
                order = 10
                safe = False

    # If no scorer (legacy path), fall through to reachability-based logic
    else:
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
            return None

    # Boost with language plugin risk signal
    if sym.dynamic_risk > 0.4:
        confidence = min(0.98, confidence + 0.15)
        reasons.append(f"High dynamic risk ({sym.dynamic_risk:.0%}) from language analysis")
        if sym.dynamic_risk > 0.7:
            tier = "probable" if tier == "definite" else tier
            safe = False

    # Kind-based
    if sym.kind in ("method", "function") and "test" in sym.name.lower():
        confidence *= 0.6
        reasons.append("Likely test/helper (low priority)")

    if sym.kind == "class" and confidence > 0.8:
        order = 2

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
        alive_score=round(alive_score, 3),
        tier_new=result.tier if scorer is not None else "uncertain",
        factor_breakdown=factor_breakdown,
    )
    return ds


def build_scorer(
    config: Config,
    graph: CallGraph,
    roots: set[str],
    all_file_paths: list[Path],
    custom_registrations: list[str] | None = None,
) -> MultiFactorDeadnessScorer:
    """Build a MultiFactorDeadnessScorer from analysis context."""
    registration = RegistrationDetector(all_file_paths, config.repo_root)
    if custom_registrations:
        for pat in custom_registrations:
            registration.add_custom_pattern(pat)

    imports = ImportAnalyzer(all_file_paths, config.repo_root)

    scorer = MultiFactorDeadnessScorer(
        config=config,
        repo_root=config.repo_root,
        graph=graph,
        registration=registration,
        imports=imports,
        roots=roots,
        all_file_paths=all_file_paths,
    )
    return scorer
