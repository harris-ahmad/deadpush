"""Thesis eval harness (Phase 4): scenarios × baselines → CSV + summary plots.

Scripted agent-like workloads (no live LLM). See ``docs/thesis.md`` §§5–7.
"""

from __future__ import annotations

from .runner import run_eval_matrix, write_csv, write_overhead_svg, write_summary_md
from .types import EvalRow, ScenarioResult

__all__ = [
    "EvalRow",
    "ScenarioResult",
    "run_eval_matrix",
    "write_csv",
    "write_summary_md",
    "write_overhead_svg",
]
