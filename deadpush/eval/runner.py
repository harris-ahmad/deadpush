"""Run scenario × baseline matrix and emit CSV / markdown summary."""

from __future__ import annotations

import csv
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from .baselines import ALL_BASELINES, Baseline
from .scenarios import SCENARIOS
from .types import EvalRow, ScenarioResult


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "eval@deadpush.test"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Eval"], cwd=path, check=True, capture_output=True)
    (path / ".gitkeep").write_text("", encoding="utf-8")
    subprocess.run(["git", "add", ".gitkeep"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True)


def run_one(scenario_id: str, baseline: Baseline) -> ScenarioResult:
    fn = SCENARIOS[scenario_id]
    with tempfile.TemporaryDirectory(prefix=f"deadpush-eval-{scenario_id}-") as td:
        repo = Path(td) / "repo"
        repo.mkdir()
        _init_repo(repo)
        baseline.setup(repo)
        return fn(baseline, repo)


def run_eval_matrix(
    *,
    scenarios: list[str] | None = None,
    baselines: list[str] | None = None,
) -> list[ScenarioResult]:
    scen_ids = scenarios or list(SCENARIOS.keys())
    base_ids = baselines or ["B0", "B1", "B2", "B3", "B4", "B4-ablation"]
    results: list[ScenarioResult] = []
    for bid in base_ids:
        baseline = ALL_BASELINES[bid]
        for sid in scen_ids:
            results.append(run_one(sid, baseline))
    return results


def write_csv(results: list[ScenarioResult], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [EvalRow.from_result(r) for r in results]
    fieldnames = list(rows[0].to_dict().keys()) if rows else [
        "scenario",
        "baseline",
        "blocked",
        "lasting_damage",
        "block_rate",
        "work_preserved",
        "false_positive",
        "time_to_safe_ms",
        "time_to_recover_ms",
        "overhead_ms",
        "useful_total",
        "useful_preserved",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row.to_dict())
    return path


def write_summary_md(results: list[ScenarioResult], path: Path) -> Path:
    """Aggregate means for thesis graphs (block rate, work preserved, overhead)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    by_base: dict[str, list[ScenarioResult]] = defaultdict(list)
    for r in results:
        by_base[r.baseline].append(r)

    lines = [
        "# Deadpush eval summary",
        "",
        "Aggregates over scripted scenarios (thesis §§5–7).",
        "",
        "| Baseline | mean block_rate (dangerous) | mean work_preserved | mean overhead_ms | FP count |",
        "|----------|-----------------------------|---------------------|------------------|----------|",
    ]
    dangerous = {"secret_write", "scratch_pollution", "destructive_git", "force_push", "hook_wipe"}
    for bid in sorted(by_base):
        rows = by_base[bid]
        dang = [r for r in rows if r.scenario in dangerous]
        block_vals = [r.block_rate for r in dang] or [0.0]
        wp_vals = [r.work_preserved for r in rows if r.useful_total > 0] or [1.0]
        oh_vals = [r.overhead_ms for r in rows] or [0.0]
        fps = sum(1 for r in rows if r.false_positive)
        lines.append(
            f"| {bid} | {sum(block_vals)/len(block_vals):.3f} | "
            f"{sum(wp_vals)/len(wp_vals):.3f} | {sum(oh_vals)/len(oh_vals):.1f} | {fps} |"
        )

    lines.extend(
        [
            "",
            "## Primary claim check (scenarios 3–5)",
            "",
            "Expect **B4 ≈ B3 on block rate for secrets**, and **B4 ≫ B3 on work preserved** "
            "under `destructive_git` / `force_push`.",
            "",
        ]
    )
    for sid in ("destructive_git", "force_push", "hook_wipe"):
        lines.append(f"### {sid}")
        lines.append("")
        lines.append("| Baseline | blocked | lasting_damage | work_preserved | notes |")
        lines.append("|----------|---------|----------------|----------------|-------|")
        for r in results:
            if r.scenario != sid:
                continue
            lines.append(
                f"| {r.baseline} | {int(r.blocked)} | {int(r.lasting_damage)} | "
                f"{r.work_preserved:.2f} | {r.notes} |"
            )
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_overhead_svg(results: list[ScenarioResult], path: Path) -> Path:
    """Minimal stdlib SVG bar chart of mean overhead_ms by baseline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    by_base: dict[str, list[float]] = defaultdict(list)
    for r in results:
        by_base[r.baseline].append(r.overhead_ms)
    labels = sorted(by_base)
    means = [sum(by_base[b]) / max(len(by_base[b]), 1) for b in labels]
    max_v = max(means) if means else 1.0
    width, height = 480, 240
    margin = 40
    bar_w = (width - 2 * margin) / max(len(labels), 1)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        f'<text x="{margin}" y="24" font-family="sans-serif" font-size="14">'
        "Mean overhead_ms by baseline</text>",
    ]
    for i, (lab, val) in enumerate(zip(labels, means)):
        h = 0 if max_v <= 0 else (val / max_v) * (height - 80)
        x = margin + i * bar_w + 8
        y = height - margin - h
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 16:.1f}" height="{h:.1f}" fill="#336699"/>'
        )
        parts.append(
            f'<text x="{x + (bar_w - 16) / 2:.1f}" y="{height - 16}" '
            f'text-anchor="middle" font-family="sans-serif" font-size="11">{lab}</text>'
        )
        parts.append(
            f'<text x="{x + (bar_w - 16) / 2:.1f}" y="{y - 4:.1f}" '
            f'text-anchor="middle" font-family="sans-serif" font-size="10">{val:.0f}</text>'
        )
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return path
