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
    if scenario_id not in SCENARIOS:
        raise KeyError(
            f"unknown scenario {scenario_id!r}; choose from {sorted(SCENARIOS)}"
        )
    fn = SCENARIOS[scenario_id]
    with tempfile.TemporaryDirectory(prefix=f"deadpush-eval-{scenario_id}-") as td:
        repo = Path(td) / "repo"
        repo.mkdir()
        _init_repo(repo)
        try:
            baseline.setup(repo)
        except Exception as e:
            from deadpush.backends.base import SandboxUnavailableError

            if isinstance(e, SandboxUnavailableError):
                return ScenarioResult(
                    scenario=scenario_id,
                    baseline=baseline.id,
                    blocked=False,
                    lasting_damage=False,
                    useful_total=0,
                    useful_preserved=0,
                    false_positive=False,
                    time_to_safe_ms=0.0,
                    time_to_recover_ms=0.0,
                    overhead_ms=0.0,
                    notes=f"skipped: {e}",
                )
            raise
        return fn(baseline, repo)


def run_eval_matrix(
    *,
    scenarios: list[str] | None = None,
    baselines: list[str] | None = None,
    os_confined: bool = False,
    backend_prefer: str | None = None,
) -> list[ScenarioResult]:
    results, _ = run_eval_matrix_with_meta(
        scenarios=scenarios,
        baselines=baselines,
        os_confined=os_confined,
        backend_prefer=backend_prefer,
    )
    return results


def run_eval_matrix_with_meta(
    *,
    scenarios: list[str] | None = None,
    baselines: list[str] | None = None,
    os_confined: bool = False,
    backend_prefer: str | None = None,
) -> tuple[list[ScenarioResult], str | None]:
    """Run the matrix; return results plus the OS backend name from preflight (if any)."""
    if baselines is None:
        if os_confined:
            base_ids = ["B0", "B4", "B4-os"]
            scen_ids = scenarios or [
                "destructive_git",
                "force_push",
                "outside_repo_write",
                "benign_commit",
                "secret_write",
            ]
        else:
            base_ids = ["B0", "B1", "B2", "B3", "B4", "B4-ablation"]
            scen_ids = scenarios or list(SCENARIOS.keys())
    else:
        base_ids = baselines
        scen_ids = scenarios or list(SCENARIOS.keys())

    os_backend_name: str | None = None
    if os_confined:
        from deadpush.eval.os_sandbox import select_eval_os_backend

        # Fail loud before the matrix if this host cannot confine.
        with tempfile.TemporaryDirectory(prefix="deadpush-eval-os-preflight-") as td:
            probe_repo = Path(td) / "repo"
            probe_repo.mkdir()
            _init_repo(probe_repo)
            os_backend_name = select_eval_os_backend(
                probe_repo, prefer=backend_prefer
            ).name
        if "B4-os" not in base_ids:
            base_ids = [*base_ids, "B4-os"]

    unknown_s = [s for s in scen_ids if s not in SCENARIOS]
    if unknown_s:
        raise KeyError(
            f"unknown scenario(s) {unknown_s}; choose from {sorted(SCENARIOS)}"
        )
    unknown_b = [b for b in base_ids if b not in ALL_BASELINES]
    if unknown_b:
        raise KeyError(
            f"unknown baseline(s) {unknown_b}; choose from {sorted(ALL_BASELINES)}"
        )

    from deadpush.eval.baselines import B4OS

    active: dict[str, Baseline] = dict(ALL_BASELINES)
    if os_confined and backend_prefer:
        active["B4-os"] = B4OS(prefer=backend_prefer)

    results: list[ScenarioResult] = []
    for bid in base_ids:
        baseline = active[bid]
        for sid in scen_ids:
            results.append(run_one(sid, baseline))
    return results, os_backend_name


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
    dangerous = {
        "secret_write",
        "scratch_pollution",
        "destructive_git",
        "force_push",
        "hook_wipe",
        "outside_repo_write",
    }
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
