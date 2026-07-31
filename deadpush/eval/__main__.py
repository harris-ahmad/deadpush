"""CLI: ``python -m deadpush.eval``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .runner import run_eval_matrix, write_csv, write_overhead_svg, write_summary_md


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Deadpush thesis eval harness (scenarios × baselines)")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("eval_out"),
        help="Output directory for CSV / summary / SVG",
    )
    p.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="Subset of scenario ids (default: all)",
    )
    p.add_argument(
        "--baselines",
        nargs="*",
        default=None,
        help="Subset of baseline ids (default: B0–B4 + ablation)",
    )
    args = p.parse_args(argv)

    try:
        results = run_eval_matrix(scenarios=args.scenarios, baselines=args.baselines)
    except KeyError as e:
        print(f"deadpush.eval: {e}", file=sys.stderr)
        return 2
    out = args.out
    csv_path = write_csv(results, out / "results.csv")
    md_path = write_summary_md(results, out / "summary.md")
    svg_path = write_overhead_svg(results, out / "overhead.svg")
    print(f"wrote {csv_path}")
    print(f"wrote {md_path}")
    print(f"wrote {svg_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
