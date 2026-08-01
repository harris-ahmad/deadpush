"""CLI: ``python -m deadpush.eval``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deadpush.backends.base import SandboxUnavailableError

from .os_sandbox import os_confinement_status
from .runner import (
    run_eval_matrix_with_meta,
    write_csv,
    write_overhead_svg,
    write_summary_md,
)


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
        help="Subset of scenario ids (default: all, or OS subset with --os-confined)",
    )
    p.add_argument(
        "--baselines",
        nargs="*",
        default=None,
        help="Subset of baseline ids (default: B0–B4 + ablation)",
    )
    p.add_argument(
        "--os-confined",
        action="store_true",
        help="Require Seatbelt/bubblewrap and include B4-os (thesis §9)",
    )
    p.add_argument(
        "--backend",
        default=None,
        choices=["seatbelt", "bubblewrap", "linux-sandbox"],
        help="Prefer a specific OS confinement backend with --os-confined",
    )
    p.add_argument(
        "--os-status",
        action="store_true",
        help="Print whether this host can run OS-confined eval and exit",
    )
    args = p.parse_args(argv)

    if args.os_status:
        status = os_confinement_status(Path.cwd())
        print(json.dumps(status, indent=2))
        return 0 if status.get("available") else 1

    try:
        results, os_backend = run_eval_matrix_with_meta(
            scenarios=args.scenarios,
            baselines=args.baselines,
            os_confined=args.os_confined,
            backend_prefer=args.backend,
        )
    except KeyError as e:
        print(f"deadpush.eval: {e}", file=sys.stderr)
        return 2
    except SandboxUnavailableError as e:
        print(f"deadpush.eval: OS confinement unavailable: {e}", file=sys.stderr)
        return 2

    out = args.out
    csv_path = write_csv(results, out / "results.csv")
    md_path = write_summary_md(results, out / "summary.md")
    svg_path = write_overhead_svg(results, out / "overhead.svg")
    print(f"wrote {csv_path}")
    print(f"wrote {md_path}")
    print(f"wrote {svg_path}")
    if os_backend:
        print(f"os_confinement backend: {os_backend}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
