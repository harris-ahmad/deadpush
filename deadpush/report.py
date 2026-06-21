"""
Report generators (markdown + json) for deadpush scan results.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .graph import DeadSymbol, DebrisFile


def generate_markdown_report(
    dead_symbols: list[DeadSymbol],
    debris: list[DebrisFile],
    repo_root: Path,
    roots: list[str] | None = None,
) -> str:
    lines: list[str] = []
    lines.append("# deadpush Report")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Repo: {repo_root}")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- Dead symbols: {len(dead_symbols)}")
    lines.append(f"- Debris items: {len(debris)}")
    blocking = [d for d in debris if getattr(d, "block_push", False)]
    lines.append(f"- Blocking debris: {len(blocking)}")
    lines.append("")

    if dead_symbols:
        lines.append("## Dead Code")
        by_file: dict[str, list[DeadSymbol]] = {}
        for ds in dead_symbols:
            by_file.setdefault(ds.symbol.path, []).append(ds)
        for fpath in sorted(by_file):
            lines.append(f"\n### {fpath}")
            for ds in sorted(by_file[fpath], key=lambda x: x.symbol.line):
                tier = ds.tier.upper()
                lines.append(
                    f"- **{ds.symbol.name}** (line {ds.symbol.line}) — {tier} "
                    f"({ds.confidence*100:.0f}%) — safe={ds.safe_to_delete}"
                )
                for r in ds.reasons[:3]:
                    lines.append(f"  - {r}")
    else:
        lines.append("## Dead Code\n\nNo dead code found. Great!")

    lines.append("\n## Debris")
    if debris:
        for d in sorted(debris, key=lambda x: (not x.block_push, x.category, x.path)):
            flag = "🚫 BLOCK" if d.block_push else "warn"
            lines.append(f"- {d.path} [{d.category}] {flag} conf={d.confidence:.0%}")
            if d.suggestion:
                lines.append(f"  → {d.suggestion}")
    else:
        lines.append("No semantic debris detected.")

    if roots:
        lines.append("\n## Entry Points Used")
        for r in roots[:20]:
            lines.append(f"- {r}")

    lines.append("\n---\n*Report by deadpush — keep your vibe coding safe.*")
    return "\n".join(lines)


def generate_json_report(
    dead_symbols: list[DeadSymbol],
    debris: list[DebrisFile],
    repo_root: Path,
    roots: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "version": "0.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(repo_root),
        "summary": {
            "dead_count": len(dead_symbols),
            "debris_count": len(debris),
            "blocking_debris": len([d for d in debris if getattr(d, "block_push", False)]),
            "entry_points": len(roots or []),
        },
        "dead_symbols": [
            {
                "id": ds.symbol.id,
                "name": ds.symbol.name,
                "kind": ds.symbol.kind,
                "path": ds.symbol.path,
                "line": ds.symbol.line,
                "tier": ds.tier,
                "confidence": ds.confidence,
                "reasons": ds.reasons,
                "safe_to_delete": ds.safe_to_delete,
            }
            for ds in dead_symbols
        ],
        "debris": [
            {
                "path": d.path,
                "category": d.category,
                "confidence": d.confidence,
                "block_push": d.block_push,
                "suggestion": d.suggestion,
                "reasons": d.reasons,
            }
            for d in debris
        ],
        "roots": roots or [],
    }
