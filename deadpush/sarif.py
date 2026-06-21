"""
Enhanced SARIF v2.1.0 generator for deadpush.

Production-ready output for IDEs and GitHub Advanced Security.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .graph import DeadSymbol, DebrisFile


def generate_sarif(
    dead_symbols: list[DeadSymbol],
    debris: list[DebrisFile],
    repo_root: Path,
) -> dict[str, Any]:
    results = []

    for d in debris:
        level = "error" if d.block_push else "warning"
        results.append({
            "ruleId": f"deadpush/debris/{d.category}",
            "level": level,
            "message": {
                "text": d.suggestion,
                "markdown": f"**Category:** {d.category}\n\n{d.suggestion}\n\n**Reasons:**\n" +
                            "\n".join(f"- {r}" for r in d.reasons)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": d.path,
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": {
                "deadpush_category": d.category,
                "confidence": round(d.confidence, 3),
                "block_push": d.block_push
            }
        })

    for ds in dead_symbols:
        level = "warning" if ds.tier in ("definite", "probable") else "note"
        results.append({
            "ruleId": f"deadpush/deadcode/{ds.tier}",
            "level": level,
            "message": {
                "text": f"{ds.symbol.name} is {ds.tier} dead code",
                "markdown": f"**Symbol:** `{ds.symbol.name}`\n**Tier:** {ds.tier}\n**Confidence:** {ds.confidence*100:.0f}%\n\n" +
                            "\n".join(f"- {r}" for r in ds.reasons)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(Path(ds.symbol.path).relative_to(repo_root)),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": ds.symbol.line,
                        "startColumn": 1
                    }
                }
            }],
            "properties": {
                "deadpush_tier": ds.tier,
                "confidence": round(ds.confidence, 3),
                "kind": ds.symbol.kind,
                "safe_to_delete": ds.safe_to_delete,
                "delete_order": ds.delete_order
            }
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "deadpush",
                    "version": "0.3.0",
                    "informationUri": "https://github.com/harris-ahmad/deadpush",
                    "rules": [
                        {
                            "id": "deadpush/debris/llm_context_file",
                            "name": "LLM Context File",
                            "shortDescription": {"text": "AI coding assistant context/instructions file committed to repository"},
                            "defaultConfiguration": {"level": "error"}
                        },
                        {
                            "id": "deadpush/deadcode/definite",
                            "name": "Definite Dead Code",
                            "shortDescription": {"text": "Code unreachable from any production entry point"},
                            "defaultConfiguration": {"level": "warning"}
                        },
                        {
                            "id": "deadpush/deadcode/ai_regenerated_duplicate",
                            "name": "AI Regenerated Duplicate",
                            "shortDescription": {"text": "File structurally similar to another (likely LLM-regenerated)"},
                            "defaultConfiguration": {"level": "warning"}
                        }
                    ]
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat()
            }]
        }]
    }
    return sarif


def write_sarif(sarif_data: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
