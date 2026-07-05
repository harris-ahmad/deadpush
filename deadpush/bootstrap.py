"""deadpush-managed bootstrap artifacts — exempt from self-sabotage guardrails.

When ``protect`` runs it creates CI workflows, ignore files, IDE MCP config, and
GPC snippets. Without an allowlist the guardian treats its own scaffolding as
agent attacks (sensitive config / LLM context) and enters an intervention loop.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

# Exact repo-relative paths written by protect/configure.
BOOTSTRAP_EXACT_PATHS: frozenset[str] = frozenset({
    ".github/workflows/deadpush-guard.yml",
    ".cursor/rules/deadpush-gpc.mdc",
})

# Prefixes always owned by deadpush (state, quarantine, etc.).
BOOTSTRAP_PREFIXES: tuple[str, ...] = (
    ".deadpush/",
    ".deadpush-quarantine/",
    ".deadpush-archive/",
    ".deadpush-config-backups/",
)

# Tooling ignore files merged by protect — not LLM context pollution.
PROTECT_IGNORE_FILES: frozenset[str] = frozenset({
    ".cursorignore",
    ".claudeignore",
})

BOOTSTRAP_MANIFEST = ".deadpush/bootstrap_paths.json"


def _normalize_rel(rel_path: str) -> str:
    rel = rel_path.replace("\\", "/").strip()
    while rel.startswith("./"):
        rel = rel[2:]
    if rel.startswith("/"):
        rel = rel[1:]
    return rel


def is_bootstrap_path(rel_path: str, repo_root: Path | str | None = None) -> bool:
    """True when *rel_path* is a deadpush-managed bootstrap artifact."""
    rel = _normalize_rel(rel_path)
    if rel in BOOTSTRAP_EXACT_PATHS:
        return True
    if any(rel.startswith(prefix) for prefix in BOOTSTRAP_PREFIXES):
        return True
    name = Path(rel).name.lower()
    if name in PROTECT_IGNORE_FILES:
        return True
    if repo_root is not None:
        root = Path(repo_root).resolve()
        manifest = root / BOOTSTRAP_MANIFEST
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                for entry in data.get("paths", []):
                    pat = str(entry).replace("\\", "/")
                    if rel == pat or fnmatch(rel, pat):
                        return True
            except Exception:
                pass
    return False


def record_bootstrap_paths(repo_root: Path, paths: list[str]) -> Path:
    """Persist paths touched by protect (informational + manifest lookup)."""
    root = Path(repo_root).resolve()
    manifest = root / BOOTSTRAP_MANIFEST
    manifest.parent.mkdir(parents=True, exist_ok=True)
    existing: list[str] = []
    if manifest.exists():
        try:
            existing = list(json.loads(manifest.read_text(encoding="utf-8")).get("paths", []))
        except Exception:
            pass
    merged = sorted(set(existing) | {_normalize_rel(p) for p in paths})
    payload = {
        "paths": merged,
        "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return manifest


def default_protect_bootstrap_paths() -> list[str]:
    """Paths protect/configure typically create or update."""
    return sorted({
        *BOOTSTRAP_EXACT_PATHS,
        *PROTECT_IGNORE_FILES,
        ".gitignore",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".cursor/mcp.json.deadpush.bak",
        ".vscode/mcp.json.deadpush.bak",
    })
