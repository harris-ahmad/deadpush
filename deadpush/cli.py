"""
deadpush CLI - Production level with Rich UI, Safe Archive, Context Cleaner, etc.

This is the complete, advanced CLI with all "wow" features implemented.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click

from .config import load_config
from .crawler import iter_source_files
from .debris import DebrisDetector
from .graph import (
    CallGraph,
    DeadSymbol,
    DebrisFile,
    Edge,
    Symbol,
    make_symbol_id,
    FileGraph,
    FunctionDef,
    CallEdge,
    build_repo_call_graph,
)
from .languages.base import CallSite
from .report import generate_markdown_report, generate_json_report

from .ui import (
    is_rich_available,
    print_blocking_warning,
    print_error,
    print_header,
    print_scan_summary,
    print_success,
    print_warning,
    create_debris_table,
    create_dead_symbols_tree,
)


def _auto_merge_ignore_files(repo_root: Path, new_patterns: set[str]):
    """Smartly merge patterns into .cursorignore, .claudeignore, and .gitignore."""
    ignore_files = [".cursorignore", ".claudeignore", ".gitignore"]

    for ignore_name in ignore_files:
        ignore_path = repo_root / ignore_name
        existing = set()

        if ignore_path.exists():
            try:
                existing = {line.strip() for line in ignore_path.read_text().splitlines() if line.strip() and not line.startswith("#")}
            except Exception:
                continue

        to_add = new_patterns - existing
        if to_add:
            with ignore_path.open("a", encoding="utf-8") as f:
                f.write("\n# Added by deadpush protect\n")
                for pattern in sorted(to_add):
                    f.write(f"{pattern}\n")
            print(f"  → Updated {ignore_name} with {len(to_add)} patterns")

# Try importing rich-dependent modules
try:
    from rich.console import Console
    RICH_CONSOLE = Console()
except ImportError:
    RICH_CONSOLE = None


# =============================================================================
# Core Scan Logic (reused by multiple commands)
# =============================================================================

def _resolve_callee_to_symbol(
    call: CallSite,
    file_symbols: dict[str, Symbol],
    file_imports: dict[str, str],
    all_symbols: dict[str, Symbol],
    current_file: str
) -> str | None:
    """Best-effort resolution of a CallSite to an existing symbol id.

    Tries (in order):
    1. Exact match on callee name within current file (local function/method)
    2. Method on same receiver if tracked (very basic)
    3. Imported name resolution (from file_imports)
    4. Global / other file symbol name match (last resort)
    This is still heuristic (no full type tracking or points-to), but
    dramatically better than raw string edges for call-graph integrity.
    """
    if not call.callee:
        return None

    callee = call.callee.strip()

    # 1. Local exact match in current file
    local_id = make_symbol_id(current_file, callee)
    if local_id in file_symbols:
        return local_id

    # 2. Method resolution using receiver (basic intra-file or imported)
    if call.is_method and call.receiver:
        recv = call.receiver.strip()
        # Common self/this resolution: look for methods on classes in file
        for sid, sym in file_symbols.items():
            if sym.kind in ("method", "function") and sym.name == callee:
                # Heuristic: if receiver is this/self or class name prefix
                if recv in ("this", "self") or any(c in sid for c in [recv, "." + recv]):
                    return sid
        # Try receiver as module prefix from imports
        if recv in file_imports:
            mod = file_imports[recv]
            candidate = f"{mod}::{callee}"  # rough
            for sid in all_symbols:
                if callee in sid and mod in sid:
                    return sid

    # 3. Direct import resolution
    if callee in file_imports:
        mod = file_imports[callee]
        for sid, sym in all_symbols.items():
            if sym.name == callee and mod in sid:
                return sid

    # 4. Fallback: any symbol with matching name (across files) - low confidence
    # Prefer same basename file
    candidates = []
    base = Path(current_file).stem
    for sid, sym in all_symbols.items():
        if sym.name == callee:
            if base in sid:
                candidates.insert(0, sid)
            else:
                candidates.append(sid)
    if candidates:
        return candidates[0]

    return None


_CONFIDENCE_ORDER: dict[str, int] = {
    "high": 0,
    "medium": 1,
    "low": 2,
    "uncertain": 3,
}


def _filter_by_confidence(
    dead_symbols: list[DeadSymbol],
    config,
    aggressive: bool = False,
    show_uncertain: bool = False,
    min_confidence: str | None = None,
) -> list[DeadSymbol]:
    """Filter dead symbols by confidence tier.

    Default (agent-safe, conservative): only high-confidence (alive_score <= 0.2).
    --aggressive: drop to low + show uncertain.
    --min-confidence: explicit override.
    """
    if aggressive:
        effective_min = "low"
        effective_show_uncertain = True
    else:
        effective_min = min_confidence or config.dead_code.min_confidence
        effective_show_uncertain = show_uncertain or config.dead_code.show_uncertain

    threshold = _CONFIDENCE_ORDER.get(effective_min, 0)

    filtered = []
    for ds in dead_symbols:
        tier_idx = _CONFIDENCE_ORDER.get(ds.tier_new, 3)
        if tier_idx > threshold:
            continue
        if not effective_show_uncertain and ds.tier_new == "uncertain":
            continue
        filtered.append(ds)

    return filtered


def _run_full_analysis(config, explicit_entries=None, max_depth=-1, use_rich=True, check_imports=True,
                      aggressive=False, show_uncertain=False, min_confidence=None):
    """Internal function that performs the full analysis."""
    from .entrypoints import resolve_entry_points
    from .languages import get_enabled_plugins
    from .reachability import compute_reachability
    from .scorer import score_symbol, build_scorer

    plugins = get_enabled_plugins(config)
    files = list(iter_source_files(config.repo_root, config))

    graph = CallGraph()
    per_file_graphs: dict[str, dict[str, Any]] = {}
    all_imports: list[tuple[str, str]] = []

    for f in files:
        if not f.is_text:
            continue
        plugin = None
        for p in plugins.values():
            if f.path.suffix.lower() in p.extensions:
                plugin = p
                break
        if not plugin:
            continue
        try:
            tree = plugin.parse(f.path.read_bytes(), str(f.path))
            file_path = str(f.path)

            for sym in plugin.extract_symbols(tree, file_path):
                graph.add_symbol(sym)

            file_symbols = {s.id: s for s in graph.symbols.values() if s.path == file_path}
            file_imports: dict[str, str] = {}
            try:
                for imp in plugin.extract_imports(tree, file_path):
                    if imp.module:
                        for n in imp.names:
                            if n != "*":
                                file_imports[n] = imp.module
                        if imp.level == 0:
                            all_imports.append((imp.module, f.path.suffix))
            except Exception:
                pass

            rich_calls: list[dict[str, Any]] = []
            for call in plugin.extract_call_sites(tree, file_path):
                resolved_id = _resolve_callee_to_symbol(
                    call, file_symbols, file_imports, graph.symbols, file_path
                )
                target = resolved_id or call.callee or call.raw_callee_text
                conf = 0.95 if resolved_id else 0.75
                graph.add_edge(Edge(src=call.caller_id, dst=target, kind="calls", confidence=conf))

                rich_calls.append({
                    "caller_id": call.caller_id,
                    "callee_name": call.callee,
                    "callee_id": resolved_id,
                    "line": call.line,
                    "snippet": "",
                    "usage": "call",
                    "binding": call.receiver,
                    "package": file_imports.get(call.receiver or "") if call.receiver else None,
                })

            file_functions: list[dict[str, Any]] = []
            for sym in plugin.extract_symbols(tree, file_path):
                if sym.kind in ("function", "method", "class"):
                    file_functions.append({
                        "id": sym.id,
                        "name": sym.name,
                        "qualified_name": getattr(sym, "qualified_name", sym.name),
                        "line_start": sym.line,
                        "line_end": getattr(sym, "line_end", sym.line),
                        "is_entry_point": sym.is_entry_point,
                    })

            per_file_graphs[file_path] = {
                "language": plugin.__class__.__name__.replace("Plugin", "").lower(),
                "imports": [],
                "bindings": {},
                "functions": file_functions,
                "calls": rich_calls,
            }

        except Exception:
            continue

    try:
        repo_graph = build_repo_call_graph(per_file_graphs)
        graph.files_graph = per_file_graphs
        graph.function_index = repo_graph.get("function_index", {})
        graph.call_edges = repo_graph.get("call_edges", [])
        graph.entry_points = repo_graph.get("entry_points", [])
    except Exception:
        pass

    roots = resolve_entry_points(graph, files, plugins, config)
    reachability = compute_reachability(graph, roots, config)

    # Build multi-factor scorer
    file_paths = [f.path for f in files if f.is_text]
    try:
        scorer = build_scorer(
            config=config,
            graph=graph,
            roots=set(roots),
            all_file_paths=file_paths,
            custom_registrations=config.dead_code.custom_registrations,
        )
    except Exception:
        scorer = None

    dead_symbols = []
    for sym_id in list(reachability.unreachable) + list(reachability.uncertain):
        sym = graph.get_symbol(sym_id)
        if sym:
            scored = score_symbol(sym, graph, reachability, config, scorer=scorer)
            if scored:
                dead_symbols.append(scored)

    # Filter by confidence tier
    dead_symbols = _filter_by_confidence(dead_symbols, config, aggressive=aggressive,
                                          show_uncertain=show_uncertain, min_confidence=min_confidence)

    detector = DebrisDetector(config)
    debris = detector.scan(files)

    # Test quality analysis
    try:
        from .tests import TestAnalyzer
        test_analyzer = TestAnalyzer()
        test_issues = test_analyzer.analyze_batch(files)
    except Exception:
        test_issues = []

    # Security boundary scan
    try:
        from .security import SecurityScanner
        ss = SecurityScanner(config.repo_root)
        sec_report = ss.scan_and_report(files)
    except Exception:
        sec_report = None

    # Stale comment detection
    try:
        from .comments import StaleCommentDetector
        cd = StaleCommentDetector()
        stale_docs = cd.analyze_batch(files)
    except Exception:
        stale_docs = []

    # Architecture layer enforcement
    try:
        from .layers import LayerEnforcer
        enforcer = LayerEnforcer()
        layer_violations = enforcer.analyze_batch(files)
    except Exception:
        layer_violations = []

    # Complexity gate: check for significant increases from baseline
    try:
        from .complexity import ComplexityTracker
        tracker = ComplexityTracker()
        complexity_alerts = []
        for f in files:
            if f.is_text:
                alert = tracker.check_complexity(str(f.rel_path), f.path)
                if alert:
                    complexity_alerts.append(alert)
    except Exception:
        complexity_alerts = []

    # Import hallucination validation (opt-in network check)
    if check_imports:
        try:
            from .imports import ImportValidator
            validator = ImportValidator()
            hallucinated = validator.validate_batch(all_imports)
            for h in hallucinated:
                from .graph import DebrisFile
                debris.append(DebrisFile(
                    path="(external import)",
                    category=h["category"],
                    confidence=h["confidence"],
                    reasons=[h["reason"]],
                    block_push=False,
                    suggestion=h.get("suggestion", ""),
                ))
        except Exception:
            pass

    return {
        "graph": graph,
        "debris": debris,
        "dead_symbols": dead_symbols,
        "reachability": reachability,
        "files": files,
        "roots": roots,
        "complexity_alerts": complexity_alerts,
        "test_issues": test_issues,
        "stale_docs": stale_docs,
        "layer_violations": layer_violations,
        "security_report": sec_report,
    }


# =============================================================================
# CLI Commands
# =============================================================================
@click.group()
@click.version_option(package_name="deadpush")
def main():
    """deadpush — Guardrails for the vibe coding era."""
    pass


@main.command("clean")
@click.option("--safe", is_flag=True, default=True, help="Move files to archive instead of deleting (recommended)")
@click.option("--dry-run", is_flag=True, help="Show what would be done without making changes")
@click.option("--force", is_flag=True, help="Actually delete files (dangerous)")
def cmd_clean(safe, dry_run, force):
    """
    Clean dead code and debris.

    By default uses --safe mode: moves problematic files to .deadpush-archive/
    with full explanations instead of deleting them.
    """
    config = load_config()
    result = _run_full_analysis(config)
    debris = result["debris"]
    dead = result["dead_symbols"]

    all_issues = debris + [d for d in dead]  # simplified

    if not all_issues:
        print_success("Nothing to clean. Your repo looks healthy!")
        return

    if dry_run:
        click.echo(f"Would process {len(all_issues)} items.")
        return

    if safe and not force:
        archive_dir = config.repo_root / ".deadpush-archive" / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_dir.mkdir(parents=True, exist_ok=True)

        moved = []
        for item in all_issues:
            path = Path(item.path if hasattr(item, 'path') else item.symbol.path)
            if path.exists():
                dest = archive_dir / path.name
                shutil.move(str(path), str(dest))
                moved.append(str(path))

        # Write explanation report
        report_path = archive_dir / "CLEANUP_REPORT.md"
        report_path.write_text(f"# deadpush Safe Archive\n\nMoved {len(moved)} items on {datetime.now()}.\n\n" + 
                               "\n".join([f"- {m}" for m in moved]))

        print_success(f"Safely archived {len(moved)} items to {archive_dir}")
        print_warning("Review the archive before permanently deleting anything.")
    else:
        print_error("Hard delete mode is disabled by default for safety. Use --safe (default) or --force if you really mean it.")


@main.command("clean-context")
def cmd_clean_context():
    """
    Generate ignore patterns and a ready-to-paste message for Claude / Cursor / Windsurf.

    This is extremely useful while vibe coding.
    """
    config = load_config()
    result = _run_full_analysis(config)
    debris = result["debris"]
    dead = result["dead_symbols"]

    ignore_patterns = set()
    for d in debris:
        if d.category in ("llm_context_file", "vibe_scratchpad", "duplicate_file"):
            ignore_patterns.add(str(Path(d.path).name))
            ignore_patterns.add(f"**/{Path(d.path).name}")

    for ds in dead:
        ignore_patterns.add(f"**/{Path(ds.symbol.path).name}")

    click.echo("\n# Recommended patterns for .cursorignore / .claudeignore / .gitignore\n")
    for p in sorted(ignore_patterns):
        click.echo(p)

    click.echo("\n--- Copy-paste this into your AI chat ---\n")
    click.echo("Please ignore all files matching these patterns. They have been identified as dead code or semantic debris by deadpush static analysis.")
    click.echo("This will help keep my context clean and focused on production code.")


@main.command("debris")
def cmd_debris():
    """Run only debris detection with nice output."""
    config = load_config()
    files = list(iter_source_files(config.repo_root, config))
    detector = DebrisDetector(config)
    debris = detector.scan(files)

    if is_rich_available():
        table = create_debris_table(debris)
        RICH_CONSOLE.print(table)
    else:
        for d in debris:
            click.echo(f"{d.path} - {d.category}")


@main.command("watch")
def cmd_watch():
    """Watch the repository for new debris in real time (great while vibe coding)."""
    from .watch import start_watch
    start_watch()


@main.command("guard")
@click.option("--no-intervention", is_flag=True, help="Warning mode only (no blocking/quarantine)")
@click.option("--daemon", is_flag=True, help="Run as background daemon")
@click.option("--strict", is_flag=True, help="Enable strict intervention mode")
def cmd_guard(no_intervention, daemon, strict):
    """
    Start the AI Agent Guardian.

    This is the core always-on protection while using AI coding agents.
    """
    from .guard import run_guardian
    intervention = not no_intervention
    run_guardian(intervention=intervention, daemon=daemon, strict=strict)


@main.command("protect")
@click.option("--enable", is_flag=True, help="Enable persistent background guardian (auto-starts daemon after setup)")
@click.option("--daemon", is_flag=True, help="Start the guardian as a persistent background daemon after performing full setup")
def cmd_protect(enable, daemon):
    """
    One-command setup to protect your vibe coding workflow.

    This is the primary "set it and forget it" command. It:
    - Installs a git pre-push hook for safety
    - Auto-updates .cursorignore / .claudeignore / .gitignore with AI/dead-code patterns
    - (with --daemon / --enable) Starts the real-time AI Agent Guardian in the background
      (survives terminal close, handles multi-agent activity)

    Run this once per repo (or after major changes) then walk away.
    The guardian will monitor, score, quarantine dangerous files autonomously.
    """
    config = load_config()

    start_background = bool(enable or daemon)

    print_header("deadpush Protect", "One-command setup for AI Agent Guardian (persistent background protection)")

    # 1. Install git hooks (pre-push + pre-commit)
    print("\n[1/3] Installing git hooks (pre-push + pre-commit)...")
    try:
        from .hooks import install_hook
        install_hook(config.repo_root)
    except Exception as e:
        print_warning(f"Git hook installation issue: {e}")
        print_warning("  (Tip: ensure this is a git repo with .git/hooks/)")
    try:
        from .hooks import install_precommit_hook
        install_precommit_hook(config.repo_root)
        print("  Also installed pre-commit guardrail hook.")
    except Exception as e:
        print_warning(f"Pre-commit hook installation issue: {e}")
    try:
        from .hooks import setup_mcp_discovery
        setup_mcp_discovery(config.repo_root)
        print("  Agent auto-discovery configured (.cursor/mcp.json, .vscode/mcp.json).")
    except Exception as e:
        print_warning(f"MCP discovery setup issue: {e}")

    # 2. Generate + merge smart ignore patterns into the real ignore files
    #    (this is the key hands-off part - users no longer have to manually curate)
    print("\n[2/3] Updating smart ignore files (.cursorignore, .claudeignore, .gitignore)...")
    try:
        result = _run_full_analysis(config)
        debris = result.get("debris", [])
        suggestions = {str(Path(d.path).name) for d in debris if d.category in ("llm_context_file", "vibe_scratchpad", "hardcoded_secret", "chat_export", "duplicate_file")}
        # Always include core high-risk AI agent / temp / quarantine patterns
        core_patterns = {
            "claude.md", ".cursorrules", ".claude_instructions", ".copilot-instructions.md",
            "windsurf_rules.md", "agents.md", "llm_context.txt", "ai_prompt.md",
            ".deadpush-autoignore", ".deadpush-quarantine/", ".deadpush-archive/",
            "**/scratch*.md", "**/temp*.py", "**/tmp*.go", "**/playground.*",
            "node_modules/", "__pycache__/", ".venv/", "target/", "dist/",
        }
        to_merge = suggestions | core_patterns
        _auto_merge_ignore_files(config.repo_root, to_merge)
        print_success("  Smart ignores merged/updated.")
    except Exception as e:
        print_warning(f"  Ignore file update skipped (non-fatal): {e}")

    # 3. Optionally start the persistent guardian in background + set up agent-native MCP control
    print("\n[3/3] Guardian + Agent Control setup...")
    if start_background:
        print("Starting AI Agent Guardian in persistent background (daemon) mode...")
        print("  (Survives terminal close/logout. Use `deadpush status` to inspect.)")

        # Ensure directories for the Intercept/MCP write guardrails (for agents using deadpush mcp)
        try:
            from .intercept import STAGING_DIR, FEEDBACK_DIR, GUARDRAIL_DIR, QUARANTINE_DIR
            for d in [GUARDRAIL_DIR, STAGING_DIR, FEEDBACK_DIR, QUARANTINE_DIR]:
                (config.repo_root / d).mkdir(parents=True, exist_ok=True)
            print("  Created agent write staging/feedback directories under .deadpush/")
        except Exception:
            pass

        # Auto-start helpers for reboot survival (AGENT priority 2)
        try:
            from .guard import run_guardian, setup_autostart
            autostart_info = setup_autostart(config.repo_root)
            if autostart_info:
                print("\n[Auto-start for reboots]")
                print(autostart_info)
        except Exception as e:
            print_warning(f"Autostart helper generation skipped (non-fatal): {e}")

        print_success("✅ Protection setup + daemon launch complete!")

        # Prominent MCP / Local Control instructions for AI agents (the key new feature in AGENT.md)
        print("\n=== For your AI coding agents (Claude, Cursor, Windsurf, etc.) ===")
        print("Configure your agent to launch this as its MCP / tool server:")
        print("    deadpush mcp")
        print("")
        print("This gives agents native, guardrailed tools over stdio (MCP protocol):")
        print("  - write_file   : write only if it passes all guardrails (layers, secrets, injection, etc.)")
        print("  - check_file   : preview whether a write would be blocked")
        print("  - get_feedback : see why previous writes were blocked")
        print("  - get_status   : current guardrail configuration")
        print("")
        print("Agents can now safely write code without you in the loop, while the background")
        print("guardian (started above) continues its FS watching + Safety Score.")

        # Launch the main background guardian
        try:
            from .guard import run_guardian
            run_guardian(intervention=True, daemon=True, strict=False)
        except SystemExit:
            pass
        except Exception as e:
            print_warning(f"Daemon launch had issue (try `deadpush guard --daemon`): {e}")
    else:
        print_success("Protection setup complete (hooks + ignores).")
        print("Guardian NOT started in background.")
        print("  Start with: deadpush protect --daemon  (or --enable)")
        print("")
        print("For AI agents, also tell them to use:")
        print("    deadpush mcp")
        print("as their tool server (gives them guardrailed writes).")




# =============================================================================
# Cross-Verification Command (additional manual verification layer)
# This helps users audit the integrity of the static analysis results.
# It performs simple but exhaustive textual reference search across the
# discovered source files and compares against the static call graph results.
# =============================================================================
@main.command("verify")
@click.option("--format", "fmt", type=click.Choice(["rich", "text", "json"]), default="rich")
@click.option("--min-confidence", type=float, default=0.8, help="Only verify dead symbols above this static confidence")
@click.option("--include-tests", is_flag=True, help="Also search in test files (often contain references)")
def cmd_verify(fmt, min_confidence, include_tests):
    """Cross-verify dead code results with textual reference search.

    For every symbol the static analysis marked as dead, we do an
    exhaustive (but simple) search for the symbol name in all source files.
    Discrepancies are reported so you can manually decide if the static
    analysis missed something (dynamic dispatch, string references, etc.)
    or if the textual match is spurious (comments, other languages, tests).

    This is *not* a replacement for the static analysis -- it is a second
    opinion / manual verification aid, exactly as requested for trust in
    the integrity of `deadpush scan`.
    """
    config = load_config()
    result = _run_full_analysis(config)
    dead = result["dead_symbols"]

    if not dead:
        print_success("No dead symbols reported by static analysis. Nothing to cross-verify.")
        return

    # Collect candidates above threshold
    candidates = [d for d in dead if d.confidence >= min_confidence]
    if not candidates:
        print_warning(f"No dead symbols with confidence >= {min_confidence}")
        return

    print_header("Cross-Verification of Dead Symbols", f"Static analysis vs. textual references (threshold {min_confidence})")

    # Prepare source files for search (reuse crawler, optionally filter tests)
    all_files = list(iter_source_files(config.repo_root, config))
    search_files = []
    for fi in all_files:
        if not include_tests and any(t in str(fi.rel_path).lower() for t in ["test", "spec", "__tests__"]):
            continue
        if fi.is_text:
            search_files.append(fi)

    discrepancies = []
    verified_dead = 0

    for ds in candidates:
        sym = ds.symbol
        name = sym.name
        # Simple but exhaustive textual search (word boundary, case sensitive for now)
        # We count occurrences that are not the definition line itself.
        references = []
        for fi in search_files:
            try:
                text = fi.path.read_text(encoding="utf-8", errors="ignore")
                lines = text.splitlines()
                for i, line in enumerate(lines, 1):
                    if i == sym.line and str(fi.path) == sym.path:
                        continue  # definition itself
                    # Use word boundary-ish search (handles .name( and name( etc.)
                    pattern = rf'\b{name}\b'
                    if re.search(pattern, line):
                        references.append((str(fi.rel_path), i, line.strip()[:80]))
            except Exception:
                continue

        ref_count = len(references)
        if ref_count > 0:
            discrepancies.append({
                "symbol": sym,
                "tier": ds.tier,
                "confidence": ds.confidence,
                "references": references,
                "ref_count": ref_count
            })
        else:
            verified_dead += 1

    # Report
    if fmt == "json":
        data = {
            "verified_as_dead": verified_dead,
            "potential_misses": len(discrepancies),
            "discrepancies": [
                {
                    "symbol": d["symbol"].name,
                    "path": d["symbol"].path,
                    "tier": d["tier"],
                    "static_confidence": d["confidence"],
                    "textual_references_found": d["ref_count"],
                    "examples": d["references"][:3]
                } for d in discrepancies
            ]
        }
        click.echo(json.dumps(data, indent=2))
        return

    print(f"Static analysis marked {len(candidates)} symbols as dead (>= {min_confidence} confidence).")
    print(f"  - {verified_dead} have ZERO textual references outside their definition (high confidence dead).")
    print(f"  - {len(discrepancies)} have textual references (investigate these).")

    if discrepancies:
        print("\nDiscrepancies (textual references found for 'dead' symbols):")
        for d in discrepancies[:30]:  # limit output
            sym = d["symbol"]
            print(f"\n{sym.path}:{sym.line}  {sym.name}  ({d['tier']}, {d['confidence']*100:.0f}%)")
            print(f"  Found {d['ref_count']} textual matches. Examples:")
            for ref_path, ref_line, snippet in d["references"][:3]:
                print(f"    {ref_path}:{ref_line}  {snippet}")

        if len(discrepancies) > 30:
            print(f"\n... and {len(discrepancies)-30} more. Use --format json for full data.")

    print("\nInterpretation guide:")
    print("  - Textual matches in tests, docs, or strings are often false positives for liveness.")
    print("  - Matches via dynamic code (getattr, eval, string require, etc.) are real misses by static analysis.")
    print("  - Zero matches = very likely truly dead (the static analysis was probably correct).")
    print("\nUse this as a second opinion layer. The static call-graph is now much stronger (structured CallSites + resolution),")
    print("but cross-verification gives you manual audit power.")


# =============================================================================
# Vibe Session Management
# =============================================================================

@main.group("session")
def cmd_session():
    """Manage vibe coding sessions.

    Sessions help you track what happened during a period of AI-assisted coding.
    Start a session before you begin vibe coding, then end it when you're done.
    The guardian can tag all interventions with the active session.
    """
    pass


@cmd_session.command("start")
@click.option("--label", "-l", default="", help="A label for this session (e.g. 'adding stripe payments')")
def cmd_session_start(label):
    """Start a new vibe coding session."""
    from .session import SessionManager
    mgr = SessionManager()
    existing = mgr.get_active_session()
    if existing:
        print_warning(f"Session '{existing.label}' is already active (started {existing.start_time}).")
        if not click.confirm("End it and start a new one?"):
            return
        mgr.end_session()

    session = mgr.start_session(label=label)
    print_success(f"Session started: {session.label}")
    print(f"  ID: {session.id}")
    print(f"  Started: {session.start_time}")
    print()
    print("Run `deadpush session end` to finish this session and get a rollup summary.")
    print("The guardian will tag all interventions during this session.")


@cmd_session.command("end")
def cmd_session_end():
    """End the current vibe session and show a rollup summary."""
    from .session import SessionManager
    mgr = SessionManager()
    active = mgr.get_active_session()
    if not active:
        print_warning("No active session to end.")
        return

    session = mgr.end_session()
    if session:
        print_success("Session ended.")
        print()
        summary = mgr.get_session_summary(session)
        click.echo(summary)
    else:
        print_error("Could not end session.")


@cmd_session.command("status")
def cmd_session_status():
    """Show the active session info."""
    from .session import SessionManager
    mgr = SessionManager()
    active = mgr.get_active_session()
    if not active:
        print_warning("No active session. Start one with `deadpush session start`.")
        return

    print_header("Active Vibe Session", active.label)
    print(f"  Started: {active.start_time}")
    print(f"  Files changed: {len(active.files_changed)}")
    print(f"  Incidents: {len(active.incidents)}")
    print(f"  Safety: {active.safety_score_start} → {active.safety_score_end or active.safety_score_start}")

    if active.files_changed:
        print(f"\n  Files touched ({len(active.files_changed)}):")
        for f in active.files_changed[-10:]:
            print(f"    - {f}")
        if len(active.files_changed) > 10:
            print(f"    ... and {len(active.files_changed) - 10} more")

    if active.incidents:
        print(f"\n  Recent incidents ({len(active.incidents)} total):")
        for inc in active.incidents[-5:]:
            print(f"    - {inc.get('reason', '?')}")


@cmd_session.command("log")
@click.option("--limit", type=int, default=10, help="Number of sessions to show")
def cmd_session_log(limit):
    """Show session history."""
    from .session import SessionManager
    mgr = SessionManager()
    history = mgr.get_session_history(limit=limit)

    if not history:
        print_warning("No completed sessions yet.")
        return

    print_header("Vibe Session History", f"Last {len(history)} sessions")
    for session in history:
        summary = mgr.get_session_summary(session)
        # Only show first line
        first_line = summary.split("\n")[0]
        score_info = ""
        if session.safety_score_end is not None:
            diff = session.safety_score_end - session.safety_score_start
            score_info = f" | Safety: {session.safety_score_start}→{session.safety_score_end} ({'+' if diff >= 0 else ''}{diff})"
        print(f"  {session.id} - {first_line}{score_info}")
        print(f"           {len(session.files_changed)} files, {len(session.incidents)} incidents")
        print()


@main.command("churn")
@click.option("--days", type=int, default=30, help="Analysis window in days (default: 30)")
@click.option("--threshold", type=float, default=0.5, help="Churn score threshold to flag (0-1, default: 0.5)")
@click.option("--format", "fmt", type=click.Choice(["rich", "json"]), default="rich")
def cmd_churn(days, threshold, fmt):
    """Analyze git churn to detect thrashed files.

    High churn files are being rewritten frequently — a common signal of
    AI agents repeatedly modifying the same code, or architectural instability.
    """
    config = load_config()
    from .churn import ChurnAnalyzer
    analyzer = ChurnAnalyzer(config.repo_root, window_days=days)
    report = analyzer.analyze()

    if not report.total_files_analyzed:
        print_warning("No git history found in this repository (or window is too small).")
        return

    if fmt == "json":
        data = {
            "window_days": days,
            "total_commits": report.total_commits_in_window,
            "total_files_analyzed": report.total_files_analyzed,
            "high_churn_files": [
                {
                    "path": f.path,
                    "commit_count": f.commit_count,
                    "author_count": f.author_count,
                    "churn_score": f.churn_score,
                    "reason": f.flag_reason,
                }
                for f in report.high_churn_files
                if f.churn_score >= threshold
            ],
        }
        click.echo(json.dumps(data, indent=2))
        return

    print_header("deadpush Churn Analysis", f"Last {days} days — {report.total_commits_in_window} commits across {report.total_files_analyzed} files")

    flagged = [f for f in report.high_churn_files if f.churn_score >= threshold]
    if not flagged:
        print_success(f"No files exceed churn threshold ({threshold}). Repo looks stable.")
        return

    print_warning(f"{len(flagged)} file(s) with elevated churn (threshold >= {threshold}):")
    print()
    for f in flagged[:25]:
        flag = "🔥" if f.churn_score > 0.7 else "⚠"
        click.echo(f"  {flag}  {f.path}")
        click.echo(f"       {f.commit_count} changes, {f.author_count} author(s), score: {f.churn_score:.2f}")
        click.echo(f"       {f.flag_reason}")
        print()
    if len(flagged) > 25:
        click.echo(f"  ... and {len(flagged) - 25} more. Use --format json for full data.")

    print()
    click.echo("Interpretation:")
    click.echo("  - High churn = files being rewritten frequently. In vibe coding, this means")
    click.echo("    AI agents are thrashing on these files instead of editing in place.")
    click.echo("  - Investigate whether these files need architectural refactoring to become stable.")
    click.echo("  - Run `deadpush scan` to check for dead code and debris in high-churn files.")


@main.command("scan")
@click.option("--entry", "-e", multiple=True, help="Explicit entry points")
@click.option("--depth", type=int, default=-1)
@click.option("--format", "fmt", type=click.Choice(["rich", "markdown", "json", "sarif", "summary"]), default="rich")
@click.option("--output", "-o", type=click.Path(), help="Write report to file")
@click.option("--no-rich", is_flag=True, help="Force plain text output")
@click.option("--check-imports/--no-check-imports", default=True, help="Validate external imports against package registries (default: on)")
@click.option("--aggressive", is_flag=True, help="Include low-confidence dead symbols + uncertain tier (use for cleanup sprints)")
@click.option("--show-uncertain", is_flag=True, help="Show uncertain-tier symbols (alive_score > 0.7, usually abstained)")
@click.option("--min-confidence", type=click.Choice(["high", "medium", "low", "uncertain"]), default=None,
              help="Minimum deadness confidence tier (default: high, overrides --aggressive)")
def cmd_scan(entry, depth, fmt, output, no_rich, check_imports, aggressive, show_uncertain, min_confidence):
    """Full scan with rich output, SARIF, markdown, json etc."""
    config = load_config()
    if entry:
        config.entrypoints.include.extend(entry)

    use_rich = is_rich_available() and not no_rich and fmt in ("rich", "summary")

    if use_rich and fmt != "summary":
        print_header("deadpush Scan", "Analyzing repository for dead code and debris...")

    result = _run_full_analysis(
        config, list(entry) if entry else None, depth, use_rich=use_rich,
        check_imports=check_imports, aggressive=aggressive,
        show_uncertain=show_uncertain, min_confidence=min_confidence,
    )

    debris = result["debris"]
    dead = result["dead_symbols"]
    blocking = [d for d in debris if getattr(d, "block_push", False)]

    if fmt == "sarif":
        from .sarif import generate_sarif, write_sarif
        sarif_data = generate_sarif(dead, debris, config.repo_root)
        out_path = Path(output) if output else Path("deadpush-report.sarif.json")
        write_sarif(sarif_data, out_path)
        print_success(f"SARIF report written to {out_path}")
        return

    if fmt == "markdown":
        md = generate_markdown_report(dead, debris, config.repo_root, result.get("roots"))
        out = Path(output) if output else Path("deadpush-report.md")
        out.write_text(md, encoding="utf-8")
        print_success(f"Markdown report written to {out}")
        return

    if fmt == "json":
        data = generate_json_report(dead, debris, config.repo_root, result.get("roots"))
        out = Path(output) if output else Path("deadpush-report.json")
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print_success(f"JSON report written to {out}")
        return

    if fmt == "rich" and use_rich:
        # Count by tier
        tier_counts: dict[str, int] = {}
        for ds in dead:
            t = getattr(ds, "tier_new", ds.tier)
            tier_counts[t] = tier_counts.get(t, 0) + 1
        tier_str = ", ".join(f"{k}={v}" for k, v in sorted(tier_counts.items()))

        print_scan_summary(
            total_files=len(result["files"]),
            dead_count=len(dead),
            debris_count=len(debris),
            blocking_debris=len(blocking),
            entry_points=len(result.get("roots", [])),
        )
        if tier_str:
            print(f"  Dead symbols by tier: {tier_str}")
        if blocking:
            print_blocking_warning(blocking)
        if debris:
            RICH_CONSOLE.print(create_debris_table(debris))
        if dead:
            RICH_CONSOLE.print(create_dead_symbols_tree(dead))

        # Security boundaries
        sec_report = result.get("security_report")
        if sec_report and sec_report.untested:
            print_warning(f"Security Boundaries: {len(sec_report.untested)} untested security-sensitive operation(s)")
            for sb in sec_report.untested[:6]:
                print(f"  🔐 {sb.file}:{sb.line}  {sb.description} ({sb.category})")

        # Architecture layer violations
        layer_violations = result.get("layer_violations", [])
        if layer_violations:
            print_warning(f"Layer Violations: {len(layer_violations)} import(s) cross architectural boundaries")
            for lv in layer_violations[:6]:
                print(f"  🏛 {lv.file}:{lv.line}  {lv.description[:100]}")

        # Stale documentation issues
        stale_docs = result.get("stale_docs", [])
        if stale_docs:
            by_type: dict[str, list] = {}
            for sd in stale_docs:
                by_type.setdefault(sd.issue_type, []).append(sd)
            parts = []
            for t, items in sorted(by_type.items()):
                parts.append(f"{len(items)} {t.replace('_', ' ')}")
            print_warning(f"Stale Documentation: {', '.join(parts)}")
            for sd in stale_docs[:6]:
                print(f"  📝 {sd.file}:{sd.line}  {sd.description[:90]}")

        # Test quality issues
        test_issues = result.get("test_issues", [])
        if test_issues:
            by_type: dict[str, list] = {}
            for ti in test_issues:
                by_type.setdefault(ti.issue_type, []).append(ti)
            parts = []
            for t, items in sorted(by_type.items()):
                parts.append(f"{len(items)} {t.replace('_', ' ')}")
            print_warning(f"Test Quality: {', '.join(parts)}")
            for ti in test_issues[:8]:
                print(f"  ⚠ {ti.file}:{ti.line}  {ti.description[:90]}")
            if len(test_issues) > 8:
                print(f"  ... and {len(test_issues) - 8} more. Run with --format json for full data.")

        # Complexity alerts
        complexity_alerts = result.get("complexity_alerts", [])
        if complexity_alerts:
            exceeded = [a for a in complexity_alerts if a.get("exceeded")]
            high_initial = [a for a in complexity_alerts if not a.get("exceeded") and a.get("note")]
            if exceeded:
                print_warning(f"Complexity Gate: {len(exceeded)} file(s) exceeded the complexity threshold:")
                for a in exceeded[:10]:
                    print(f"  ⚠ {a['file']}: {a['baseline']} → {a['current']} (+{a['pct_increase']}%)")
                if len(exceeded) > 10:
                    print(f"  ... and {len(exceeded) - 10} more")
            if high_initial:
                print(f"  ℹ {len(high_initial)} file(s) with high initial complexity (first scan)")

        print_success("Scan complete. Run `deadpush clean --safe` to safely archive issues.")
    else:
        complexity_alerts = result.get("complexity_alerts", [])
        exceeded = len([a for a in complexity_alerts if a.get("exceeded")])
        test_issues = len(result.get("test_issues", []))
        stale_docs = len(result.get("stale_docs", []))
        layer_violations = len(result.get("layer_violations", []))
        sec_report = result.get("security_report")
        sec_untested = len(sec_report.untested) if sec_report else 0
        # Count by tier
        tier_counts: dict[str, int] = {}
        for ds in dead:
            t = getattr(ds, "tier_new", ds.tier)
            tier_counts[t] = tier_counts.get(t, 0) + 1
        tier_str = ", ".join(f"{k}={v}" for k, v in sorted(tier_counts.items()))
        click.echo(
            f"Scanned {len(result.get('files', []))} files. "
            f"Found {len(dead)} dead symbols ({tier_str}), {len(debris)} debris, "
            f"{exceeded} complexity alerts, "
            f"{test_issues} test issues, "
            f"{stale_docs} stale docs, "
            f"{layer_violations} layer violations, "
            f"{sec_untested} untested security boundaries."
        )


# Add other commands like install, reachability, etc. as before...
# (For brevity in this implementation, the core new wow features are above)

# =============================================================================
# Status command (polish / usability)
# =============================================================================
@main.command("status")
def cmd_status():
    """Show whether the guardian is running, latest Safety Score, recent incidents, and session info.

    This is the primary way to check on your always-on protector without reading logs manually.
    """
    from .guard import DaemonManager
    pid_dir = Path.home() / ".deadpush"
    pidfile = pid_dir / "guardian.pid"
    lockfile = pid_dir / "guardian.lock"
    dm = DaemonManager(pidfile, lockfile)
    running = dm.is_running()

    print_header("deadpush Status", "AI Agent Guardian - persistent background protection")

    if running:
        try:
            pid = int(pidfile.read_text().strip())
            print_success(f"🟢 Guardian is RUNNING (PID {pid})")
        except Exception:
            print_success("🟢 Guardian is RUNNING")
    else:
        print_warning("🔴 Guardian is NOT currently running.")
        print("   Start it with the hands-off command:")
        print("     deadpush protect --daemon")
        print("   Or:")
        print("     deadpush guard --daemon")

    log = pid_dir / "guardian.log"
    if log.exists():
        try:
            text = log.read_text(errors="ignore")
            lines = text.strip().splitlines()[-40:] if text.strip() else []
            # last score/status line
            last_status = None
            for ln in reversed(lines):
                if "Safety:" in ln or "Score:" in ln or "Status:" in ln:
                    last_status = ln
                    break
            print("\nLatest Safety Score / status (from log):")
            if last_status:
                click.echo("  " + last_status)
            else:
                click.echo("  (no recent score line found)")

            # recent interventions (actionable)
            intervs = [ln for ln in lines if "INTERVENTION" in ln or "QUARANTINED" in ln or "Critical file" in ln]
            if intervs:
                print("\nRecent guardian actions / incidents:")
                for iv in intervs[-6:]:
                    click.echo("  " + iv)
            else:
                print("\nNo intervention actions in recent log tail.")

            print(f"\nLog file: {log}")
            print("Live tail: tail -f " + str(log))
        except Exception as e:
            print_warning(f"Could not parse recent log: {e}")
    else:
        print_warning("No guardian.log found yet (start the guardian to begin logging).")

    print("\nOther checks:")
    print("  - Per-repo quarantines: cd your-repo ; deadpush quarantine list")
    print("  - Full scan: deadpush scan")

    # Show control interface if running
    port_file = Path.home() / ".deadpush" / "guardian.control.port"
    if port_file.exists():
        try:
            port = port_file.read_text().strip()
            print(f"\nLocal Control Interface (for AI agents): http://127.0.0.1:{port}")
            print("  Agents can GET /status, /quarantine-list, /safety-score, etc.")
        except Exception:
            pass


# =============================================================================
# Quarantine management (Priority per AGENT.md - easy review/restore builds trust)
# =============================================================================
@main.group("quarantine")
def cmd_quarantine():
    """Manage files the guardian has quarantined (safer than delete).

    Use these to review what was auto-quarantined and restore if it was a false positive.
    This is critical for "aggressive intervention" without user fear.
    """
    pass


@cmd_quarantine.command("list")
@click.option("--limit", type=int, default=None, help="Max number of entries to show")
def cmd_quarantine_list(limit):
    """List all currently quarantined files with reasons and original locations."""
    from .guard import QuarantineManager
    config = load_config()
    qm = QuarantineManager(config.repo_root)
    entries = qm.list_quarantined()
    if limit:
        entries = entries[:limit]
    if not entries:
        print_success("No files are currently quarantined. Everything looks clean!")
        return

    if is_rich_available():
        try:
            from rich.table import Table
            table = Table(title="Quarantined by deadpush Guardian", box=None)
            table.add_column("Quarantined Name", style="cyan")
            table.add_column("When", style="dim")
            table.add_column("Reason", style="yellow")
            table.add_column("Original Path", style="green")
            for e in entries:
                table.add_row(
                    e["name"],
                    str(e.get("quarantined_at", e.get("mtime", "")))[:19],
                    e.get("reason", "(unknown)")[:60],
                    str(e.get("original_path", "(unknown)")),
                )
            RICH_CONSOLE.print(table)
            print(f"\n{len(entries)} quarantined file(s) in {qm.quarantine_dir}")
        except Exception:
            # fallback plain
            for e in entries:
                click.echo(f"- {e['name']} | {e.get('reason','?')} | orig: {e.get('original_path','?')}")
    else:
        for e in entries:
            click.echo(f"- {e['name']} | reason: {e.get('reason','?')} | would restore to: {e.get('original_path','?')}")
        click.echo(f"\nTotal: {len(entries)} in {qm.quarantine_dir}")


@cmd_quarantine.command("restore")
@click.argument("quarantined_path")
def cmd_quarantine_restore(quarantined_path):
    """Restore a quarantined file to its original location.

    QUARANTINED_PATH can be the filename shown in `list` or full path inside the quarantine dir.
    """
    from .guard import QuarantineManager
    config = load_config()
    qm = QuarantineManager(config.repo_root)
    restored = qm.restore(quarantined_path)
    if restored:
        print_success(f"Restored successfully to: {restored}")
        print_warning("Review the file and consider adding exceptions if this was a false positive.")
    else:
        print_error(f"Could not restore '{quarantined_path}'. Check the name with `deadpush quarantine list`, or the original location may already exist.")


@cmd_quarantine.command("clear")
@click.option("--older-than", "older_than", type=int, default=None, help="Only clear items older than this many days (default: all)")
@click.option("--force", is_flag=True, help="Do not ask for confirmation (dangerous)")
def cmd_quarantine_clear(older_than, force):
    """Permanently delete quarantined files (and their metadata).

    By default clears everything. Use --older-than for pruning old ones.
    """
    from .guard import QuarantineManager
    config = load_config()
    qm = QuarantineManager(config.repo_root)
    if not force:
        msg = "Permanently delete ALL quarantined files" if older_than is None else f"Permanently delete quarantined files older than {older_than} days"
        if not click.confirm(f"{msg}? This cannot be undone."):
            print("Aborted.")
            return
    n = qm.clear(older_than_days=older_than)
    print_success(f"Cleared {n} quarantined item(s).")


@main.group("hooks")
def cmd_hooks():
    """Manage deadpush git hooks."""
    pass


@cmd_hooks.command("install-precommit")
def cmd_hooks_install_precommit():
    """Install the pre-commit guardrail hook.

    Blocks commits with prompt injection, hardcoded secrets,
    security violations, and architecture layer violations.
    """
    config = load_config()
    try:
        from .hooks import install_precommit_hook
        install_precommit_hook(config.repo_root)
        print_success("Pre-commit guardrail hook installed.")
    except Exception as e:
        print_error(f"Failed to install pre-commit hook: {e}")


@cmd_hooks.command("run-precommit")
def cmd_hooks_run_precommit():
    """Run guardrails on staged files (called by the pre-commit hook).

    Exits with code 1 if violations are found, blocking the commit.
    """
    config = load_config()
    from .hooks import run_precommit_guardrails
    passed, violations = run_precommit_guardrails(config.repo_root)
    sys.exit(0 if passed else 1)


@main.command("deps")
@click.option("--registry/--no-registry", default=True, help="Look up registry metadata for new packages (default: on)")
@click.option("--format", "fmt", type=click.Choice(["rich", "text", "json"]), default="rich")
def cmd_deps(registry, fmt):
    """Review dependencies — show new packages added since last commit."""
    config = load_config()
    from .deps import DepsReviewer
    reviewer = DepsReviewer(config.repo_root)

    diff = reviewer.diff_with_head()

    if not diff.added and not diff.changed and not diff.removed:
        click.echo("No dependency changes since HEAD.")
        return

    if fmt == "json":
        import json as _json
        data = {
            "added": [{"name": d.name, "version": d.version, "source": d.source_file} for d in diff.added],
            "removed": [{"name": d.name, "version": d.version, "source": d.source_file} for d in diff.removed],
            "changed": [{"name": o.name, "old_version": o.version, "new_version": n.version, "source": o.source_file} for o, n in diff.changed],
        }
        click.echo(_json.dumps(data, indent=2))
        return

    if diff.removed:
        print_warning(f"Removed ({len(diff.removed)}):")
        for d in diff.removed:
            print_warning(f"  ✂ {d.name} {d.version} ({d.source_file})")

    if diff.changed:
        print_info(f"Changed ({len(diff.changed)}):")
        for o, n in diff.changed:
            print_info(f"  ↕ {o.name} {o.version} → {n.version}")

    if diff.added:
        print_warning(f"New Dependencies ({len(diff.added)}):")
        reviews = reviewer.review_added(diff.added) if registry else []
        review_map = {r["name"]: r for r in reviews}
        for d in diff.added:
            r = review_map.get(d.name)
            if r and r.get("registry_info"):
                info = r["registry_info"]
                first_release = info.get("first_release", "?")
                summary = info.get("summary", "")
                print_warning(f"  ⚡ {d.name} {d.version} ({d.source_file})")
                if summary:
                    click.echo(f"      {summary[:80]}")
                if first_release:
                    click.echo(f"      First release: {first_release}")
            else:
                print_warning(f"  ⚡ {d.name} {d.version} ({d.source_file}) (no registry metadata)")


@main.command("intercept")
@click.option("--daemon", is_flag=True, help="Run as persistent background daemon")
@click.option("--http/--no-http", default=False, help="Also start HTTP API on port 9876 (default: off)")
def cmd_intercept(daemon, http):
    """Start the pre-write file interception daemon.

    Watches .deadpush/staging/ for files written by coding agents.
    Runs guardrails on each file — approves safe writes or blocks dangerous ones
    with structured feedback the agent can read and self-correct from.
    """
    from .intercept import run_intercept
    run_intercept(daemon=daemon, http=http)


@main.command("mcp")
def cmd_mcp():
    """Start the Model Context Protocol server for AI agent integration.

    Runs over stdio. Any MCP-compatible agent (Cursor, Claude Desktop, etc.)
    can connect and call all deadpush capabilities as native tools:
      - write_file / check_file: guardrailed file writing
      - scan: full analysis (dead code, debris, tests, docs, layers, security)
      - get_dead_symbols / get_debris / get_test_issues / get_stale_docs
      - get_layer_violations / get_security_boundaries / get_complexity_alerts
      - clean: remove dead code and debris
      - quarantine_list / quarantine_restore: manage quarantined files
      - get_feedback / get_status / get_safety_score

    All tools return structured JSON. Configure your agent to run: deadpush mcp
    """
    from .mcp_server import run_mcp
    run_mcp()


if __name__ == "__main__":
    main()
