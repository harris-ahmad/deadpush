# deadpush

Guardrails for the vibe coding era.

This is the complete production implementation of deadpush as specified.

## Location of full source code

The full advanced Python implementation (all modules: cli.py, graph.py, debris.py, reachability.py, languages/*.py, hook.py, etc.) was built in this project.

See the detailed architecture in the original build prompt for the complete code of each file.

## Quick start

```bash
pip install -e .
deadpush scan
deadpush install
```

## What's included (v0.2+)

- **Beautiful Rich terminal UI** — premium experience with tables, trees, and colored confidence
- **Safe Archive Mode** (`deadpush clean --safe`) — moves problematic files instead of deleting
- **Smart Context Cleaner** (`deadpush clean-context`) — generates ignore patterns + pasteable message for Claude/Cursor
- **Structural duplicate detection** — uses Python AST to catch AI-regenerated near-duplicates
- **High-quality call graph construction** — structured CallSite extraction (receivers, methods, qualified names) + best-effort symbol resolution across imports and files for accurate reachability (much improved over raw-text matching)
- Full reachability-based dead code detection with cross-verification support
- Semantic debris detection (LLM context files, vibe scratchpads, committed secrets, etc.)
- Pre-push git hook that blocks dangerous pushes
- GitHub Action + optional PR commenting
- Optional Anthropic LLM enrichment

## The AI Agent Guardian (Core Value)

The primary command per the project vision is the hands-off one:

```bash
# The single command for full autonomous protection (install + start bg + auto-reboot helpers):
deadpush protect --daemon
# (or --enable ; same effect)

# This does:
# - git pre-push hook install (blocks risky pushes)
# - Auto-merges AI-agent / debris patterns into .cursorignore + .claudeignore + .gitignore
# - Starts (and sets up for reboot) the persistent background guardian
#   (double-fork, file logging only, Safety Score with multi-agent burst detection,
#    rate-limited interventions, auto-quarantine instead of delete, recovery on watcher errors)

# Inspect / control:
deadpush status                 # Is it running? Last score? Recent incidents? Quarantines?
deadpush quarantine list        # Review what was auto-quarantined (with reasons + original paths)
deadpush quarantine restore foo.py   # Put it back (only if original spot free)
deadpush guard --no-intervention   # Watch-only mode (no blocking)

# Manual / re-start the watcher:
deadpush guard --daemon
```

This fulfills the core principle: protection as autonomous and "set-it-and-forget-it" as possible. Users (or their AI agents) run `deadpush protect --daemon` once and can step away while many Claude/Cursor/Windsurf agents work in parallel. The guardian monitors the FS in a detached process, handles bursts intelligently, and only intervenes on real risks (with easy restore).

**Bonus for agents**: A Local Control Interface runs automatically (HTTP on http://127.0.0.1:14242 or the port in `~/.deadpush/guardian.control.port`). Your AI coding agents can query:
- GET /status, /safety-score, /recent-incidents, /quarantine-list
- POST /trigger-light-analysis or restore quarantined files safely

This lets agents self-regulate without you running manual commands.

See `deadpush protect --help` and `deadpush --help` for all options.

## Other Useful Commands

```bash
deadpush scan                 # Full analysis with beautiful output
deadpush clean --safe         # Safely archive issues
deadpush clean-context        # Get ignore patterns for your AI chat
deadpush protect --daemon     # Full auto setup + start persistent guardian (PRIMARY)
deadpush guard --daemon       # Start (or re-start) the background watcher
deadpush status               # Show if guardian running, Safety Score, recent incidents
deadpush verify               # Cross-verify static dead-code results with textual reference search (second opinion layer)
deadpush quarantine list      # Review quarantined files
deadpush quarantine restore <path>  # Restore a quarantined file
```

## Verifying Scan Integrity

The static analysis (`deadpush scan`) now builds proper structured call graphs (see `CallSite` in language plugins + resolver in cli.py). However, no static analysis is perfect (especially with JS/TS dynamic patterns, reflection, etc.).

Use the built-in cross-verifier for an additional manual verification layer:

```bash
deadpush verify --min-confidence 0.8
# or with more context
deadpush verify --format json > verification.json
```

It searches all source files for textual references to symbols the static analysis marked dead and highlights discrepancies. This lets you quickly see:
- Real misses by the call graph (e.g. dynamic `getattr`, string requires).
- Spurious textual matches (tests, comments, similar names).

Treat `deadpush scan` results + `deadpush verify` as strong hints that still benefit from human review.

For the complete source of every .py file, refer to the step-by-step implementation provided during the build.
