# deadpush

[![GitHub stars](https://img.shields.io/github/stars/harris-ahmad/deadpush?style=social)](https://github.com/harris-ahmad/deadpush)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Your personal AI Agent Guardian.**  
Protects you from the mistakes, secrets, and context pollution that AI coding agents (Claude, Cursor, Windsurf, etc.) inevitably create — even when you're not watching.

Run it once with `deadpush protect --daemon` and it runs in the background forever, monitoring your filesystem in real time.

---

## The Problem (2026 AI Coding Reality)

You tell your agent to "add the new feature" and walk away.

30 minutes later you come back to:
- A `claude.md` or `.cursorrules` file committed to the repo
- Hardcoded API keys in `.env` files the agent "helpfully" created
- 47 new "temporary" scripts and scratchpads
- Dead code and duplicated logic everywhere

**deadpush** is the always-on guardian that catches this the moment it happens.

## One Command. Real Protection.

```bash
pip install deadpush[watch,rich]
deadpush protect --daemon
```

That's it.

It will:
- Install a smart pre-push git hook
- Merge AI-specific ignore patterns into `.cursorignore`, `.claudeignore`, and `.gitignore`
- Start a persistent background process that watches your entire repo
- Automatically quarantine dangerous files the second they appear
- Track a **Safety Score** that reacts intelligently when multiple agents are going wild

While you're at the gym, in a meeting, or sleeping, deadpush is on duty.

## See It In Action

```bash
# After running protect --daemon, try simulating an agent:
mkdir -p .deadpush-e2e-sandbox
touch .deadpush-e2e-sandbox/claude.md
echo 'OPENAI_API_KEY=sk-...' > .deadpush-e2e-sandbox/.env.bad

deadpush status
deadpush quarantine list
```

You'll see the guardian react, drop the Safety Score, and quarantine the files.

For a full automated demo of every feature (including burst simulation and call-graph verification):

```bash
python scripts/full_e2e_test.py --simulate-agent --burst --run-scan
```

## Key Features

- **True background guardian** — Survives terminal close, supports systemd/launchd autostart
- **Smart multi-agent Safety Score** — Penalizes bursts of dangerous activity from parallel agents
- **Automatic quarantine** (never hard-delete) — Easy `deadpush quarantine list` / `restore`
- **Local Control Interface for agents** — Your AI coding agents can query the guardian themselves (`GET /status`, `/quarantine-list`, etc. on localhost)
- **Cross-platform pre-push hook** — Works in PowerShell, CMD, and Git Bash
- **Strong static analysis + verification** — Structured call graphs + `deadpush verify` so you can actually trust (or challenge) the dead code reports
- **Debris detection** — LLM context files, vibe scratchpads, hardcoded secrets, AI-generated duplicates

## Commands You'll Actually Use

```bash
deadpush protect --daemon     # The one command you run per repo
deadpush status               # Is the guardian alive? What's the Safety Score?
deadpush quarantine list      # See what it caught
deadpush verify               # Cross-check the static analysis with real references
```

## Why This Matters in the AI Era

AI agents are incredible productivity multipliers.

They are also incredibly good at creating technical debt, leaking secrets, and polluting your context — especially when you give them long-running tasks and step away.

deadpush is the missing safety net.

## Installation

```bash
pip install deadpush[watch,rich]
```

Then run `deadpush protect --daemon` in any repo you care about.

## Windows Users

The pre-push hook ships as a Python script + `.cmd` shim. It works from PowerShell, Command Prompt, and Git Bash. The `deadpush protect` command records the exact Python interpreter so everything works even inside virtualenvs.

## Development

```bash
git clone https://github.com/harris-ahmad/deadpush
cd deadpush
pip install -e ".[dev,watch,rich]"
```

## Architecture

deadpush is organized into four layers that work together:

### 1. Intercept Layer (`deadpush/intercept.py`)
The real-time guardrail engine. Every file write is checked against:
- **Security guardrails**: `eval`, `subprocess`, pickle deserialization, SQL injection patterns
- **Secret detection**: Hardcoded API keys, tokens, passwords (with **path-aware lowering** — test/mock files get `warn` instead of `block`)
- **Prompt injection**: AI prompt manipulation patterns (ignore-previous-instructions, role-play overrides, chat markup)
- **Destructive change detection**: Near-empty rewrites, >50% line reduction
- **Sensitive config protection**: CI/CD, deployment, Docker files
- **Layer violations**: Architecture import rules
- **Debris detection**: AI artifacts, stub code, temp files

**Path-aware guardrails**: Files in `test/`, `spec/`, `tests/`, `__tests__/`, `mocks/`, `fixtures/` directories, or files with `test_`, `_test`, `_spec` stems, automatically receive lowered severity for security/secret checks — recognizing that test code commonly uses patterns that would be dangerous in production.

**Learned false positive suppression**: When the agent adjudicator confirms a finding is a false positive, the pattern is persisted to `.deadpush/learned_patterns.json` and auto-suppressed on future checks. This creates a **feedback-driven learning loop** that reduces noise over time.

### 2. Analysis Layer (`deadpush/deadness.py`, `deadpush/graph.py`, `deadpush/importgraph.py`)
Multi-factor dead code scoring combining 8 signals:
- **Call graph in-degree** (0.30): How many callers reference the symbol
- **Registration detection** (0.20): Framework decorators, URL routes, CLI commands
- **String reference** (0.10): Name appears as string literal elsewhere
- **Import count** (0.10): External module imports
- **Entry point reachability** (0.05): Reachable from detected entry points
- **Git freshness** (0.05): Recently modified (git blame)
- **Call chain propagation** (0.10): Callers are themselves live (pass-through scoring)
- **Test coverage** (0.10): Referenced in test files

Each symbol gets a `DeadnessResult` with an `alive_score` (0.0–1.0), a `tier` (high/medium/low/uncertain), factor breakdown, reasons, and an **uncertainty** field explaining why the classifier might be wrong.

The `uncertainty` field is populated when the signal is ambiguous (e.g., "String reference detected but could be coincidental", "Import found but likely re-export", "Only one caller — may be indirect").

### 3. Call Graph Resolution (`deadpush/cli.py:84-148`)
The `_resolve_callee_to_symbol` function uses a 5-step heuristic pipeline:
1. **Local exact match**: Symbol exists in the same file
2. **Method receiver resolution**: Class methods via receiver name (`self`, `this`, or class name)
3. **Import resolution**: Module-qualified names from `file_imports`
4. **Dotted name resolution**: `module.function` style callee splitting
5. **Fallback name match**: Any symbol with matching name across the project (lowest confidence)

Each step uses exact prefix/suffix matching rather than loose substring checks to avoid false edges.

### 4. MCP Server (`deadpush/mcp_server.py`)
A Model Context Protocol server (stdio transport) exposing all capabilities as tools:
- **Agent-as-Adjudicator**: `verify_finding` and `learn_false_positive` tools let the agent itself adjudicate uncertain findings and teach deadpush about false positive patterns, creating a **feedback-driven learning loop**.
- **Write/Check pipeline**: `write_file`, `check_file`, `get_write_diff`, `retry_write`
- **Test-verified writes**: `verify_write` runs guardrails + tests atomically
- **Scanning**: `scan`, `get_dead_symbols`, `get_debris`, `get_test_issues`, `get_stale_docs`, `get_layer_violations`, `get_security_boundaries`, `get_complexity_alerts`
- **Configuration**: `add_allowed_pattern`, `ignore_path`, `set_guardrail_level`, `reset_runtime_config`
- **Feedback**: `get_feedback`, `get_recent_feedback`, `acknowledge_feedback`

### Data Flow

```
Agent writes file
       ↓
Intercept Layer checks (security, secrets, prompt injection, debris, layers, destructive changes)
       ↓
Path-aware lowering for test/mock files  →  Learned pattern suppression
       ↓
Approved?  →  Blocked → Quarantine + Feedback
  Yes
       ↓
MCP verify_write (optional) → Run tests → Pass? → Write
                                              Fail → Quarantine + Restore from git
```

## Philosophy

Set it and forget it.

The best guardian is one you forget exists — until the moment it saves you from your own agent.

---

**Star the repo** if you think every developer running AI coding agents in 2026 should have this running in the background.

For the complete source and architecture, see the implementation notes in the repo.
