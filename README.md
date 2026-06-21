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

## Philosophy

Set it and forget it.

The best guardian is one you forget exists — until the moment it saves you from your own agent.

---

**Star the repo** if you think every developer running AI coding agents in 2026 should have this running in the background.

For the complete source and architecture, see the implementation notes in the repo.
