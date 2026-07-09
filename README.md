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
- LLM context files like `CLAUDE.md` or `agents.md` committed to the repo

**deadpush** is the always-on guardian that catches this the moment it happens.

## One Command. Real Protection.

```bash
pip install deadpush
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

For a full automated demo of guardian features (burst simulation, hooks, MCP):

```bash
python scripts/full_e2e_test.py --simulate-agent --burst
```

## Enforcement tiers

deadpush uses explicit tiers so you know what is **proven** vs **heuristic**. Full catalog: [docs/guarantees.md](docs/guarantees.md).

| Tier | Command | What it guarantees |
|------|---------|-------------------|
| **T0 Deter** | `deadpush protect --daemon` | Accident prevention, loud tamper logs |
| **T1 Harden** | `deadpush protect --hardened` | Agent cannot kill guardian, edit policy, or tamper hooks |
| **T2 Sandbox** | `deadpush run --sandbox -- …` | Confined agent I/O + git/MCP gates |
| **T3 Ship** | GitHub Action + branch protection | Violations cannot merge (uncircumventable) |

**Recommended default:** T0 locally + [T3 on GitHub](docs/github-setup.md) (5-minute setup).

## Key Features

- **True background guardian** — Survives terminal close, supports systemd/launchd autostart
- **Smart multi-agent Safety Score** — Penalizes bursts of dangerous activity from parallel agents
- **Automatic quarantine** (never hard-delete) — Easy `deadpush quarantine list` / `restore`
- **MCP proxy + Guardian Push Channel** — Mandatory tool-path scanning and push incidents to agents
- **Plugin SDK** — Extend `enforce_content()` via `deadpush.guardrails` entry points
- **Cross-platform git hooks** — Pre-commit, post-commit, and pre-push guardrails
- **Debris detection** — LLM context files, vibe scratchpads, hardcoded secrets

## Commands You'll Actually Use

```bash
deadpush protect --daemon     # T0: one command per repo
deadpush protect --hardened   # T1: unkillable guardian (requires sudo)
deadpush run --sandbox -- …   # T2: sandboxed agent session
deadpush mcp-proxy -- …       # Wrap MCP servers with guardrails
deadpush status               # Safety Score + guardian health
deadpush quarantine list      # See what it caught
deadpush doctor               # Health check (hooks, MCP, guardian)
deadpush mcp                  # MCP server for AI agents (guardrailed writes)
```

See also: [comparison vs other guardrails](docs/comparison.md) · [guarantee catalog](docs/guarantees.md)

## Why This Matters in the AI Era

AI agents are incredible productivity multipliers.

They are also incredibly good at creating technical debt, leaking secrets, and polluting your context — especially when you give them long-running tasks and step away.

deadpush is the missing safety net.

## Installation

```bash
pip install deadpush
```

Then run `deadpush protect --daemon` in any repo you care about.

## Windows Users

The pre-push hook ships as a Python script + `.cmd` shim. It works from PowerShell, Command Prompt, and Git Bash. The `deadpush protect` command records the exact Python interpreter so everything works even inside virtualenvs.

## Server-side enforcement (uncircumventable)

The local guardian and git hooks run on the developer's (or agent's) machine, so a
determined agent can bypass them with `git push --no-verify`, git plumbing, or by
killing the daemon. The fix is to also enforce **off** that machine, where the agent
has no shell. deadpush ships a `deadpush scan` command that scans a commit range (or
whole tree) and exits non-zero on any block-level violation, plus two ways to run it:

**GitHub / GitLab.com — a required status check.** Copy
[`examples/github/deadpush.yml`](examples/github/deadpush.yml) to
`.github/workflows/deadpush.yml`, then require the `deadpush` check under branch
protection. A commit with secrets or dangerous code is blocked from the protected
branch no matter what happened locally.

```yaml
- uses: harris-ahmad/deadpush/.github/actions/scan@main
```

**Self-hosted git (bare / Gitea / GitLab) — a `pre-receive` hook.** Install
[`examples/server-side/pre-receive`](examples/server-side/pre-receive) on the server;
it rejects the entire push if any incoming commit has a violation. Full instructions:
[`docs/server-side/pre-receive.md`](docs/server-side/pre-receive.md).

```bash
deadpush scan --base "$BASE_SHA" --head "$HEAD_SHA"   # a PR / push range
deadpush scan --all                                    # whole tree at HEAD
```

This is the only layer a same-UID agent cannot bypass. Use it together with local
protection (and `--hardened` for an unkillable local guardian). See
[SECURITY.md](SECURITY.md) for the full threat model.

## Development

```bash
git clone https://github.com/harris-ahmad/deadpush
cd deadpush
./scripts/dev_install.sh
```

On macOS, use `dev_install.sh` instead of bare `pip install -e .` — see [CONTRIBUTING.md](CONTRIBUTING.md) if imports fail outside the repo.

### Validating hardened mode

Hardened mode's guarantees (privilege separation, an agent-unkillable daemon,
root-immutable `schg` hooks, repo ACLs, real-time quarantine, hook self-heal, and
a clean teardown) require root and a real service manager, so CI can't verify
them. Run the end-to-end QA harness manually on a clean machine or VM:

```bash
./scripts/hardened_qa.sh
```

It provisions a throwaway repo, runs `deadpush protect --hardened`, asserts every
guarantee against live system state, then uninstalls and verifies nothing is left
behind. Run it as your normal user (not root); it escalates with `sudo` only where
needed. It refuses to run if a `_deadpush` account already exists, so it can't
disturb a real hardened install (pass `--allow-existing` to override, `--keep` to
skip teardown for inspection).

## Architecture

deadpush is a closed-loop guardian with four cooperating layers:

### 1. Intercept Layer (`deadpush/intercept.py`)
The real-time guardrail engine. Every file write is checked via `enforce_content()`:
- **Security guardrails**: `eval`, `subprocess`, pickle deserialization, SQL injection patterns
- **Secret detection**: Hardcoded API keys, tokens, passwords (with **path-aware lowering** in test/mock files)
- **Prompt injection**: AI prompt manipulation patterns
- **Destructive change detection**: Near-empty rewrites, >50% line reduction
- **Sensitive config protection**: CI/CD, deployment, Docker files
- **Layer violations**: Architecture import rules
- **Debris detection**: LLM context files, scratchpads, secrets

**Learned false positive suppression**: Adjudicated false positives persist to `.deadpush/learned_patterns.json` and auto-suppress on future checks.

### 2. Guardian Daemon (`deadpush/guard.py`)
Filesystem watcher that quarantines dangerous writes, maintains the Safety Score, and exposes a local control API for agents.

### 3. Git Hooks (`deadpush/hooks.py`)
Pre-commit, post-commit, and pre-push hooks all call the same `enforce_content()` kernel — no bypass between MCP, daemon, and git.

### 4. MCP Server (`deadpush/mcp_server.py`)
Stdio MCP server exposing guardian tools: `write_file`, `check_file`, `verify_write`, quarantine management, feedback loops, and danger-gated config tools.

### Data Flow

```
Agent writes file (MCP write_file or native editor)
       ↓
enforce_content() — same kernel for MCP, hooks, and guardian
       ↓
Approved?  →  Blocked → Quarantine + Feedback + Safety Score drop
  Yes
       ↓
verify_write (optional) → Run tests → Pass? → Write
                                              Fail → Quarantine + Restore from git
       ↓
git commit → pre-commit hook → post-commit hook
git push   → pre-push hook (server-side GitHub Action available)
```

## Philosophy

Set it and forget it.

The best guardian is one you forget exists — until the moment it saves you from your own agent.

---

**Star the repo** if you think every developer running AI coding agents in 2026 should have this running in the background.

For the complete source and architecture, see the implementation notes in the repo.
