# deadpush — Agent Onboarding

This project uses **deadpush**: an agent-native guardrail system that intercepts risky file writes in real time.

## Quick Start

- Write files normally via MCP (`write_file` tool). Guardrails run automatically.
- If blocked → read the feedback file → fix the issue → retry.
- If you hit a false positive → `add_allowed_pattern` to whitelist the code.

## MCP Tools (24 available)

Connect via `deadpush mcp` (stdio JSON-RPC on `2024-11-05` protocol).

### Write / Check
| Tool | What it does |
|---|---|
| `write_file(path, content)` | Write through guardrails. Blocked files go to quarantine + feedback. |
| `check_file(path, content)` | Preview: would the file pass? Returns violations without writing. |

### Scan
| Tool | What it does |
|---|---|
| `scan` | Full analysis summary (dead symbols, debris, test issues, etc.) |
| `get_dead_symbols` | Unreachable code |
| `get_debris` | AI artifacts, stale files |
| `get_test_issues` | No-assertion / tautology / empty tests |
| `get_stale_docs` | Docstring-param mismatches |
| `get_layer_violations` | Architectural import violations |
| `get_security_boundaries` | Untested security-sensitive ops |
| `get_complexity_alerts` | Complexity spikes |

### Clean / Quarantine
| Tool | What it does |
|---|---|
| `clean(mode)` | Remove dead code / debris (safe, dry_run, force) |
| `quarantine_list(limit)` | List quarantined files |
| `quarantine_restore(name)` | Restore from quarantine |

### Feedback
| Tool | What it does |
|---|---|
| `get_feedback(limit)` | Read recent guardrail feedback |
| `get_status` | Current paths + available tools |
| `get_safety_score` | Latest guardian score |

### Config (agent self-service)
| Tool | What it does |
|---|---|
| `get_runtime_config` | View all current rules |
| `add_allowed_pattern(pattern, desc)` | Whitelist a regex pattern |
| `remove_allowed_pattern(pattern)` | Remove from allowlist |
| `ignore_path(path)` | Skip a file entirely |
| `set_guardrail_level(category, level)` | Set severity: `off`, `warn`, or `block` |
| `reset_runtime_config` | Clear all overrides to defaults |

All tools return `{"success": bool, "data": ..., "summary": "..."}`.

### Diff / Preview
| Tool | What it does |
|---|---|
| `get_write_diff(path, content)` | Preview diff + guardrail violations before writing |
| `allow_sensitive_write(path)` | Opt in to writing a sensitive config file (CI/CD, Docker, etc.) |

## Guardrail Categories

| Category | Default level | What it catches |
|---|---|---|
| `prompt_injection` | `block` | System prompt remnants, AI identity overrides, chat markup tokens |
| `secret` | `block` | API keys, tokens, passwords, AWS keys, GitHub tokens |
| `security` | `block` | eval/exec, subprocess, pickle, SQL injection, file deletion |
| `layer` | `block` | Imports violating architecture layer rules |
| `sensitive` | `block` | Writes to CI/CD, deployment, Docker, and other sensitive config files |
| `destructive` | `warn` | Near-empty rewrites of substantial files, >50% line reduction |
| `debris` | `warn` | TODO stubs, FIXME markers, bare `pass` statements |
| `dependency` | `warn` | Typosquat packages, suspicious package names in dep files |

## Self-Correction Flow

```
write_file("src/api.py", content)
  ├─ ✅ Allowed → file appears at src/api.py
  └─ ❌ Blocked → file quarantined, feedback written to .deadpush/feedback/

Read feedback: get_feedback(5)
Fix the issue in your code
Retry: write_file("src/api.py", new_content)

False positive? add_allowed_pattern("the_regex_that_matched")
Then retry — it will pass.
```

## Runtime Config

Persisted in `.deadpush/rules.json`. Survives server restarts.
Modify via MCP tools above. Do NOT edit the file directly.

Use `set_guardrail_level("prompt_injection", "warn")` to downgrade a category to warning-only (doesn't block, just reports).

## What NOT To Do

- Do NOT bypass guardrails by writing directly to the filesystem.
- Do NOT edit `.deadpush/rules.json` directly — use the MCP tools.
- Do NOT delete `.deadpush/` directory contents unless you understand the consequences.
- Do NOT add `ignore all previous instructions` or similar prompt injection patterns to any file.
- Do NOT commit secrets, API keys, or tokens to the repository.
