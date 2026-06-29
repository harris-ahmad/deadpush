# deadpush — Agent Onboarding

This project uses **deadpush**: an agent-native guardrail system that intercepts risky file writes in real time.

## Quick Start

- Write files normally via MCP (`write_file` tool). Guardrails run automatically.
- If blocked → read the feedback file → fix the issue → retry.
- If you hit a false positive → `add_allowed_pattern` to whitelist the code (requires `deadpush mcp --danger`).

## MCP Tools

Connect via `deadpush mcp` (stdio JSON-RPC on `2024-11-05` protocol).

### Write / Check
| Tool | What it does |
|---|---|
| `write_file(path, content)` | Write through guardrails. Blocked files go to quarantine + feedback. |
| `check_file(path, content)` | Preview: would the file pass? Returns violations without writing. |
| `verify_write(path, content)` | Write + run related tests. File only persists if tests pass. |
| `get_write_diff(path, content)` | Preview diff + guardrail violations before writing. |
| `retry_write(path, content)` | Submit corrected content for a previously blocked file. |

### Quarantine
| Tool | What it does |
|---|---|
| `quarantine_list(limit)` | List quarantined files |
| `quarantine_restore(name)` | Restore from quarantine (danger mode) |

### Feedback
| Tool | What it does |
|---|---|
| `get_feedback(limit)` | Read recent guardrail feedback |
| `get_recent_feedback(limit)` | Unacknowledged feedback only |
| `acknowledge_feedback(name)` | Mark feedback as read/addressed |
| `get_status` | Current paths + available tools |
| `get_safety_score` | Latest guardian score |
| `get_test_results(limit)` | Recent verify_write test output |

### Config (agent self-service — danger mode for softening actions)
| Tool | What it does |
|---|---|
| `get_runtime_config` | View all current rules |
| `add_allowed_pattern(pattern, desc)` | Whitelist a regex pattern |
| `remove_allowed_pattern(pattern)` | Remove from allowlist |
| `ignore_path(path)` | Skip a file entirely |
| `set_guardrail_level(category, level)` | Set severity: `off`, `warn`, or `block` |
| `reset_runtime_config` | Clear all overrides to defaults |
| `allow_sensitive_write(path)` | Opt in to writing a sensitive config file |
| `learn_false_positive(category, pattern, reason)` | Teach deadpush to suppress a false positive |
| `adjudicate_finding(...)` | Structured adjudication rubric for a finding |

All tools return `{"success": bool, "data": ..., "summary": "..."}`.

## Guardrail Categories

| Category | Default level | What it catches |
|---|---|---|
| `prompt_injection` | `block` | System prompt remnants, AI identity overrides, chat markup tokens |
| `secret` | `block` | API keys, tokens, passwords, AWS keys, GitHub tokens |
| `security` | `block` | eval/exec, subprocess, pickle, SQL injection, file deletion |
| `layer` | `block` | Imports violating architecture layer rules |
| `sensitive` | `block` | Writes to CI/CD, deployment, Docker, and other sensitive config files |
| `destructive` | `warn` | Near-empty rewrites of substantial files, >50% line reduction |
| `debris` | `warn` | LLM context files, scratchpads, hardcoded secrets in debris scan |
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

## What NOT To Do

- Do NOT bypass guardrails by writing directly to the filesystem.
- Do NOT edit `.deadpush/rules.json` directly — use the MCP tools.
- Do NOT delete `.deadpush/` directory contents unless you understand the consequences.
- Do NOT add `ignore all previous instructions` or similar prompt injection patterns to any file.
- Do NOT commit secrets, API keys, or tokens to the repository.
