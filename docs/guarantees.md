# deadpush Guarantee Catalog

This document is the authoritative list of **provable** guarantees deadpush provides,
organized by enforcement tier. Read [SECURITY.md](../SECURITY.md) for the full threat
model.

Each entry follows this schema:

```
G-XX: Title
  Property:   formal statement of what holds
  Mechanism:  how deadpush enforces it
  Proof:      test or QA harness that validates it
  Tier:       minimum tier required (T0–T3)
  Bypass:     what an adversary needs to defeat this guarantee
```

## Enforcement tiers

| Tier | Command | Scope |
|------|---------|-------|
| **T0 Deter** | `deadpush protect --daemon` | Accident prevention, loud tamper logs |
| **T1 Harden** | `deadpush protect --hardened` | Policy/daemon/hook integrity (G-01–G-06) |
| **T2 Sandbox** | `deadpush run --sandbox -- …` | T1 + confined agent I/O (G-07–G-09) |
| **T2-max** | T2 + native pre-write deny (Linux fanotify / macOS ES) | Syscall-level write denial (G-10) |
| **T3 Ship** | GitHub Action + branch protection | Uncircumventable remote ship gate (G-11) |

Default onboarding: **T0 locally + T3 on GitHub**. Use T1 for unattended agents, T2
when the agent must not write forbidden content even if it tries.

---

## Guarantee catalog

### G-01: Unified enforcement kernel

```
Property:   MCP, guardian, and git hooks apply identical guardrail logic
Mechanism:  enforce_content() in deadpush/intercept.py
Proof:      tests/test_intercept_guardrails.py, tests/test_exhaustive.py
Tier:       T0
Bypass:     agent never uses MCP, filesystem, or git (writes outside repo)
```

### G-02: Fail-closed when protection marker present

```
Property:   git operations refuse to proceed if deadpush is installed but hooks/deadpush missing
Mechanism:  fail-closed prelude in deadpush/hooks.py
Proof:      tests/test_failclosed.py
Tier:       T0
Bypass:     delete install marker and hooks (soft mode); root in hardened mode
```

### G-03: Hardened hooks are root-immutable

```
Property:   ∀ agent at UID=user, hardened hooks cannot be edited or deleted
Mechanism:  chflags schg (macOS) / chattr +i (Linux) with sudo
Proof:      tests/test_root_immutable.py, scripts/hardened_qa.sh
Tier:       T1
Bypass:     requires root
```

### G-04: Hardened hooks use root-owned interpreter

```
Property:   hardened git hooks execute /var/db/deadpush/venv/bin/python, not user-writable python
Mechanism:  hook template embeds hardened_python() path
Proof:      tests/test_tier0_hardening.py::TestHardenedHookInterpreter
Tier:       T1
Bypass:     requires root to replace hardened venv
```

### G-05: Hardened policy is agent-immutable

```
Property:   ∀ agent at UID=user, is_hardened → rules.json in /var/db/deadpush/policy/<id>/ unchanged
Mechanism:  root-owned policy directory; in-repo .deadpush/rules.json ignored
Proof:      tests/test_tier0_hardening.py::TestHardenedPolicyLocation
Tier:       T1
Bypass:     requires root
```

### G-06: Hardened daemon is agent-unkillable

```
Property:   ∀ agent at UID=user, guardian process running as _deadpush cannot be killed
Mechanism:  launchd/systemd KeepAlive under _deadpush user
Proof:      scripts/hardened_qa.sh (manual, requires root)
Tier:       T1
Bypass:     requires root
```

### G-07: MCP proxy blocks guarded writes before downstream execution

```
Property:   tools/call for filesystem/git write tools are scanned before forwarding to downstream MCP server
Mechanism:  deadpush mcp-proxy intercepts tools/call, runs enforce_content()
Proof:      tests/test_mcp_proxy.py
Tier:       T2 (when agent MCP config routes through proxy)
Bypass:     agent writes via shell/editor without MCP; IDE native writes
```

### G-08: Git wrapper enforces scan on commit/push

```
Property:   git commit/push invoked through deadpush run --sandbox PATH cannot skip guardrails
Mechanism:  deadpush-git wrapper prepended to PATH in sandbox session
Proof:      tests/test_git_wrapper.py, tests/test_run_session.py
Tier:       T2
Bypass:     direct .git/ plumbing; git binary outside wrapped PATH
```

### G-09: Seatbelt confines sandboxed agent writes (macOS)

```
Property:   agent subprocess launched via deadpush run --sandbox cannot write outside repo tree
Mechanism:  sandbox-exec with generated Seatbelt profile
Proof:      tests/test_seatbelt_sandbox.py
Tier:       T2 (macOS)
Bypass:     not launched via deadpush run; Cursor GUI editor (outside wrapped subprocess)
```

### G-10: Pre-write syscall deny (Linux T2-max)

```
Property:   write syscalls to repo paths denied before completion when fanotify backend active
Mechanism:  LinuxEnforcementBackend with fanotify FAN_DENY
Proof:      tests/test_fanotify_deny.py (ubuntu CI only)
Tier:       T2-max (Linux)
Bypass:     writes outside watched mount; CAP_SYS_ADMIN adversary
```

### G-11: Server-side ship gate

```
Property:   commits with block-level violations cannot merge to protected branches
Mechanism:  deadpush scan in GitHub Actions / pre-receive hook + branch protection
Proof:      tests covering scan_range/scan_tree; examples/github/deadpush.yml
Tier:       T3
Bypass:     push to unprotected branch; disable branch protection (requires admin)
```

### G-12: Guardian Push Channel delivers incidents

```
Property:   connected GPC clients receive INCIDENT/LOCKDOWN messages when guardian blocks a write
Mechanism:  Unix domain socket at ~/.deadpush/gpc.<repo-id>.sock
Proof:      tests/test_gpc.py
Tier:       T0 (receive-only); T2 (mandatory session integration)
Bypass:     client not subscribed to GPC socket
```

---

## Heuristic (not guaranteed)

These are best-effort detections. Review diffs before pushing.

| ID | Description | Why not guaranteed |
|----|-------------|-------------------|
| H-01 | All obfuscated dangerous code detected | Pattern matching is incomplete |
| H-02 | Agent reads feedback and self-corrects | Depends on LLM behavior |
| H-03 | Agent voluntarily uses deadpush MCP tools | MCP is cooperative in T0 |
| H-04 | Watchdog quarantine has zero race window | Post-write reactive on T0/T1 |

---

## Trusted Computing Base (TCB)

Components that must be trusted for guarantees to hold:

1. **Root at install time** — hardened setup (`deadpush protect --hardened`)
2. **`/var/db/deadpush/venv/bin/python`** — pinned interpreter for hardened hooks
3. **`enforce_content()`** — enforcement kernel + registered guardrail plugins
4. **Git host branch protection** — required status checks for T3
5. **Platform sandbox backend** — Seatbelt (macOS T2) or fanotify/Landlock (Linux T2-max)
6. **OS kernel** — fanotify, Landlock, or Endpoint Security when T2-max is active

Everything else (pattern rules, LLM behavior, agent cooperation) is **detection**, not
a guarantee.

---

## Proof harness index

| Harness | Validates | Run |
|---------|-----------|-----|
| `pytest tests/` | Unit + integration proofs | `uv run pytest` |
| `scripts/hardened_qa.sh` | T1 live system guarantees | `./scripts/hardened_qa.sh` (macOS/Linux, needs sudo) |
| `scripts/full_e2e_test.py` | Guardian + MCP + hooks demo | `python scripts/full_e2e_test.py --simulate-agent` |

Found a bypass of any **T1+ guarantee**? Report privately via [SECURITY.md](../SECURITY.md).
