# OpenAI conversation notes (design depth)

Companion to the locked research claim in [`thesis.md`](thesis.md).
Implementation order is thesis-gated; this file keeps the richer product/paper
ideas (intent contracts, GPC open spec, trust budget, policy packs) so we do
not lose them while building Phase 1–4.

**Phase 1 landed:** write-ahead journal store in `deadpush/journal.py`
(content-addressed blobs, first-wins preimages per epoch, restore/restore_all).
Save points and staged git intercept come next and will *call* this store —
guardians must capture **before** mutation (session seed / pre-risk snapshot),
because post-write watchdog alone sees the already-changed bytes.

---

**Keep the name Deadpush.** Change the *story*:

> Not “file quarantine for AI agents”  

> → **runtime governance layer for autonomous coding agents**

Elevator pitch they landed on:

> An OS-level guardian that observes coding agents, enforces policy, preserves recoverability, and eventually talks back via Guardian Channel Push (GCP).

Three **pillars** they said should define the product/paper:

1. **Journaling + save points** (safe recovery)

2. **Staged response** (don’t hard-kill work)

3. **Guardian Channel Push** as an open governance protocol

---

## Important concepts

### 1. Intent as a *contract*, not LLM parsing

You correctly rejected “parse English with an LLM.” Three deterministic options:

| Option | Idea |

|--------|------|

| **Explicit intent** | `intent=rename` declared by user/agent |

| **Rule classifier** | Keyword → expected blast radius (e.g. rename ⇒ few files) |

| **Scope contract** | Agent declares plan: `intent=refactor, scope=src/auth, max_files=20` |

Guardian verifies **behavior against the contract** (file counts, dirs, commands) — no code understanding required.

### 2. Behavioral anomaly detection (OS-level, not semantic)

Measure:

- File-edit volume / rate

- Unrelated directories touched

- Dangerous commands `docker build`, `kubectl apply`, etc.)

- Git history / `.git` mutation patterns

Mismatch with declared intent → pause + ask approval.

### 3. Git protection as its own product surface

Risky ops: `reset --hard`, `push --force`, `filter-repo`, hook/ref rewrites, `.git` config edits.

Treat as a **permission layer with risk tiers**, not English understanding.

### 4. Staged response (anti-adoption-killer)

Don’t halt hours of work. Sequence:

1. **Intercept** dangerous command (pause, don’t kill)

2. **Checkpoint** so work isn’t lost

3. **Negotiate** via GCP: explain why + safer alternatives

4. If agent insists → **human-in-the-loop**

Differentiator phrase: *“never lose work while staying safe.”*

### 5. Journaling + save points (DB WAL inspiration)

| Mechanism | Answers | Nature |

|-----------|---------|--------|

| **Journaling** | How do I recover? | Continuous: hash/store originals before mutation |

| **Save points** | How far back? | Milestone markers (validated invariants) |

- Store **only changed files** in a hidden recovery dir (not full worktrees)

- Save points at boundaries: before high-risk cmds, after tests pass, etc.

- Restore to **most recent validated save point** (build OK, no secrets, etc.)

Paper framing: *journaling + save points for autonomous coding agents.*

### 6. GCP = governance event bus (not “reverse MCP”)

Positioning upgrade:

- Not “reverse of MCP”

- → **event-driven governance protocol for coding agents**

Design principles:

- Agent-agnostic **facts/events**, not puppet-master commands

- Tiny state machine: `observed → validated → action_required → resolved`

- Handshake + **capability negotiation** (pause/resume, checkpoint restore, policy explain…)

- Separate **transport** (sockets) from **semantics** `SecretDetected`, `PolicyViolation`, `CheckpointCreated`)

- Bidirectional: guardian notifies; agent can reply with intent (“I’ll remove the secret”)

### 7. How agents connect when they don’t speak GCP

Adoption ladder:

1. **Wrapper** (today): `deadpush run` launches agent as subprocess + OS monitoring  

2. **Skills**: teach agent to acknowledge Guardian events via markdown skills  

3. **Plugin / extension API** if available  

4. **Native GCP** long-term  

GCP negotiation is optional upgrade; quarantine/rollback must work without it.

### 8. Trust budget / reputation (observability, not opaque AI score)

- Session metrics: quarantines, violations, self-corrections

- Trends over time for evaluation

- **Trust budget**: start 100, deduct on violations, tighten controls under threshold

- Use for observation / adaptive policy — not a black-box “reputation LLM”

### 9. Policy packs

Preset rule packs teams install instead of writing everything from scratch (enterprise/adoption play).

### 10. Explainability

Already partly shipped (quarantine feedback). Keep framing: **block + why**, always.

---

## What’s already in Deadpush (as you described)

- Watchdog FS monitoring + quarantine

- Hardened `_deadpush` privilege separation) vs sandbox

- Config `deadpush.toml`)

- Safety score → lockdown

- MCP (optional tools *to* the agent)

- GPC / “GCP” (guardian → agent channel) — novel, but agents don’t speak it yet

- Explicitly **not** “AI slop” — OS-level systems tool

---

## Action items (recommended order)

ChatGPT’s implementation order matches a sensible roadmap:

### Phase A — Prototype first (start here)

1. **File journaling** — before mutation, store original content/hash for changed files  

2. **Save points** — milestone checkpoints with validation criteria  

3. Wire restore path: roll back to last validated save point  

### Phase B — Staged recovery

4. Intercept high-risk git/shell commands (pause, don’t kill)  

5. Checkpoint before allowing/denying  

6. Safer alternatives messaging (even without full GCP)  

7. Human escalation path  

### Phase C — Git protection product surface

8. Risk-tiered git command gate `reset --hard`, force-push, hooks/refs)  

9. `.git` integrity watching  

10. Policy: log benign overrides; block malicious by default  

### Phase D — Intent contracts (deterministic)

11. Scope contract schema `intent`, `scope`, `max_files`, …)  

12. Blast-radius checks vs contract  

13. Soft block / approval on mismatch  

### Phase E — GCP as open spec

14. Document event semantics + state machine (spec separate from implementation)  

15. Capability handshake  

16. Skills pack that teaches agents to respond to Guardian events  

17. Keep wrapper path as default today  

### Phase F — Observability / packaging

18. Trust budget (extend/clarify safety score)  

19. Session reliability reports (not opaque reputation)  

20. Policy packs  

21. Retagline README: *safety / governance layer*, not just quarantine  

### Meta

22. Write `DESIGN.md` (ChatGPT never successfully delivered the full markdown — you still need this)  

23. Consider paper framing: systems paper on journaling + staged recovery + governance protocol  

---

## Strategic insights worth keeping

- **Don’t lead with “.env secrets”** — too narrow; lead with agent governance / seatbelt system  

- **Hard blocks kill adoption** — staged + recoverability is the UX thesis  

- **Git tampering feels like its own product** — you agreed; treat it as a major pillar, not a side feature  

- **GCP is the right research question**, but only if useful *without* native agent support first  

- **Separate layers**: mechanism (OS quarantine/journal) ≠ policy (rules) ≠ protocol (GCP)  

- Name stays **Deadpush**; slogan upgrades  

---

## Open questions the conversation left hanging

1. Exact save-point validation rules (tests? build? no secrets?)  

2. Where journals/save points live (hidden dir layout, retention, hardened ownership)  

3. How to intercept shell/git commands reliably under Seatbelt/bwrap vs IDE-native agents  

4. Minimal skill format that actually makes Claude/Cursor/Codex *respond* to Guardian events  

5. Whether “GCP” should be renamed in public docs to avoid confusion with Google Cloud Platform (you use GPC in code already — worth aligning)  