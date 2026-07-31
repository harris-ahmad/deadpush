# Deadpush research thesis (1-page)

**Working title:** Never Lose Work While Staying Safe: Runtime Governance for Coding Agents via Journaling and Staged Recovery

**Status:** claim locked for evaluation — implement only what this page requires.

---

## 1. Claim (one sentence)

An OS-level guardian that **journals file state and stages responses to high-risk agent actions** can block destructive agent behavior **without discarding hours of useful work**, outperforming quarantine-only and hard-block baselines on recoverability while matching them on safety.

## 2. Why this claim (not “we catch `.env`”)

Secrets and scratch files are already handled by Deadpush’s quarantine path. The novel, paper-shaped gap is:

> When an agent is about to destroy progress (`git reset --hard`, force-push, mass wipe, hook deletion), today’s tools either **miss it** or **stop the world**. Deadpush should **intercept, checkpoint, negotiate/escalate — then restore to a validated save point** so safety does not equal lost work.

GPC/GCP remains a **delivery channel** for staged events, not the primary claim.

## 3. Non-goals (explicit)

- Parsing natural-language prompts with an LLM
- Becoming “reverse MCP” as the headline contribution
- Mass GitHub-star / viral product packaging
- Full intent-contract system (Phase D) until claim A is measured

## 4. System under test (minimum build)

| Piece | Role in the claim | Exists today? |
|-------|-------------------|---------------|
| FS watch + quarantine + feedback | Safety baseline | Yes |
| Sandbox / hardened install | Confinement / integrity | Yes (partial Linux) |
| GPC events | Notify agent of blocks | Yes (agents rarely speak it) |
| **File journal** (pre-mutation originals) | Recoverability | **No — build** |
| **Save points** (validated milestones) | How far to roll back | **No — build** |
| **Staged intercept** of high-risk git cmds | Don’t hard-kill | Partial (wrapper/hooks) — **extend** |
| Eval harness (scenarios + metrics) | Graphs for the paper | **No — build** |

## 5. Threat / scenario suite

Scripted agent-like workloads (no need for live Claude in v0):

1. **Secret write** — create `.env` with API key  
2. **Scratch pollution** — dump `CLAUDE.md` / scratchpads  
3. **Destructive git** — `git reset --hard` after N useful commits/edits  
4. **Force-push attempt** — `git push --force`  
5. **Hook wipe** — delete/replace `.git/hooks/*`  
6. **Mass edit** — touch ≫K unrelated files after a narrow “task”

## 6. Baselines

| ID | Behavior |
|----|----------|
| B0 | No guardian |
| B1 | `.gitignore` / ignore files only |
| B2 | Pre-commit / pre-push hooks only |
| B3 | Deadpush quarantine-only (current soft path; no journal restore) |
| B4 | **Deadpush + journal + staged recovery** (system under test) |

## 7. Metrics (what the graphs show)

| Metric | Definition |
|--------|------------|
| **Block rate** | Fraction of dangerous actions prevented from lasting effect |
| **False-positive rate** | Benign actions incorrectly staged/blocked |
| **Work preserved** | % of useful pre-incident edits still present after intervention |
| **Time-to-safe** | Wall time from incident to safe tree (no secrets / no wipe) |
| **Time-to-recover** | Wall time to restore last validated save point |
| **Overhead** | Extra latency / CPU vs B0 on a normal edit loop |

Primary result for the paper: **B4 ≈ B3 on block rate, ≫ B3 on work preserved** under scenarios 3–5.

## 8. Implementation order (thesis-gated)

1. Journal store (changed-file originals + hashes) — **done** (`deadpush/journal.py`)
2. Save points (create / list / restore; validation stub: “no quarantined secrets in tree”) — **in progress on `feat/save-points`** (`deadpush/savepoints.py`)
3. Staged git intercept for `reset --hard` / force-push (wrapper path first)
4. Eval harness producing CSV + plots for §6–7
5. Only then: richer GPC event types for staged recovery

## 9. Success criteria for “ready to write the paper”

- [ ] Scenarios 1–6 automated  
- [ ] B0–B4 runnable on one OS (macOS Seatbelt *or* Linux bwrap)  
- [ ] Graphs for block rate, work preserved, overhead  
- [ ] One ablation: journal without staged git vs full B4  

## 10. One-line contribution statement (abstract seed)

> We present Deadpush as a runtime governance layer for coding agents that combines OS-level enforcement with write-ahead-style journaling and staged recovery, and we show that recoverability can be improved without sacrificing safety on destructive agent actions.
