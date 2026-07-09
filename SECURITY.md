# Security Policy

deadpush is a guardrail for AI coding agents. Because it is itself a security
tool, it is important to be precise about **what it does and does not guarantee**.
This document is the honest threat model: read it before relying on deadpush as a
boundary rather than a convenience.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue
for a security bug.

For the list of provable guarantees and enforcement tiers, see [docs/guarantees.md](docs/guarantees.md).

- Preferred: open a [GitHub Security Advisory](https://github.com/harris-ahmad/deadpush/security/advisories/new)
  (Security → Report a vulnerability).
- Or email **harris@deadpush.dev** with a description, affected version, and a
  proof-of-concept if you have one.

We aim to acknowledge within **72 hours** and to ship a fix or mitigation for
confirmed high-severity issues as quickly as is practical. Please give us a
reasonable window to remediate before public disclosure. There is no bug-bounty
program at this time; credit is gladly given in the changelog and advisory.

## Supported versions

deadpush is on a `0.2.x` beta line. Security fixes land on the latest released
`0.2.x`. Older versions are not maintained — upgrade to the latest release.

| Version | Supported |
| ------- | --------- |
| latest `0.2.x` | ✅ |
| < latest `0.2.x` | ❌ |

---

## Threat model

### What deadpush is for

deadpush exists to catch the damage an **AI coding agent** causes while it operates
on your repository — often unattended. Concretely, it aims to stop dangerous or
unwanted content from reaching your working tree, your commits, and your remote:

- hardcoded secrets and credentials,
- dangerous code (`eval`/`exec`, shell execution, unsafe deserialization, …),
- prompt-injection and LLM-context files (`.cursorrules`, `CLAUDE.md`, …),
- destructive rewrites, sensitive-config tampering, and repo "debris".

It enforces at three points that share **one enforcement kernel**
(`enforce_content()`), so there is no gap between them:

1. **Git hooks** — `pre-commit`, `post-commit`, `pre-push`.
2. **Guardian daemon** — a filesystem watcher that quarantines dangerous writes in
   real time, re-scans every new commit to catch out-of-band commits (git plumbing
   or `--no-verify`, which skip the hooks) and reverts them, and maintains a
   monotonic Safety Score.
3. **MCP server** — guardrailed `write_file`/`check_file` tools for agents that
   integrate over MCP.
4. **Server-side enforcement (off the agent's machine)** — `deadpush scan` wired in
   as a GitHub Actions check (with branch protection) and/or a `pre-receive` hook on
   self-hosted git. This layer runs where the agent has no shell, so it is the only
   one a same-UID agent cannot bypass locally (see below).

### The adversary

The primary adversary is an **AI coding agent running with your own user account
(same UID)** that may — accidentally or "helpfully" — try to route around the
guardrails: disabling hooks, editing policy, killing the daemon, or hiding a
payload. This is a realistic model: agents have been observed treating a guardian
as an obstacle and attempting to remove it.

**Out of scope** (deadpush does not defend against these):

- A **root/administrator** adversary, physical access, or a compromised OS/kernel.
- A **compromised toolchain** — a trojaned `git`, Python interpreter, or a
  malicious third-party dependency already present on the machine.
- A **remote/server-side** attacker. deadpush is a local, client-side tool. Use
  branch protection, required status checks, and server-side scanning on the
  remote as complementary controls.
- The **quality** of the human decision when a violation is surfaced. deadpush
  raises the signal; a human (or policy) still decides.

---

## Two modes, two very different guarantees

deadpush runs in one of two modes. **The distinction is the single most important
thing to understand about its security.**

### Soft mode (default) — deterrence, not a boundary

Everything runs as **your user**: the daemon, the hooks, and the policy files under
the in-repo `.deadpush/` directory. A same-UID agent can, in principle, do anything
you can do — including editing `.deadpush/rules.json` to disable a guardrail,
deleting the install marker, clearing a user-immutable (`uchg`) hook, or killing
the daemon.

Soft mode is therefore **deterrence and accident-prevention**: it reliably catches
the overwhelmingly common case (an agent doing something dangerous *without trying
to evade the guard*), and it makes deliberate evasion noisy and inconvenient. It is
**not** a hard security boundary against a determined same-UID adversary, and it is
not marketed as one.

In particular, a same-UID agent can **kill the daemon** (`pkill`, `launchctl
unload`, …). Soft mode cannot prevent this — no user-privileged process can stop
another process at the same privilege from being killed. What soft mode does is make
a kill **loud instead of silent**: the shadow process respawns the guardian, the
restart is logged as a possible-tamper event, and `deadpush status` / `deadpush
doctor` report a killed guardian (a stale PID file with no live process) distinctly
from a clean stop. To make the guardian genuinely unkillable by a same-UID agent,
use hardened mode; to make a kill *irrelevant* to what actually ships, use the
server-side check.

### Hardened mode — a real same-UID boundary

Hardened mode (`deadpush protect --hardened`, requires root to set up) introduces
**privilege separation**: a dedicated, non-login `_deadpush` user/group owns the
enforcement machinery so that a same-UID agent cannot tamper with it. Hardened mode
is what turns the guarantees below from "best effort" into "an attacker at your UID
cannot do this without root."

Hardened mode provides:

- **Root-immutable hooks.** Hooks are locked with `chflags schg` (macOS) /
  `chattr +i` (Linux). Only root can clear the flag, so the agent cannot delete or
  rewrite a hook. (Soft mode uses owner-clearable `uchg`.)
- **A root-owned interpreter for hooks.** Hooks execute
  `/var/db/deadpush/venv/bin/python` (owned by `_deadpush`, not user-writable), so
  the agent cannot neuter enforcement by editing the `deadpush` package it runs —
  which would otherwise defeat even an immutable hook file.
- **Root-owned policy.** `rules.json` / `learned_patterns.json` and the fail-closed
  marker live under `/var/db/deadpush/policy/<repo-id>/`, owned by `_deadpush` and
  readable-but-not-writable by you. The agent cannot weaken enforcement by editing
  in-repo `.deadpush/` files.
- **Fail-closed that the agent cannot clear.** A root-owned install marker keeps the
  hooks failing closed (refusing to run rather than allowing an unscanned
  push/commit) even if the in-repo marker is deleted. `DEADPUSH_STRICT=1` forces
  fail-closed everywhere.
- **An agent-unkillable daemon.** The guardian runs under `_deadpush` via
  launchd/systemd and respawns; a same-UID agent cannot `kill` it, and it
  self-heals hooks (including a hijacked `core.hooksPath`) each cycle.
- **An authenticated control surface.** The localhost control server serves
  read-only `GET`s openly (so the human dashboard works) but requires a bearer
  token — stored `0600` and root-owned in hardened mode, so the agent cannot read
  it — for every state-changing `POST` (allowlist changes, quarantine restore),
  compared in constant time.
- **Confined quarantine restore.** Restores are resolved and required to stay inside
  the repository tree, so a crafted quarantine `.reason` file cannot make the
  privileged guardian write to an arbitrary path.

Hardened mode's guarantees are validated end-to-end by `scripts/hardened_qa.sh`,
which provisions a throwaway repo, asserts each property against live system state,
and verifies a clean teardown.

---

## Inherent limits (true even in hardened mode)

These are not bugs; they are boundaries of what a local, heuristic guardrail can
promise. Treat deadpush as **defense-in-depth**, never as your only control.

- **Content detection is heuristic.** Guardrails match known-dangerous patterns.
  A determined agent can obfuscate an arbitrary payload — aliasing
  (`import os as o; o.system(...)`), dynamic dispatch
  (`getattr(__import__("os"), "system")`), encoding, or splitting content — to
  evade signature matching. Detection **raises the cost and catches the common
  cases**; it cannot be a completeness guarantee. Reviewing the diff before you
  push remains the real backstop, and hardened mode ensures the guard you *do* have
  cannot be silently switched off.
- **Local hooks can be bypassed by design.** `git push --no-verify`,
  `git commit --no-verify`, or driving git's plumbing directly will skip the hooks
  — git intentionally allows the operator to opt out. deadpush closes this two ways:
  the daemon re-scans every new commit and reverts out-of-band commits that carry
  violations, and — authoritatively — the **server-side check** (`deadpush scan` via
  GitHub Actions or a `pre-receive` hook) runs where the agent cannot opt out, so a
  bypassed local commit is still rejected at the remote. Enable it (see below).
- **Range scanning sees net changes.** Pre-push scans the net diff of what is being
  pushed (whole tree for a brand-new branch; `remote_sha..local_sha` for an
  update). Content that is added and then removed **within** a single pushed range
  is not surfaced by the diff, though the commits still ship. History review /
  server-side scanning covers this.
- **Soft mode is not a boundary** (see above). If you need a real same-UID
  boundary, use hardened mode.
- **deadpush is not a secrets manager or SAST suite.** It reduces the blast radius
  of agent mistakes; it does not replace secret rotation, least-privilege
  credentials, dependency auditing, or human code review.

---

## Hardening recommendations for operators

- Use **`--hardened`** on repositories where an agent runs unattended and you want a
  boundary rather than deterrence.
- **Wire up the server-side check** — the one layer that runs off the agent's
  machine and cannot be bypassed with `--no-verify`, plumbing, or a killed daemon:
  add `deadpush scan` as a GitHub Actions check (`examples/github/deadpush.yml`) and
  make it a required status check, or install the `pre-receive` hook on self-hosted
  git (`docs/server-side/pre-receive.md`).
- Keep **server-side controls** on: protected branches, required checks, and
  push/secret scanning on your git host. Local and server-side controls are
  complementary.
- Do not rely on `--no-verify` habits; if you must bypass, do it deliberately and
  review the change.
- Keep deadpush updated to the latest `0.2.x` for security fixes.

---

*Found a way around any hardened-mode guarantee above? That is exactly the kind of
report we want — please disclose it privately as described at the top of this file.*
