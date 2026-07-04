# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] - 2026-07-04

### Fixed
- **`protect`/`guard` now default to soft mode (critical first-run fix)**: the
  default was hardened (`use_hardened = not soft`), so the documented one-liner
  `pip install deadpush && deadpush protect --daemon` silently triggered a `sudo`
  password prompt — and on a normal (non-editable) pip install it then failed
  outright. Soft (same-UID) mode is now the default; hardened mode is opt-in via
  `--hardened`. This matches the README and `SECURITY.md`.
- **Hardened mode works from a pip/wheel install**: `_ensure_hardened_venv`
  assumed a source checkout and looked for a `pyproject.toml` above the package,
  raising `deadpush source not found at .../site-packages` for every
  pip-installed user who ran `--hardened`. It now installs the matching version
  from PyPI (`deadpush==<version>`) when there is no local source tree, and still
  installs the working tree for dev checkouts.

## [0.2.2] - 2026-07-04

First public release on PyPI (`0.2.1` was burned by PyPI's deleted-filename
reuse rule and skipped). The project stays on a 0.2.x beta line until the
production-readiness gates (blocking lint, lockfiled reproducible builds, and
green macOS + Linux CI including the lifecycle integration test) are met.

### Security (hardened mode — Tier 0)

A threat-model audit (adversarial agent running as the same UID) found five ways
a same-UID agent could defeat *hardened* mode even though the daemon and hook
files were protected. These close them so hardened mode is a real boundary, not
just defense-in-depth. Covered by `tests/test_tier0_hardening.py` and validated
end-to-end by `scripts/hardened_qa.sh`.

- **Hardened hooks now execute the root-owned interpreter (H2)**: git hooks used
  the *user's* interpreter and user-writable `deadpush` package, so a same-UID
  agent could no-op the guardrails by editing the package — defeating even a
  root-immutable hook file. Hardened hooks now run `/var/db/deadpush/venv/bin/
  python` (owned by `_deadpush`, not user-writable). The guardian's auto-repair
  re-pins this interpreter and re-locks `schg` instead of downgrading.
- **Guardrail policy is now read from a root-owned dir (H1)**: enforcement read
  `rules.json` / `learned_patterns.json` from the in-repo `.deadpush/` directory,
  which the agent can write (it could set every category to `off` or allowlist
  `.*`). Hardened installs now read/write policy from a root/`_deadpush`-owned
  tree (`/var/db/deadpush/policy/<repo-id>/`) that the user can traverse and read
  but not modify. Soft mode is unchanged (in-repo, deterrence only).
- **Control server enforces a bearer token on mutations (H3)**: the localhost
  control server shipped with auth wired up but disabled (no token), so any
  local process — including the agent — could reset the allowlist or restore
  quarantined files. A random token is now generated per guardian and stored
  `0600` (root-owned in hardened mode, so the agent can't read it); state-changing
  `POST`s require it (with a constant-time compare), while read-only `GET`s stay
  open so the human dashboard still works.
- **Quarantine restore is confined to the repo tree (H4)**: `restore()` moved a
  file to the absolute "Original path" read from an agent-writable `.reason`
  file, letting a crafted `.reason` make the guardian (running as `_deadpush`)
  write anywhere — a confused-deputy write. The destination is now resolved and
  required to stay within the repo, else the restore is refused.
- **Fail-closed can no longer be cleared by the agent (H5)**: the hooks' fail-
  closed decision keyed only off the agent-deletable in-repo `.deadpush/installed`
  marker. Hardened setup now also writes a root-owned marker under
  `/var/db/deadpush/policy/<repo-id>/`, and the hook prelude honors it, so
  fail-closed holds even if the in-repo marker is deleted. (Combined with H2 the
  root-owned interpreter is itself un-deletable by the agent.)
- **Hardened state dir is now `0711` (was `0700`)**: required so the user's git
  hooks can *traverse* to the root-owned interpreter and policy. The directory is
  not listable and secret files (the control token) remain `0600`.

### Added
- **`SECURITY.md` threat model**: documents the adversary (a same-UID AI agent),
  the soft-vs-hardened guarantees, the inherent limits of heuristic detection, and
  private vulnerability reporting.
- **Real-time move/delete handling**: the watchdog guardian only handled
  `on_created`/`on_modified`, so an agent could evade the real-time layer by
  moving un-scanned content into place (stage a payload in a skipped dir like
  `node_modules/` then `mv` it in, or rename a benign file onto a dangerous
  path/name). `on_moved` now evaluates the destination exactly like a fresh
  write (dangerous content is quarantined). `on_deleted` records forensic
  telemetry (log + session incident) but is deliberately non-punitive — it does
  not auto-restore or dock the safety score, since the score never recovers and
  a legitimate multi-file `git rm`/refactor would otherwise false-trigger
  lockdown; tracked files remain recoverable from git history. Covered by
  `tests/test_move_delete_events.py`.
- **Fail-closed git hooks**: once a repo is protected (a `.deadpush/installed`
  marker is written), the installed hooks refuse to run when the deadpush
  interpreter goes missing, instead of silently allowing the push/commit.
  `DEADPUSH_STRICT=1` forces fail-closed everywhere.
- **`protect` verifies and reports failure**: `deadpush protect` now polls that
  the guardian actually started, and exits non-zero with actionable guidance if
  hooks, the marker, or the daemon did not come up (no more false "success").
- **`doctor` protection checks**: reports the protection marker (and whether the
  pinned interpreter still exists) plus git-hook integrity.
- **Lifecycle integration test** (`tests/test_integration_lifecycle.py`): drives
  the installed CLI and executes the real generated hooks; runs on macOS + Linux
  in CI.
- **Hardened-mode QA harness** (`scripts/hardened_qa.sh`): a manual, root-gated
  end-to-end validator for the hardened guarantees CI cannot cover — privilege
  separation, an agent-unkillable daemon (and launchd/systemd respawn),
  root-immutable `schg`/`+i` hooks, repo + `$HOME`-traverse ACLs, real-time
  quarantine, `core.hooksPath` self-heal, and a verified clean teardown. It runs
  in a throwaway repo, escalates only via `sudo`, and refuses to run when a
  `_deadpush` account already exists so it can't disturb a real install.
- **`core.hooksPath` hijack detection + self-heal**: `git config core.hooksPath
  /dev/null` (or any dir other than `.git/hooks`) silently disabled every hook
  without tripping the checksum/immutability checks. `verify_hooks_installed` now
  flags it, `repair_deadpush_hooks` restores it (repo-local only, overriding a
  global hijack if needed), the running guardian auto-repairs it every cycle, and
  `doctor` reports it. Covered by `tests/test_hookspath_hijack.py`.
- **Root-immutable hooks in hardened mode**: hardened installs now lock the git
  hooks ROOT-immutable (`sudo chflags schg` on macOS, `sudo chattr +i` on Linux)
  instead of only user-immutable (`uchg`). A same-UID agent can no longer clear
  the flag to delete or rewrite a hook — only root can. Soft mode keeps the
  owner-clearable `uchg`. `_is_immutable` now recognises `schg` (so the guardian
  never loops trying to "repair" a locked hook it cannot rewrite), `uninstall`
  clears it via sudo (with an automatic escalation fallback), and if `schg` can't
  be set it fails safe to `uchg` with a loud warning. Covered by
  `tests/test_root_immutable.py`.

### Fixed
- **Pre-push new-branch range can no longer be poisoned (D4)**: for a brand-new
  branch (remote side all-zeros) the hook derived the scan boundary from
  `git rev-list … --not --remotes`, trusting local `refs/remotes/*`. Those refs are
  writable by a same-UID agent, so forging `refs/remotes/x/y` at the payload commit
  made git treat the dangerous content as "already on the remote" and shrank the
  scanned diff to exclude it — while `git push` still shipped those commits. New
  refs now always scan the entire pushed tree (`empty-tree..local_sha`), which
  cannot be poisoned by local refs; existing-branch updates keep using the
  trustworthy `remote_sha` git supplies from the real push negotiation. Covered by
  `tests/test_prepush_newbranch.py`
  (`test_new_branch_push_cannot_be_poisoned_by_fake_remote_ref`).
- **Uninstall leaves the repo pristine**: cleanup only removed an empty
  `.guardian`, leaving behind empty `.deadpush` (e.g. `.deadpush/feedback/`) and
  `.deadpush-quarantine` directories. It now prunes deadpush's own now-empty
  bookkeeping dirs — but strictly non-destructively: a directory is removed only
  when it has no remaining contents, so real feedback data, config, and
  quarantined files are always preserved. Covered by
  `tests/test_integration_lifecycle.py`
  (`test_uninstall_leaves_repo_pristine`, `test_uninstall_preserves_user_data`).
- **Cross-platform uninstall**: `deadpush uninstall` invoked `launchctl`
  unconditionally, which raised `FileNotFoundError` on Linux and made the command
  exit non-zero. It now unloads/removes the correct service per platform (launchd
  plist on macOS, systemd unit on Linux — the systemd unit was previously never
  removed) and treats a missing/inactive service manager as a no-op.
- **Hardened-mode teardown parity on Linux**: hardened setup already supported
  Linux (`useradd`/`groupadd`/`setfacl`), but uninstall only ran macOS
  `dscl`/`chmod -N`, so it crashed on Linux and orphaned the `_deadpush`
  account/ACLs. Added `teardown_hardened_environment`, a platform-aware,
  best-effort reversal that revokes every `_deadpush` ACL (repo tree,
  `.guardian`, and parent traverse dirs — a shared walk with setup so the two
  can't drift) and deletes the account (macOS `dscl`, Linux `userdel`/`groupdel`),
  revoking ACLs before removing the account. Covered by
  `tests/test_hardened.py::TestTeardownHardenedEnvironment`.

### Changed
- **Wider git-hook file coverage**: the pre-commit/pre-push/post-commit hooks
  gated content scanning on a small extension allowlist (~18 types), so an agent
  could commit dangerous content in files the hooks never read — extensionless
  and config files such as `Dockerfile`, `Makefile`, `.env`, `.npmrc`, shell
  rc-files, and LLM-context files like `.cursorrules` / `.claude_instructions`
  (the watchdog daemon already scanned these; the hooks did not). A shared
  `is_enforceable_path()` now mirrors the daemon's coverage: a much wider set of
  code/config/infra/text extensions plus sensitive-by-name and `.env*` /
  `Dockerfile*` files, while binary formats (images, archives, compiled objects,
  keystores) are always skipped. Covered by `tests/test_file_coverage.py`.
- **Robust hook/daemon entrypoint**: generated hooks, the launchd/systemd units,
  and the shadow respawn command now launch via `deadpush_bootstrap` instead of
  `-m deadpush.cli`, so they work in editable installs where macOS hides the
  `.pth` file (previously the guardian and hooks failed to import deadpush from a
  non-source working directory).
- **Single source of truth for version**: `pyproject.toml` derives the version
  from `deadpush/__init__.py` (hatchling dynamic version); metadata and
  `deadpush.__version__` can no longer drift.

### CI / tooling
- Ruff is now a **blocking** gate; the codebase is lint-clean.
- `uv.lock` is committed and CI runs `uv lock --check` + `uv sync --frozen` for
  reproducible builds.
- CI test matrix runs on **macOS and Linux** across supported Python versions.

### Fixed
- **launchctl bootstrap bug**: `protect` no longer marks the guardian as
  bootstrapped when `launchctl bootstrap` fails; it now falls back to a direct
  daemon launch and verifies the result.
- `uninstall` now also removes the deadpush git hooks and the protection marker,
  so a full uninstall truly leaves nothing behind.
- **Pre-push scanning of new branches**: pushing a brand-new branch (remote side
  all-zeros) previously diffed the working tree against the tip and scanned
  nothing, letting a first push bypass content enforcement. New commits are now
  resolved against the boundary already on the remote (or the whole tree when
  there is no shared history) and scanned. Covered by `tests/test_prepush_newbranch.py`.
- **Test isolation / macOS notification spam**: the autostart unit tests wrote
  real plists into `~/Library/LaunchAgents` (path derived from `$HOME`, not the
  temp repo), triggering a macOS "app can run in the background" notification per
  run and littering hundreds of stale plists. They now use the isolated
  `hardened_env` fixture.

### Packaging
- **Homebrew formula rewrite** (`Formula/deadpush.rb`): switched from a fragile
  `pip3 install --prefix` to `virtualenv_install_with_resources` with runtime
  dependencies pinned to the `uv.lock` versions (`click`, `pathspec`, `watchdog`),
  a Homebrew-audit-clean `desc`, and a `--version` test. Passes `brew style`.
  A release helper (`scripts/brew_release.sh`) fills the source `sha256` and runs
  audit/install/test. Note: `brew install` requires the repo to be **public** with
  the release tag pushed; the `sha256` is a placeholder until then.

---

## [1.0.0] - unreleased

_Historical notes previously drafted under a 1.0.0 heading; not yet released._

### Added
- **Log rotation**: RotatingFileHandler (10MB × 5 files) prevents unbounded log growth
- **Safety score JSON persistence**: Structured `safety_score.json` in state dir, auto-saved on every incident, read by MCP server
- **MCP Bearer token authentication**: Optional token auth for GuardianControlServer endpoints
- **Health endpoint**: `GET /health` on GuardianControlServer for launchd/systemd health checks
- **CLI: doctor**: Comprehensive health check (`deadpush doctor`)
- **CLI: uninstall**: Complete removal including hardened mode cleanup (`deadpush uninstall`)
- **CLI: init**: Guided first-time setup (`deadpush init --mode default|hardened --daemon`)
- **Hardened mode**: Full privilege separation via dedicated `_deadpush` user/group
  - Dedicated `_deadpush` group (not wheel) — eliminates root escalation risk
  - ACLs on repo (read) + `.guardian/` (write), hooks write access removed
  - LaunchDaemon with `UserName=_deadpush`, state in `/var/db/deadpush/`
  - `setup_hardened_environment()` one-time sudo setup
- **Lock/PID improvements**: Holder PID stored in lock file, start-time verification, `--force` cleanup
- **Daemon fork safety**: Handler and control server created post-fork, FD closure
- **Shadow process hardening**: Health checks via `ps`, exponential backoff, PID coordination
- **Lock manager**: Holder PID in lock file, `force_cleanup()`, `--force` CLI flag
- **Test scripts**: `scripts/soak_test.py` (multi-repo), `scripts/stress_test.py` (high-concurrency)
- **CI/CD**: GitHub Actions workflow for building wheels, publishing to PyPI, GitHub Releases
- **Homebrew formula**: Template formula for `brew install deadpush`

### Changed
- **Per-repo hardened flag**: Replaced global `_hardened_enabled` with explicit `hardened` parameter on all functions
- **Safety score storage**: Migrated from log parsing to structured JSON (`safety_score.json`)
- **MCP safety score tool**: Now reads structured JSON instead of log parsing
- **Lock manager**: Added holder PID tracking, force cleanup, `get_holder_pid()`
- **Daemon fork safety**: `GuardianHandler` and `GuardianControlServer` created post-fork, all inherited FDs closed
- **Shadow process**: Health checks via `ps`, exponential backoff (3s→60s), max 10 failures, PID file coordination
- **PID reuse protection**: Start time verification via `ps -o etimes=` + command line check
- **TOCTOU lock fix**: Holder PID stored, `--force` cleanup flag

### Security
- Removed `_deadpush` from wheel group — eliminated root escalation via sudoers
- Removed hook write ACL for `_deadpush` — guardian no longer modifies `.git/hooks/`
- Dedicated `_deadpush` group with GID 499

### Fixed
- PID reuse false positive in `DaemonManager.is_running()`
- TOCTOU race in lock acquisition
- Fork crash from thread-before-fork in daemon mode
- Duplicate `_require_auth` method in control handler

---

## [0.2.1] - 2026-06-20

### Added
- Multi-agent Safety Score with burst detection
- Session tracking (events, recent files, duration)
- Per-repo scoped state files (PID, lock, port, suspend, plist)
- Launchd/systemd autostart config generation
- Shadow process for guardian respawn
- MCP server with stdio transport
- Agent-as-Adjudicator feedback loop
- Debris detection (LLM context files, vibe scratchpads, secrets, duplicates)
- Layer violation detection (architecture import rules)
- Smart ignore file auto-merge

### Changed
- Safety score now tracks multi-agent bursts
- Path-aware guardrail lowering for test/mock files
- Learned false positive patterns persisted to `.deadpush/learned_patterns.json`

---

## [0.1.0] - 2026-06-10

### Added
- Initial release
- Real-time filesystem guardian with watchdog
- 7-category guardrail pipeline (security, secrets, prompt injection, debris, layers, destructive, sensitive config)
- Call graph dead code analysis with 8-factor scoring
- Git pre-push hook installation
- Quarantine system (safe restore via git)
- Static call graph resolution
- Basic MCP server with stdio transport