# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Staged for the next release. The project stays on a 0.2.x beta line until the
production-readiness gates (blocking lint, lockfiled reproducible builds, and
green macOS + Linux CI including the lifecycle integration test) are met._

### Added
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