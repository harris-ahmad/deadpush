# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-27

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