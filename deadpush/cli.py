"""deadpush CLI — AI Agent Guardian."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .config import load_config
from .ui import is_rich_available, print_error, print_header, print_success, print_warning


def _auto_merge_ignore_files(repo_root: Path, new_patterns: set[str]):
    from .hooks import merge_guardian_ignore_files
    merge_guardian_ignore_files(repo_root, new_patterns)


@click.group()
@click.version_option(package_name="deadpush")
def main():
    """deadpush — Guardrails for the vibe coding era."""
    pass


@main.command("guard")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root to guard (default: auto-detect from cwd)")
@click.option("--no-intervention", is_flag=True, help="Warning mode only (no blocking/quarantine)")
@click.option("--daemon", is_flag=True, help="Run as background daemon")
@click.option("--strict", is_flag=True, help="Enable strict intervention mode")
@click.option("--soft", is_flag=True, help="Dev-only: run as your UID (agent can kill guardian)")
@click.option("--hardened", is_flag=True, help="Run as _deadpush user (default unless --soft)")
def cmd_guard(repo, no_intervention, daemon, strict, soft, hardened):
    """
    Start the AI Agent Guardian.

    This is the core always-on protection while using AI coding agents.
    """
    from .guard import run_guardian
    import os
    intervention = not no_intervention
    use_hardened = not soft
    if hardened:
        use_hardened = True
    if soft and hardened:
        print_error("Cannot use --soft with --hardened")
        return
    if repo:
        os.chdir(Path(repo).resolve())
    run_guardian(intervention=intervention, daemon=daemon, strict=strict, hardened=use_hardened)


@main.command("protect")
@click.option("--enable", is_flag=True, help="Enable persistent background guardian (auto-starts daemon after setup)")
@click.option("--daemon", is_flag=True, help="Start the guardian as a persistent background daemon after performing full setup")
@click.option("--soft", is_flag=True, help="Dev-only: same-UID guardian (agent can pkill it; not production-safe)")
@click.option("--hardened", is_flag=True, help="Explicitly request hardened mode (default unless --soft)")
@click.option(
    "--allow-self-protect",
    is_flag=True,
    help="Allow protecting the deadpush source repo itself (not recommended for development)",
)
def cmd_protect(enable, daemon, soft, hardened, allow_self_protect):
    """
    One-command setup to protect your vibe coding workflow.

    This is the primary "set it and forget it" command. It:
    - Installs a git pre-push hook for safety
    - Auto-updates .cursorignore / .claudeignore / .gitignore with AI/dead-code patterns
    - (with --daemon / --enable) Starts the real-time AI Agent Guardian in the background
      (survives terminal close, handles multi-agent activity)

    Run this once per repo (or after major changes) then walk away.
    The guardian will monitor, score, quarantine dangerous files autonomously.
    """
    from .config import is_guardian_dev_repo
    config = load_config()

    if is_guardian_dev_repo(config.repo_root) and not allow_self_protect:
        print_error("Refusing to protect the deadpush development repository.")
        print_error(
            "Running protect here installs git hooks and a filesystem guardian that "
            "will block your own commits and quarantine source files."
        )
        print("Test in a throwaway clone instead:")
        print("  git clone . /tmp/deadpush-e2e && cd /tmp/deadpush-e2e && deadpush protect")
        print("Or pass --allow-self-protect to override (not recommended).")
        return

    start_background = bool(enable or daemon)
    use_hardened = not soft
    if hardened:
        use_hardened = True
    if soft and hardened:
        print_error("Cannot use --soft with --hardened")
        return

    # If hardened mode, do the one-time privilege separation setup first
    if use_hardened:
        print("\n[0/4] Setting up hardened environment (privilege separation)...")
        from .guard import setup_hardened_environment
        try:
            summary = setup_hardened_environment(config.repo_root, auto_load=start_background)
            print(summary)
        except Exception as e:
            print_warning(f"Hardened environment setup failed: {e}")
            print_warning("Try running with sudo directly, or check system logs.")
            return
    elif start_background:
        print_warning("Running in --soft mode: guardian uses your UID and can be killed by agents.")

    print_header("deadpush Protect", "One-command setup for AI Agent Guardian (persistent background protection)")

    # 1. Install git hooks (pre-push + pre-commit + post-commit)
    print("\n[1/3] Installing git hooks (pre-push, pre-commit, post-commit)...")
    try:
        from .hooks import install_hook
        install_hook(config.repo_root)
    except Exception as e:
        print_warning(f"Pre-push hook installation issue: {e}")
        print_warning("  (Tip: ensure this is a git repo with .git/hooks/)")
    try:
        from .hooks import install_precommit_hook
        install_precommit_hook(config.repo_root)
        print("  Also installed pre-commit guardrail hook.")
    except Exception as e:
        print_warning(f"Pre-commit hook installation issue: {e}")
    try:
        from .hooks import install_postcommit_hook
        install_postcommit_hook(config.repo_root)
        print("  Also installed post-commit guardrail hook (catches --no-verify bypass).")
    except Exception as e:
        print_warning(f"Post-commit hook installation issue: {e}")
    try:
        from .hooks import verify_hooks_installed
        problems = verify_hooks_installed(config.repo_root)
        if problems:
            print_warning(f"  Hook verification issues: {', '.join(problems)}")
            print_warning("  Re-run `deadpush protect` to repair hooks.")
        else:
            print_success("  All git guardrail hooks verified (checksums OK).")
    except Exception as e:
        print_warning(f"Hook verification skipped: {e}")
    try:
        from .hooks import setup_mcp_discovery
        setup_mcp_discovery(config.repo_root)
        print("  Agent auto-discovery configured (.cursor/mcp.json, .vscode/mcp.json).")
    except Exception as e:
        print_warning(f"MCP discovery setup issue: {e}")

    # GitHub Actions server-side guard (must be committed to take effect)
    try:
        from .hooks import setup_github_guard_action
        action_path = setup_github_guard_action(config.repo_root)
        if action_path:
            from .hooks import _make_immutable
            _make_immutable(action_path)
    except Exception as e:
        print_warning(f"GitHub Action guard setup issue: {e}")

    # 2. Generate + merge smart ignore patterns into the real ignore files
    #    (this is the key hands-off part - users no longer have to manually curate)
    print("\n[2/3] Updating smart ignore files (.cursorignore, .claudeignore, .gitignore)...")
    try:
        from .hooks import merge_guardian_ignore_files
        merge_guardian_ignore_files(config.repo_root)
        print_success("  Smart ignores merged/updated.")
    except Exception as e:
        print_warning(f"  Ignore file update skipped (non-fatal): {e}")

    # 3. Optionally start the persistent guardian in background + set up agent-native MCP control
    print("\n[3/3] Guardian + Agent Control setup...")
    if start_background:
        print("Starting AI Agent Guardian in persistent background (daemon) mode...")
        print("  (Survives terminal close/logout. Use `deadpush status` to inspect.)")

        # Ensure directories for feedback and quarantine
        try:
            from .intercept import FEEDBACK_DIR, QUARANTINE_DIR
            for d in [FEEDBACK_DIR, QUARANTINE_DIR]:
                (config.repo_root / d).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # Auto-start helpers for reboot survival (AGENT priority 2)
        try:
            from .guard import run_guardian, setup_autostart, _scoped_plist_path
            autostart_info = setup_autostart(config.repo_root, hardened=use_hardened)
            if autostart_info:
                print("\n[Auto-start for reboots]")
                print(autostart_info)
        except Exception as e:
            print_warning(f"Autostart helper generation skipped (non-fatal): {e}")

        # In hardened mode, the daemon was already loaded by setup_hardened_environment().
        # In default mode, bootstrap the launchd plist so guardian runs under launchd.
        if not use_hardened:
            plist_path = _scoped_plist_path(config.repo_root)
            _bootstrapped = False
            if plist_path.exists():
                try:
                    import subprocess, os
                    uid = os.getuid()
                    result = subprocess.run(
                        ["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode == 0:
                        _bootstrapped = True
                    else:
                        _bootstrapped = True
                except Exception:
                    pass

            # If bootstrap failed or on non-macOS, fall back to direct daemon launch
            if not _bootstrapped:
                print("  (launchd bootstrap unavailable — starting guardian directly)")
                try:
                    run_guardian(intervention=True, daemon=True, strict=False, hardened=use_hardened)
                except SystemExit:
                    pass
                except Exception as e:
                    print_warning(f"Daemon launch had issue (try `deadpush guard --daemon`): {e}")
            else:
                print_success("✅ Guardian launched under launchd (auto-restarts if killed).")
        else:
            print_success("✅ Guardian running as _deadpush under launchd.")

        print_success("✅ Protection setup + daemon launch complete!")

        # Prominent MCP / Local Control instructions for AI agents (the key new feature in AGENT.md)
        print("\n=== For your AI coding agents (Claude, Cursor, Windsurf, etc.) ===")
        print("Configure your agent to launch this as its MCP / tool server:")
        print("    deadpush mcp")
        print("")
        print("This gives agents native, guardrailed tools over stdio (MCP protocol):")
        print("  - write_file   : write only if it passes all guardrails (layers, secrets, injection, etc.)")
        print("  - check_file   : preview whether a write would be blocked")
        print("  - get_feedback : see why previous writes were blocked")
        print("  - get_status   : current guardrail configuration")
        print("")
        print("Agents can now safely write code without you in the loop, while the background")
        print("guardian (launchd-managed) continues its FS watching + Safety Score.")
    else:
        print_success("Protection setup complete (hooks + ignores).")
        print("Guardian NOT started in background.")
        print("  Start with: deadpush protect --daemon  (or --enable)")
        print("")
        print("For AI agents, also tell them to use:")
        print("    deadpush mcp")
        print("as their tool server (gives them guardrailed writes).")


@main.group("session")
def cmd_session():
    """Manage vibe coding sessions.

    Sessions help you track what happened during a period of AI-assisted coding.
    Start a session before you begin vibe coding, then end it when you're done.
    The guardian can tag all interventions with the active session.
    """
    pass


@cmd_session.command("start")
@click.option("--label", "-l", default="", help="A label for this session (e.g. 'adding stripe payments')")
def cmd_session_start(label):
    """Start a new vibe coding session."""
    from .session import SessionManager
    mgr = SessionManager()
    existing = mgr.get_active_session()
    if existing:
        print_warning(f"Session '{existing.label}' is already active (started {existing.start_time}).")
        if not click.confirm("End it and start a new one?"):
            return
        mgr.end_session()

    session = mgr.start_session(label=label)
    print_success(f"Session started: {session.label}")
    print(f"  ID: {session.id}")
    print(f"  Started: {session.start_time}")
    print()
    print("Run `deadpush session end` to finish this session and get a rollup summary.")
    print("The guardian will tag all interventions during this session.")


@cmd_session.command("end")
def cmd_session_end():
    """End the current vibe session and show a rollup summary."""
    from .session import SessionManager
    mgr = SessionManager()
    active = mgr.get_active_session()
    if not active:
        print_warning("No active session to end.")
        return

    session = mgr.end_session()
    if session:
        print_success("Session ended.")
        print()
        summary = mgr.get_session_summary(session)
        click.echo(summary)
    else:
        print_error("Could not end session.")


@cmd_session.command("status")
def cmd_session_status():
    """Show the active session info."""
    from .session import SessionManager
    mgr = SessionManager()
    active = mgr.get_active_session()
    if not active:
        print_warning("No active session. Start one with `deadpush session start`.")
        return

    print_header("Active Vibe Session", active.label)
    print(f"  Started: {active.start_time}")
    print(f"  Files changed: {len(active.files_changed)}")
    print(f"  Incidents: {len(active.incidents)}")
    print(f"  Safety: {active.safety_score_start} → {active.safety_score_end or active.safety_score_start}")

    if active.files_changed:
        print(f"\n  Files touched ({len(active.files_changed)}):")
        for f in active.files_changed[-10:]:
            print(f"    - {f}")
        if len(active.files_changed) > 10:
            print(f"    ... and {len(active.files_changed) - 10} more")

    if active.incidents:
        print(f"\n  Recent incidents ({len(active.incidents)} total):")
        for inc in active.incidents[-5:]:
            print(f"    - {inc.get('reason', '?')}")


@cmd_session.command("log")
@click.option("--limit", type=int, default=10, help="Number of sessions to show")
def cmd_session_log(limit):
    """Show session history."""
    from .session import SessionManager
    mgr = SessionManager()
    history = mgr.get_session_history(limit=limit)

    if not history:
        print_warning("No completed sessions yet.")
        return

    print_header("Vibe Session History", f"Last {len(history)} sessions")
    for session in history:
        summary = mgr.get_session_summary(session)
        # Only show first line
        first_line = summary.split("\n")[0]
        score_info = ""
        if session.safety_score_end is not None:
            diff = session.safety_score_end - session.safety_score_start
            score_info = f" | Safety: {session.safety_score_start}→{session.safety_score_end} ({'+' if diff >= 0 else ''}{diff})"
        print(f"  {session.id} - {first_line}{score_info}")
        print(f"           {len(session.files_changed)} files, {len(session.incidents)} incidents")
        print()


@main.command("status")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect from cwd)")
@click.option("--hardened", is_flag=True, help="Show status of a hardened guardian")
def cmd_status(repo, hardened):
    """Show whether the guardian is running, latest Safety Score, recent incidents, and session info.

    This is the primary way to check on your always-on protector without reading logs manually.
    """
    from .config import load_config
    from .guard import DaemonManager, _scoped_pidfile, _scoped_lockfile, _scoped_portfile, _scoped_log_file, _state_dir

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root
    pid_dir = _state_dir(hardened)
    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)
    dm = DaemonManager(pidfile, lockfile)
    running = dm.is_running()

    print_header("deadpush Status", f"AI Agent Guardian - {repo_root.name}")

    if running:
        try:
            pid = int(pidfile.read_text().strip())
            print_success(f"🟢 Guardian is RUNNING (PID {pid})")
        except Exception:
            print_success("🟢 Guardian is RUNNING")
    else:
        print_warning(f"🔴 Guardian is NOT currently running for {repo_root.name}.")
        print("   Start it with the hands-off command:")
        print("     deadpush protect --daemon")
        print("   Or:")
        print("     deadpush guard --daemon")

    log = _scoped_log_file(repo_root, hardened)
    if log.exists():
        try:
            text = log.read_text(errors="ignore")
            lines = text.strip().splitlines()[-40:] if text.strip() else []
            # last score/status line
            last_status = None
            for ln in reversed(lines):
                if "Safety:" in ln or "Score:" in ln or "Status:" in ln:
                    last_status = ln
                    break
            print("\nLatest Safety Score / status (from log):")
            if last_status:
                click.echo("  " + last_status)
            else:
                click.echo("  (no recent score line found)")

            # recent interventions (actionable)
            intervs = [ln for ln in lines if "INTERVENTION" in ln or "QUARANTINED" in ln or "Critical file" in ln]
            if intervs:
                print("\nRecent guardian actions / incidents:")
                for iv in intervs[-6:]:
                    click.echo("  " + iv)
            else:
                print("\nNo intervention actions in recent log tail.")

            print(f"\nLog file: {log}")
            print("Live tail: tail -f " + str(log))
        except Exception as e:
            print_warning(f"Could not parse recent log: {e}")
    else:
        print_warning("No guardian.log found yet (start the guardian to begin logging).")

    print("\nOther checks:")
    print("  - Per-repo quarantines: cd your-repo ; deadpush quarantine list")
    print("  - Health check: deadpush doctor")

    # Show control interface if running
    port_file = _scoped_portfile(repo_root, hardened)
    if not port_file.exists() and hardened:
        port_file = config.repo_root / ".guardian" / "guardian.control.port"
    if port_file.exists():
        try:
            port = port_file.read_text().strip()
            print(f"\nLocal Control Interface (for AI agents): http://127.0.0.1:{port}")
            print("  Agents can GET /status, /quarantine-list, /safety-score, etc.")
        except Exception:
            pass


# =============================================================================
# Quarantine management (Priority per AGENT.md - easy review/restore builds trust)
# =============================================================================
@main.group("quarantine")
def cmd_quarantine():
    """Manage files the guardian has quarantined (safer than delete).

    Use these to review what was auto-quarantined and restore if it was a false positive.
    This is critical for "aggressive intervention" without user fear.
    """
    pass


@cmd_quarantine.command("list")
@click.option("--limit", type=int, default=None, help="Max number of entries to show")
def cmd_quarantine_list(limit):
    """List all currently quarantined files with reasons and original locations."""
    from .guard import QuarantineManager
    config = load_config()
    qm = QuarantineManager(config.repo_root)
    entries = qm.list_quarantined()
    if limit:
        entries = entries[:limit]
    if not entries:
        print_success("No files are currently quarantined. Everything looks clean!")
        return

    if is_rich_available():
        try:
            from rich.console import Console
            from rich.table import Table
            table = Table(title="Quarantined by deadpush Guardian", box=None)
            table.add_column("Quarantined Name", style="cyan")
            table.add_column("When", style="dim")
            table.add_column("Reason", style="yellow")
            table.add_column("Original Path", style="green")
            for e in entries:
                table.add_row(
                    e["name"],
                    str(e.get("quarantined_at", e.get("mtime", "")))[:19],
                    e.get("reason", "(unknown)")[:60],
                    str(e.get("original_path", "(unknown)")),
                )
            Console().print(table)
            print(f"\n{len(entries)} quarantined file(s) in {qm.quarantine_dir}")
        except Exception:
            # fallback plain
            for e in entries:
                click.echo(f"- {e['name']} | {e.get('reason','?')} | orig: {e.get('original_path','?')}")
    else:
        for e in entries:
            click.echo(f"- {e['name']} | reason: {e.get('reason','?')} | would restore to: {e.get('original_path','?')}")
        click.echo(f"\nTotal: {len(entries)} in {qm.quarantine_dir}")


@cmd_quarantine.command("restore")
@click.argument("quarantined_path")
def cmd_quarantine_restore(quarantined_path):
    """Restore a quarantined file to its original location.

    QUARANTINED_PATH can be the filename shown in `list` or full path inside the quarantine dir.
    """
    from .guard import QuarantineManager
    config = load_config()
    qm = QuarantineManager(config.repo_root)
    restored = qm.restore(quarantined_path)
    if restored:
        print_success(f"Restored successfully to: {restored}")
        print_warning("Review the file and consider adding exceptions if this was a false positive.")
    else:
        print_error(f"Could not restore '{quarantined_path}'. Check the name with `deadpush quarantine list`, or the original location may already exist.")


@cmd_quarantine.command("clear")
@click.option("--older-than", "older_than", type=int, default=None, help="Only clear items older than this many days (default: all)")
@click.option("--force", is_flag=True, help="Do not ask for confirmation (dangerous)")
def cmd_quarantine_clear(older_than, force):
    """Permanently delete quarantined files (and their metadata).

    By default clears everything. Use --older-than for pruning old ones.
    """
    from .guard import QuarantineManager
    config = load_config()
    qm = QuarantineManager(config.repo_root)
    if not force:
        msg = "Permanently delete ALL quarantined files" if older_than is None else f"Permanently delete quarantined files older than {older_than} days"
        if not click.confirm(f"{msg}? This cannot be undone."):
            print("Aborted.")
            return
    n = qm.clear(older_than_days=older_than)
    print_success(f"Cleared {n} quarantined item(s).")


@main.group("hooks")
def cmd_hooks():
    """Manage deadpush git hooks."""
    pass


@cmd_hooks.command("uninstall")
def cmd_hooks_uninstall():
    """Remove deadpush-installed git hooks from this repo."""
    config = load_config()
    from .hooks import uninstall_deadpush_hooks

    removed = uninstall_deadpush_hooks(config.repo_root)
    if removed:
        print_success(f"Removed deadpush hooks: {', '.join(removed)}")
    else:
        print("No deadpush hooks found to remove.")


@cmd_hooks.command("install-precommit")
def cmd_hooks_install_precommit():
    """Install the pre-commit guardrail hook.

    Blocks commits with prompt injection, hardcoded secrets,
    security violations, and architecture layer violations.
    """
    config = load_config()
    try:
        from .hooks import install_precommit_hook
        install_precommit_hook(config.repo_root)
        print_success("Pre-commit guardrail hook installed.")
    except Exception as e:
        print_error(f"Failed to install pre-commit hook: {e}")


@cmd_hooks.command("run-precommit")
def cmd_hooks_run_precommit():
    """Run guardrails on staged files (called by the pre-commit hook).

    Exits with code 1 if violations are found, blocking the commit.
    """
    config = load_config()
    from .hooks import run_precommit_guardrails
    passed, violations = run_precommit_guardrails(config.repo_root)
    sys.exit(0 if passed else 1)


@cmd_hooks.command("install-postcommit")
def cmd_hooks_install_postcommit():
    """Install the post-commit guardrail hook.

    Reverts commits containing dangerous code even if --no-verify was used.
    """
    config = load_config()
    try:
        from .hooks import install_postcommit_hook
        install_postcommit_hook(config.repo_root)
        print_success("Post-commit guardrail hook installed.")
    except Exception as e:
        print_error(f"Failed to install post-commit hook: {e}")


@cmd_hooks.command("run-postcommit")
def cmd_hooks_run_postcommit():
    """Run guardrails on the last commit's files (called by the post-commit hook).

    Exits with code 1 if violations found and commit was reverted.
    """
    config = load_config()
    from .hooks import run_postcommit_guardrails
    passed, violations = run_postcommit_guardrails(config.repo_root)
    sys.exit(0 if passed else 1)


@cmd_hooks.command("run-prepush")
def cmd_hooks_run_prepush():
    """Run guardrails on commits being pushed (called by the pre-push hook).

    Reads stdin (standard pre-push format) to determine the commit range
    and checks all files in those commits for violations.
    Exits with code 1 if violations are found, blocking the push.
    """
    config = load_config()
    from .hooks import run_prepush_guardrails
    passed, violations = run_prepush_guardrails(config.repo_root)
    sys.exit(0 if passed else 1)

@main.command("intercept")
@click.option("--daemon", is_flag=True, help="Run as persistent background daemon")
def cmd_intercept(daemon):
    """Start the file interception daemon (alias for `deadpush guard`).

    Uses the watchdog-based guardian to monitor all file writes and
    enforce guardrails. The staging-based intercept has been removed;
    the guardian daemon covers every write through the filesystem.
    """
    from .guard import run_guardian
    run_guardian(intervention=True, daemon=daemon, strict=False)


@main.command("mcp")
@click.option("--danger", is_flag=True, help="⚠️  Allow guardrail weakening (enable set_guardrail_level, add_allowed_pattern, reset_runtime_config, ignore_path). Only use this if you understand the risks.")
@click.option("--hardened", is_flag=True, help="Connect to a hardened guardian")
def cmd_mcp(danger, hardened):
    """Start the Model Context Protocol server for AI agent integration.

    Runs over stdio. Any MCP-compatible agent (Cursor, Claude Desktop, etc.)
    can connect and call all deadpush capabilities as native tools:
      - write_file / check_file: guardrailed file writing
      - quarantine_list / quarantine_restore: manage quarantined files
      - get_feedback / get_status / get_safety_score

    By default, guardrail-softening tools (set_guardrail_level, add_allowed_pattern,
    reset_runtime_config, ignore_path) are disabled. Use --danger to enable them
    (you accept the security risk).

    All tools return structured JSON. Configure your agent to run: deadpush mcp
    """
    from .mcp_server import run_mcp
    run_mcp(danger_mode=danger, hardened=hardened)


@main.command("unfreeze")
@click.option("--hardened", is_flag=True, help="Target a hardened guardian")
def cmd_unfreeze(hardened):
    """Clear the MCP suspension flag and restore normal operation.

    When the guardian detects an agent actively fighting guardrails (score ≤ 5),
    it suspends MCP access. Run this command to re-enable it.
    """
    from .config import load_config
    from .guard import _scoped_suspend_file

    config = load_config()
    suspend_file = _scoped_suspend_file(config.repo_root, hardened)
    if suspend_file.exists():
        suspend_file.unlink()
        print("MCP suspension cleared. Agents can now use `deadpush mcp` again.")
    else:
        print("No suspension flag found. MCP is already active.")


@main.command("stop")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root to stop (default: auto-detect from cwd)")
@click.option("--hardened", is_flag=True, help="Stop a hardened guardian")
@click.option("--force", is_flag=True, help="Force cleanup of stale lock/PID files (use if guardian crashed)")
def cmd_stop(repo, hardened, force):
    """Stop the deadpush guardian and clean up.

    Sends SIGTERM to the guardian (which saves safety score with a clean-shutdown
    marker so restart doesn't trigger the "killed by agent" penalty), unloads the
    launchd plist, kills shadow processes, removes immutable flags from hooks,
    and cleans up PID / lock files.
    """
    import os
    import signal
    import subprocess
    import time

    from .config import load_config
    from .guard import (
        _scoped_pidfile,
        _scoped_lockfile,
        _scoped_portfile,
        _scoped_plist_label,
        _scoped_plist_path,
        stop_shadow_for_repo,
    )
    from .hooks import _make_mutable

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root
    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)
    plist_label = _scoped_plist_label(repo_root)
    plist_path = _scoped_plist_path(repo_root, hardened)
    portfile = _scoped_portfile(repo_root, hardened)
    shadow_pidfile = pidfile.with_suffix(".shadow")

    # Force cleanup mode: just remove all state files and exit
    if force:
        from .guard import DaemonManager
        dm = DaemonManager(pidfile, lockfile)
        dm.force_cleanup()
        # Also clean up plist and shared port
        if hardened:
            try:
                subprocess.run(["sudo", "rm", "-f", str(plist_path)], capture_output=True, timeout=10)
                subprocess.run(["sudo", "rm", "-f", str(repo_root / ".guardian" / "guardian.control.port")], capture_output=True, timeout=10)
            except Exception:
                pass
        else:
            if plist_path.exists():
                plist_path.unlink()
            shared_port = repo_root / ".guardian" / "guardian.control.port"
            if shared_port.exists():
                shared_port.unlink()
        print("Forced cleanup complete. All guardian state removed.")
        return

    guardian_killed = False
    shadow_killed = False

    # 1. Kill shadow processes first (they re-spawn the guardian) — repo-scoped only
    if not hardened:
        count = stop_shadow_for_repo(repo_root, hardened)
        if count:
            shadow_killed = True
            print(f"  Killed {count} shadow process(es)")
            time.sleep(0.2)

    # 2. Kill guardian via PID file for this repo only
    guardian_pid = None
    if hardened:
        try:
            r = subprocess.run(
                ["sudo", "cat", str(pidfile)],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                guardian_pid = int(r.stdout.strip())
        except Exception:
            pass
    elif pidfile.exists():
        try:
            guardian_pid = int(pidfile.read_text().strip())
        except (ValueError, OSError):
            pass

    if guardian_pid:
        try:
            if hardened:
                r = subprocess.run(
                    ["sudo", "kill", "-0", str(guardian_pid)],
                    capture_output=True, timeout=5,
                )
                if r.returncode != 0:
                    raise OSError("not running")
                subprocess.run(
                    ["sudo", "kill", str(guardian_pid)],
                    capture_output=True, timeout=5,
                )
            else:
                os.kill(guardian_pid, 0)  # check alive
                os.kill(guardian_pid, signal.SIGTERM)
            # Wait briefly so shutdown handler runs mark_clean_shutdown()
            for _ in range(10):
                try:
                    if hardened:
                        r = subprocess.run(
                            ["sudo", "kill", "-0", str(guardian_pid)],
                            capture_output=True, timeout=5,
                        )
                        if r.returncode != 0:
                            break
                    else:
                        os.kill(guardian_pid, 0)
                    time.sleep(0.2)
                except OSError:
                    break
            else:
                # Force kill if still alive
                try:
                    if hardened:
                        subprocess.run(
                            ["sudo", "kill", "-9", str(guardian_pid)],
                            capture_output=True, timeout=5,
                        )
                    else:
                        os.kill(guardian_pid, signal.SIGKILL)
                except OSError:
                    pass
            guardian_killed = True
            print(f"  Guardian PID {guardian_pid} stopped")
        except OSError:
            print(f"  Guardian PID {guardian_pid} not running (stale PID file)")

    # 3. Launchctl bootout (unload plist, prevents re-spawn)
    try:
        if hardened:
            r = subprocess.run(
                ["sudo", "launchctl", "bootout", "system", plist_label],
                capture_output=True, text=True, timeout=10,
            )
        else:
            uid = os.getuid()
            r = subprocess.run(
                ["launchctl", "bootout", f"gui/{uid}/{plist_label}"],
                capture_output=True, text=True, timeout=10,
            )
        if r.returncode == 0:
            print("  launchd plist unloaded")
        elif "not found" in r.stderr.lower() or "does not exist" in r.stderr.lower():
            pass  # not loaded — fine
        else:
            print(f"  launchctl bootout: {r.stderr.strip()}")
    except Exception:
        pass

    # 5. Remove the plist from LaunchAgents / LaunchDaemons
    try:
        if hardened:
            r = subprocess.run(["sudo", "test", "-e", str(plist_path)], capture_output=True, timeout=5)
            if r.returncode == 0:
                subprocess.run(["sudo", "rm", str(plist_path)], capture_output=True, text=True, timeout=10)
                print(f"  Removed {plist_path.name}")
        elif plist_path.exists():
            plist_path.unlink()
            print(f"  Removed {plist_path.name}")
    except OSError as e:
        print(f"  Could not remove plist: {e}")

    # 6. Clean up PID / lock / port / shadow files for this repo only
    for f in [pidfile, lockfile, portfile, shadow_pidfile]:
        try:
            if hardened:
                subprocess.run(["sudo", "rm", "-f", str(f)], capture_output=True, text=True, timeout=10)
            elif f.exists():
                f.unlink()
        except OSError:
            pass

    # 6b. Clean up shared port file (hardened mode)
    if hardened:
        shared_port = repo_root / ".guardian" / "guardian.control.port"
        try:
            subprocess.run(["sudo", "rm", "-f", str(shared_port)], capture_output=True, text=True, timeout=10)
        except OSError:
            pass

    # 7. Remove immutable flag from git hooks
    try:
        hooks_dir = config.repo_root / ".git" / "hooks"
        if hooks_dir.exists():
            for hook in hooks_dir.iterdir():
                if hook.is_file() and not hook.name.endswith(".sample"):
                    _make_mutable(hook)
            print(f"  Removed immutable flag from hooks")
    except Exception:
        pass

    # 8. Print summary
    if guardian_killed or shadow_killed:
        print("\nGuardian stopped. You can restart it later with:")
        print("  deadpush protect")
    else:
        print("No guardian was running.")



@main.command("uninstall")
@click.option("--hardened", is_flag=True, help="Uninstall hardened guardian (requires sudo)")
@click.option("--force", is_flag=True, help="Force removal without confirmation")
def cmd_uninstall(hardened, force):
    """Completely uninstall deadpush guardian and clean up all state.

    Removes:
    - Guardian process and launchd service
    - PID, lock, port files
    - Safety score and log files
    - Launchd plist
    - Shared port file (hardened)
    - Hardened: _deadpush user, group, ACLs, state directory

    Use --force to skip confirmation prompt.
    """
    from .config import load_config
    from .guard import (
        _scoped_pidfile, _scoped_lockfile, _scoped_portfile,
        _scoped_plist_label, _scoped_plist_path, _state_dir,
        _HARDENED_STATE_DIR
    )
    from .hooks import _make_mutable
    import subprocess
    import os
    import shutil

    if hardened:
        from .guard import _use_hardened
        _use_hardened()

    config = load_config()
    repo_root = config.repo_root

    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)
    portfile = _scoped_portfile(repo_root, hardened)
    plist_label = _scoped_plist_label(repo_root)
    plist_path = _scoped_plist_path(repo_root, hardened)
    state_dir = _state_dir(hardened)
    shared_port_file = repo_root / ".guardian" / "guardian.control.port"

    if not force:
        mode = "hardened" if hardened else "default"
        confirm = input(f"Uninstall deadpush ({mode} mode) for {repo_root}? This will stop the guardian, remove the launchd service, and delete all state. Continue? [y/N]: ")
        if confirm.lower() != "y":
            print("Aborted.")
            return

    print_header("deadpush Uninstall", f"Removing guardian for {repo_root.name}")

    # 1. Stop guardian (reuse stop logic)
    print("\n[1/6] Stopping guardian...")
    from .guard import DaemonManager
    dm = DaemonManager(_scoped_pidfile(repo_root, hardened), _scoped_lockfile(repo_root, hardened))
    if dm.is_running():
        # Try graceful stop first
        try:
            pid = int(pidfile.read_text().strip()) if pidfile.exists() else None
            if pid:
                if hardened:
                    subprocess.run(["sudo", "kill", str(pid)], capture_output=True, timeout=10)
                else:
                    os.kill(pid, 15)  # SIGTERM
                # Wait for graceful shutdown
                import time
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        time.sleep(0.2)
                    except OSError:
                        break
                else:
                    if hardened:
                        subprocess.run(["sudo", "kill", "-9", str(pid)], capture_output=True, timeout=5)
                    else:
                        os.kill(pid, 9)
        except Exception:
            pass
        dm.force_cleanup()
        print("  Guardian stopped")

    # 2. Unload launchd
    print("[2/6] Unloading launchd service...")
    if hardened:
        subprocess.run(["sudo", "launchctl", "bootout", "system", plist_label], capture_output=True, timeout=10)
    else:
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}/{plist_label}"], capture_output=True, timeout=10)
    print("  Launchd service unloaded")

    # 3. Remove plist
    print("[3/6] Removing plist...")
    if hardened:
        subprocess.run(["sudo", "rm", "-f", str(plist_path)], capture_output=True, timeout=10)
    elif plist_path.exists():
        plist_path.unlink()
    print(f"  Removed {plist_path.name}")

    # 4. Clean up state files
    print("[4/6] Cleaning state files...")
    for f in [pidfile, lockfile, portfile]:
        if hardened:
            subprocess.run(["sudo", "rm", "-f", str(f)], capture_output=True, timeout=10)
        elif f.exists():
            f.unlink()

    # Shared port file
    shared_port = repo_root / ".guardian" / "guardian.control.port"
    if hardened:
        subprocess.run(["sudo", "rm", "-f", str(shared_port)], capture_output=True, timeout=10)
    elif shared_port.exists():
        shared_port.unlink()

    # State directory
    if hardened:
        if state_dir.exists():
            subprocess.run(["sudo", "rm", "-rf", str(state_dir)], capture_output=True, timeout=10)
            print(f"  Removed {state_dir}")
    else:
        if state_dir.exists():
            shutil.rmtree(state_dir)
            print(f"  Removed {state_dir}")

    # 5. Remove hardened user/group and ACLs
    if hardened:
        print("[5/6] Removing hardened user, group, and ACLs...")
        # Remove ACLs from repo
        subprocess.run(["sudo", "chmod", "-R", "-N", str(repo_root)], capture_output=True, timeout=30)
        # Remove .guardian dir ACLs
        guardian_dir = repo_root / ".guardian"
        if guardian_dir.exists():
            subprocess.run(["sudo", "chmod", "-R", "-N", str(guardian_dir)], capture_output=True, timeout=10)
        # Remove user and group
        subprocess.run(["sudo", "dscl", ".", "-delete", "/Users/_deadpush"], capture_output=True, timeout=10)
        subprocess.run(["sudo", "dscl", ".", "-delete", "/Groups/_deadpush"], capture_output=True, timeout=10)
        print("  Removed _deadpush user and group, cleared ACLs")
    else:
        # Remove immutable flags from hooks
        try:
            hooks_dir = config.repo_root / ".git" / "hooks"
            if hooks_dir.exists():
                for hook in hooks_dir.iterdir():
                    if hook.is_file() and not hook.name.endswith(".sample"):
                        _make_mutable(hook)
                print("  Removed immutable flags from hooks")
        except Exception:
            pass

    # 6. Remove .guardian directory if empty
    print("[6/6] Cleaning up...")
    guardian_dir = repo_root / ".guardian"
    if guardian_dir.exists():
        try:
            if not any(guardian_dir.iterdir()):
                guardian_dir.rmdir()
                print("  Removed empty .guardian directory")
        except Exception:
            pass

    print()
    print_success(f"deadpush ({'hardened' if hardened else 'default'} mode) uninstalled completely.")
    print("You can reinstall with: deadpush protect" + (" --hardened" if hardened else ""))

    return 0


@main.command("doctor")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect from cwd)")
@click.option("--hardened", is_flag=True, help="Check hardened guardian")
def cmd_doctor(repo, hardened):
    """Run comprehensive health checks on the guardian setup.

    Verifies:
    - Guardian process is running (PID file, process alive)
    - Launchd/systemd service loaded
    - ACLs correct (hardened mode)
    - MCP control interface reachable
    - Port file readable
    - Safety score file exists and valid
    - Log file exists and writable
    """
    from .config import load_config
    from .guard import (
        _scoped_pidfile, _scoped_lockfile, _scoped_portfile,
        _scoped_plist_label, _scoped_plist_path, _scoped_safety_score_file,
        _scoped_log_file, _state_dir,
        DaemonManager,
    )
    import subprocess
    import os
    import json

    if hardened:
        from .guard import _use_hardened
        _use_hardened()

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root

    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)
    portfile = _scoped_portfile(repo_root, hardened)
    plist_label = _scoped_plist_label(repo_root)
    plist_path = _scoped_plist_path(repo_root, hardened)
    state_dir = _state_dir(hardened)
    safety_score_file = _scoped_safety_score_file(repo_root, hardened)
    log_file = _scoped_log_file(repo_root, hardened)
    shared_port_file = repo_root / ".guardian" / "guardian.control.port"

    print_header("deadpush Doctor", f"Health check for {repo_root.name}")
    print(f"Mode: {'hardened' if hardened else 'default'}")
    print(f"State dir: {state_dir}")
    print()

    all_ok = True

    def check(name, ok, detail=""):
        nonlocal all_ok
        status = "✅" if ok else "❌"
        if not ok:
            all_ok = False
        print(f"  {status} {name}" + (f" — {detail}" if detail else ""))

    # 1. Guardian process
    dm = DaemonManager(pidfile, lockfile)
    running = dm.is_running()
    check("Guardian process", running, f"PID file: {pidfile}" + (" (running)" if running else " (not running)"))

    if running:
        try:
            pid = int(pidfile.read_text().strip())
            check("Process alive", True, f"PID {pid}")
        except Exception:
            check("Process alive", False, "PID file exists but unreadable")
    else:
        check("Process alive", False, "No running guardian")

    # 2. Launchd / systemd
    if hardened:
        try:
            r = subprocess.run(["sudo", "launchctl", "list", plist_label], capture_output=True, text=True, timeout=10)
            loaded = r.returncode == 0 and plist_label in r.stdout
            check("LaunchDaemon loaded", loaded, plist_label)
        except Exception:
            check("LaunchDaemon loaded", False, "Could not check")
    else:
        try:
            uid = os.getuid()
            r = subprocess.run(["launchctl", "list", plist_label], capture_output=True, text=True, timeout=10)
            loaded = r.returncode == 0 and plist_label in r.stdout
            check("LaunchAgent loaded", loaded, plist_label)
        except Exception:
            check("LaunchAgent loaded", False, "Could not check")

    # 3. State directory
    check("State directory", state_dir.exists() and state_dir.is_dir(), str(state_dir))

    # 4. Port file
    if portfile.exists():
        try:
            port = portfile.read_text().strip()
            check("Control port file", True, f"port {port}")
        except Exception:
            check("Control port file", False, "exists but unreadable")
    else:
        check("Control port file", False, "missing")

    # 5. Shared port file (hardened)
    if hardened:
        if shared_port_file.exists():
            try:
                port = shared_port_file.read_text().strip()
                check("Shared port file", True, f"port {port} at {shared_port_file}")
            except Exception:
                check("Shared port file", False, "exists but unreadable")
        else:
            check("Shared port file", False, "missing")

    # 6. Safety score file
    if safety_score_file.exists():
        try:
            data = json.loads(safety_score_file.read_text(encoding="utf-8"))
            score = data.get("score")
            check("Safety score file", score is not None, f"score={score}, updated={data.get('last_updated', '?')}")
        except Exception as e:
            check("Safety score file", False, f"invalid JSON: {e}")
    else:
        check("Safety score file", False, "missing")

    # 7. Log file
    check("Log file", log_file.exists(), str(log_file))

    # 8. ACLs (hardened)
    if hardened:
        try:
            import subprocess
            r = subprocess.run(["ls", "-le", str(repo_root)], capture_output=True, text=True, timeout=10)
            has_acl = "_deadpush" in r.stdout
            check("Repo ACLs", has_acl, "_deadpush ACE present" if has_acl else "missing _deadpush ACE")
        except Exception:
            check("Repo ACLs", False, "could not check")

        # Check state dir permissions
        try:
            import stat
            st = state_dir.stat()
            mode = stat.S_IMODE(st.st_mode)
            owner_ok = st.st_uid == os.getuid() or st.st_uid == 0  # root or current user
            mode_ok = mode == 0o700
            check("State dir permissions", mode_ok and owner_ok, f"mode={oct(mode)}, uid={st.st_uid}")
        except Exception:
            check("State dir permissions", False, "could not check")

    # Summary
    print()
    if all_ok:
        print_success("All checks passed. Guardian is healthy.")
    else:
        print_error("Some checks failed. Run 'deadpush protect' to repair.")

    return 0 if all_ok else 1


@main.command("init")
@click.option("--mode", type=click.Choice(["default", "hardened"]), default="default", help="Protection mode: default (user-level) or hardened (privilege separation)")
@click.option("--daemon/--no-daemon", default=True, help="Start guardian daemon after setup")
@click.option("--force", is_flag=True, help="Skip confirmations")
def cmd_init(mode, daemon, force):
    """Guided first-time setup for deadpush.

    Walks through:
    1. Detects OS and repo
    2. Chooses protection mode (default vs hardened)
    3. Installs git hooks (pre-push, pre-commit, post-commit)
    4. Updates smart ignore files (.cursorignore, .claudeignore, .gitignore)
    5. Sets up GitHub Actions guard (optional)
    6. Generates autostart config (launchd/systemd)
    7. Starts guardian daemon (optional)
    8. Runs health check (doctor)

    Run this once per repo, then walk away.
    """
    from .config import load_config
    from .guard import setup_autostart, setup_hardened_environment, run_guardian
    from .hooks import (
        install_hook, install_precommit_hook, install_postcommit_hook,
        verify_hooks_installed, setup_mcp_discovery, setup_github_guard_action
    )

    config = load_config()
    repo_root = config.repo_root

    print_header("deadpush Init", f"Guided setup for {repo_root.name}")
    print(f"Mode: {mode}")
    print(f"Daemon: {'yes' if daemon else 'no'}")
    print()

    if not force:
        confirm = input(f"Initialize deadpush ({mode}) for {repo_root}? [Y/n]: ")
        if confirm.lower() == "n":
            print("Aborted.")
            return

    # 1. Install git hooks
    print("\n[1/7] Installing git hooks...")
    try:
        install_hook(repo_root)
        print("  pre-push hook installed")
    except Exception as e:
        print_warning(f"pre-push hook issue: {e}")
    try:
        install_precommit_hook(repo_root)
        print("  pre-commit hook installed")
    except Exception as e:
        print_warning(f"pre-commit hook issue: {e}")
    try:
        install_postcommit_hook(repo_root)
        print("  post-commit hook installed (catches --no-verify bypass)")
    except Exception as e:
        print_warning(f"post-commit hook issue: {e}")

    try:
        problems = verify_hooks_installed(repo_root)
        if problems:
            print_warning(f"Hook verification issues: {', '.join(problems)}")
        else:
            print_success("  All git guardrail hooks verified (checksums OK)")
    except Exception as e:
        print_warning(f"Hook verification skipped: {e}")

    try:
        setup_mcp_discovery(repo_root)
        print("  Agent auto-discovery configured (.cursor/mcp.json, .vscode/mcp.json)")
    except Exception as e:
        print_warning(f"MCP discovery setup issue: {e}")

    # 2. GitHub Actions guard
    print("\n[2/7] Setting up GitHub Actions guard...")
    try:
        action_path = setup_github_guard_action(repo_root)
        if action_path:
            print(f"  Created {action_path}")
    except Exception as e:
        print_warning(f"GitHub Action guard setup issue: {e}")

    # 3. Guardian ignore files
    print("\n[3/7] Updating guardian ignore files...")
    try:
        from .hooks import merge_guardian_ignore_files
        merge_guardian_ignore_files(repo_root)
        print_success("  Guardian ignore patterns merged/updated")
    except Exception as e:
        print_warning(f"  Ignore file update skipped: {e}")

    # 4. Hardened setup or autostart
    print("\n[4/7] Configuring persistence...")
    if mode == "hardened":
        print("  Setting up hardened environment (requires sudo)...")
        try:
            summary = setup_hardened_environment(repo_root, auto_load=daemon)
            print(summary)
        except Exception as e:
            print_error(f"Hardened setup failed: {e}")
            print_warning("Try running with sudo directly: sudo deadpush init --mode hardened")
            return 1
    else:
        try:
            autostart_info = setup_autostart(repo_root, hardened=False)
            if autostart_info:
                print(autostart_info)
        except Exception as e:
            print_warning(f"Autostart helper skipped: {e}")

    # 5. Start daemon if requested
    if daemon:
        print("\n[5/7] Starting guardian daemon...")
        if mode == "hardened":
            print_success("Hardened guardian already loaded via launchd")
        else:
            try:
                run_guardian(intervention=True, daemon=True, strict=False)
            except SystemExit:
                pass
            except Exception as e:
                print_warning(f"Daemon launch issue: {e}")

    # 6. Health check
    print("\n[6/7] Running health check...")
    from .cli import cmd_doctor
    try:
        ctx = click.get_current_context()
        ctx.invoke(cmd_doctor, hardened=(mode == "hardened"))
    except Exception as e:
        print_warning(f"Health check failed: {e}")

    # 7. Summary
    print("\n[7/7] Setup complete!")
    print_success(f"deadpush ({mode}) initialized for {repo_root.name}")
    print()
    print("Next steps:")
    if daemon:
        print("  Guardian is running in background. Use 'deadpush status' to check.")
    else:
        print("  Start guardian with: deadpush protect --daemon")
    print("  Configure your AI agent to use: deadpush mcp")
    print("  View dashboard at: http://127.0.0.1:<port>/dashboard")

    return 0

if __name__ == "__main__":
    main()
