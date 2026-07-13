"""deadpush CLI — AI Agent Guardian."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .config import load_config
from .ui import is_rich_available, print_error, print_header, print_info, print_success, print_warning


def _auto_merge_ignore_files(repo_root: Path, new_patterns: set[str]):
    from .hooks import merge_guardian_ignore_files
    merge_guardian_ignore_files(repo_root, new_patterns)


def _wait_for_guardian(repo_root: Path, hardened: bool, attempts: int = 12, delay: float = 0.5) -> bool:
    """Poll until the guardian reports running, or give up.

    launchd/systemd (and the double-fork daemon path) start the guardian
    asynchronously, so a single immediate check races the daemon's startup.
    """
    import time

    from .guard import guardian_is_running

    for _ in range(max(1, attempts)):
        try:
            if guardian_is_running(repo_root, hardened=hardened):
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False


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
@click.option("--soft", is_flag=True, help="Run as your own UID (this is the default)")
@click.option("--hardened", is_flag=True, help="Opt into hardened mode: run under a root-owned _deadpush user (requires sudo)")
@click.option(
    "--allow-self-protect",
    is_flag=True,
    help="Allow a persistent guardian on the deadpush source repo (not recommended)",
)
@click.option(
    "--no-fanotify",
    is_flag=True,
    help="Disable Linux fanotify pre-write deny in the guardian (watchdog-only)",
)
def cmd_guard(repo, no_intervention, daemon, strict, soft, hardened, allow_self_protect, no_fanotify):
    """
    Start the AI Agent Guardian.

    This is the core always-on protection while using AI coding agents.
    """
    from .config import dev_repo_guard_refusal
    from .guard import run_guardian
    import os
    intervention = not no_intervention
    if soft and hardened:
        print_error("Cannot use --soft with --hardened")
        return
    # Soft (same-UID) is the default; hardened (privilege separation, sudo) is opt-in.
    use_hardened = bool(hardened)
    if repo:
        os.chdir(Path(repo).resolve())
    config = load_config()
    refusal = dev_repo_guard_refusal(
        config.repo_root,
        allow_self_protect=allow_self_protect,
        persistent=bool(daemon or use_hardened),
    )
    if refusal:
        print_error(refusal.split("\n")[0])
        for line in refusal.split("\n")[1:]:
            print(line)
        raise SystemExit(2)
    run_guardian(
        intervention=intervention,
        daemon=daemon,
        strict=strict,
        hardened=use_hardened,
        allow_self_protect=allow_self_protect,
        enable_fanotify=not no_fanotify,
    )


@main.command("protect")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root to protect (default: auto-detect from cwd)")
@click.option("--enable", is_flag=True, help="Enable persistent background guardian (auto-starts daemon after setup)")
@click.option("--daemon", is_flag=True, help="Start the guardian as a persistent background daemon after performing full setup")
@click.option("--soft", is_flag=True, help="Same-UID guardian at your own privileges (this is the default)")
@click.option("--hardened", is_flag=True, help="Opt into hardened mode: privilege separation via a root-owned _deadpush user (requires sudo)")
@click.option(
    "--allow-self-protect",
    is_flag=True,
    help="Allow protecting the deadpush source repo itself (not recommended for development)",
)
@click.option(
    "--no-configure",
    is_flag=True,
    help="Skip IDE MCP proxy wiring (default: wrap Cursor/VS Code/Claude MCP via mcp-proxy)",
)
@click.option(
    "--no-fanotify",
    is_flag=True,
    help="Disable Linux fanotify pre-write deny in the guardian (watchdog-only)",
)
def cmd_protect(repo, enable, daemon, soft, hardened, allow_self_protect, no_configure, no_fanotify):
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
    from .config import dev_repo_guard_refusal
    config = load_config(explicit_root=Path(repo).resolve() if repo else None)

    refusal = dev_repo_guard_refusal(
        config.repo_root,
        allow_self_protect=allow_self_protect,
        full_setup=True,
    )
    if refusal:
        print_error(refusal.split("\n")[0])
        for line in refusal.split("\n")[1:]:
            print(line)
        raise SystemExit(2)

    start_background = bool(enable or daemon)
    if soft and hardened:
        print_error("Cannot use --soft with --hardened")
        raise SystemExit(2)
    # Soft (same-UID) is the default so the documented `pip install deadpush &&
    # deadpush protect --daemon` one-liner never silently requires sudo. Hardened
    # mode (privilege separation via a root-owned _deadpush user) is opt-in.
    use_hardened = bool(hardened)

    # Track failures that make protection incomplete. A production install must
    # exit non-zero (and tell the user) rather than print a warning and pretend
    # everything is fine.
    critical_failures: list[str] = []

    # If hardened mode, do the one-time privilege separation setup first
    if use_hardened:
        print("\n[0/4] Setting up hardened environment (privilege separation)...")
        from .guard import setup_hardened_environment
        try:
            summary = setup_hardened_environment(config.repo_root, auto_load=start_background)
            print(summary)
        except Exception as e:
            print_error(f"Hardened environment setup failed: {e}")
            print_error("Try running with sudo directly, or check system logs.")
            print_error("Nothing was protected. Re-run `deadpush protect` after fixing the above,")
            print_error("or use `deadpush protect --soft` for a same-UID (dev-only) guardian.")
            raise SystemExit(1)
    elif start_background:
        print_warning("Running in soft mode (default): the guardian runs at your UID, so an "
                      "agent could kill it. Use `--hardened` for a root-backed boundary (requires sudo).")

    print_header("deadpush Protect", "One-command setup for AI Agent Guardian (persistent background protection)")

    # 1. Install git hooks (pre-push + pre-commit + post-commit)
    print("\n[1/3] Installing git hooks (pre-push, pre-commit, post-commit)...")
    try:
        from .hooks import install_hook
        install_hook(config.repo_root, system=use_hardened)
    except Exception as e:
        print_error(f"Pre-push hook installation failed: {e}")
        print_error("  (Tip: ensure this is a git repo with .git/hooks/)")
        critical_failures.append("pre-push hook not installed")
    try:
        from .hooks import install_precommit_hook
        install_precommit_hook(config.repo_root, system=use_hardened)
        print("  Also installed pre-commit guardrail hook.")
    except Exception as e:
        print_warning(f"Pre-commit hook installation issue: {e}")
    try:
        from .hooks import install_postcommit_hook
        install_postcommit_hook(config.repo_root, system=use_hardened)
        print("  Also installed post-commit guardrail hook (catches --no-verify bypass).")
    except Exception as e:
        print_warning(f"Post-commit hook installation issue: {e}")
    try:
        from .hooks import verify_hooks_installed
        problems = verify_hooks_installed(config.repo_root)
        if problems:
            print_warning(f"  Hook verification issues: {', '.join(problems)}")
            print_warning("  Re-run `deadpush protect` to repair hooks.")
        elif use_hardened:
            print_success("  All git guardrail hooks verified (root-immutable / schg — "
                          "a same-UID agent cannot delete or modify them).")
        else:
            print_success("  All git guardrail hooks verified (checksums OK).")
    except Exception as e:
        print_warning(f"Hook verification skipped: {e}")

    # Record that this repo is protected. The marker pins the interpreter and
    # lets the installed hooks *fail closed* if deadpush later goes missing.
    try:
        from .config import write_install_marker
        marker = write_install_marker(config.repo_root, hardened=use_hardened)
        print(f"  Protection marker written ({marker.relative_to(config.repo_root)}).")
    except Exception as e:
        print_error(f"Could not write protection marker: {e}")
        critical_failures.append("protection marker not written")
    try:
        from .bootstrap import default_protect_bootstrap_paths, record_bootstrap_paths
        record_bootstrap_paths(config.repo_root, default_protect_bootstrap_paths())
    except Exception:
        pass
    try:
        if no_configure:
            from .hooks import setup_mcp_discovery
            setup_mcp_discovery(config.repo_root)
            print("  Agent auto-discovery configured (.cursor/mcp.json, .vscode/mcp.json).")
        else:
            from .configure import configure_all_ides
            cfg_result = configure_all_ides(config.repo_root)
            configured = [next(iter(d.keys())) for d in cfg_result.get("configured", [])]
            skipped = cfg_result.get("skipped", [])
            if configured:
                print_success(
                    f"  IDE MCP servers proxied through deadpush guardrails: {', '.join(configured)}"
                )
            if skipped:
                print(f"  (No MCP config found for: {', '.join(skipped)})")
            if cfg_result.get("gpc_snippet"):
                print(f"  GPC agent snippet: {cfg_result['gpc_snippet']}")
    except Exception as e:
        print_warning(f"IDE MCP configure issue: {e}")

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
        if not use_hardened:
            try:
                from .guard import run_guardian, setup_autostart, _scoped_plist_path
                autostart_info = setup_autostart(config.repo_root, hardened=False)
                if autostart_info:
                    print("\n[Auto-start for reboots]")
                    print(autostart_info)
            except Exception as e:
                print_warning(f"Autostart helper generation skipped (non-fatal): {e}")

        # In hardened mode, the daemon was already loaded by setup_hardened_environment().
        # In default mode, bootstrap the launchd plist so guardian runs under launchd.
        if not use_hardened:
            from .guard import run_guardian, _scoped_plist_path
            plist_path = _scoped_plist_path(config.repo_root)
            _bootstrapped = False
            if sys.platform == "darwin" and plist_path.exists():
                try:
                    import subprocess
                    import os
                    uid = os.getuid()
                    result = subprocess.run(
                        ["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
                        capture_output=True, text=True, timeout=10,
                    )
                    stderr = (result.stderr or "").strip()
                    # returncode 0 == freshly loaded; 17/EALREADY == already loaded.
                    # Any other non-zero code is a real failure we must surface.
                    if result.returncode == 0 or result.returncode == 17 or "already" in stderr.lower():
                        _bootstrapped = True
                    else:
                        print_warning(
                            f"  launchd bootstrap failed (code {result.returncode})"
                            + (f": {stderr}" if stderr else "")
                        )
                except Exception as e:
                    print_warning(f"  launchd bootstrap error: {e}")

            # If launchd didn't take (non-macOS, no plist, or bootstrap failure),
            # fall back to launching the daemon directly.
            if not _bootstrapped:
                print("  (launchd unavailable — starting guardian directly)")
                try:
                    run_guardian(
                        intervention=True,
                        daemon=True,
                        strict=False,
                        hardened=False,
                        allow_self_protect=allow_self_protect,
                        enable_fanotify=not no_fanotify,
                    )
                except SystemExit:
                    # Expected: the double-fork parent exits; the daemon child lives on.
                    pass
                except Exception as e:
                    print_warning(f"Direct daemon launch had issue: {e}")

            # Verify the guardian actually came up rather than assuming success.
            if _wait_for_guardian(config.repo_root, hardened=False):
                print_success("✅ Guardian is running (verified).")
            else:
                print_error("Guardian did not start after setup.")
                print_error("  Diagnose: deadpush doctor")
                print_error("  Retry:    deadpush guard --daemon")
                critical_failures.append("guardian not running")
        else:
            if _wait_for_guardian(config.repo_root, hardened=True):
                print_success("✅ Guardian running as _deadpush under launchd (verified).")
            else:
                print_error("Hardened setup finished but guardian is not running.")
                print_error("  Re-run: deadpush protect --daemon")
                print_error("  Logs:   sudo tail /var/db/deadpush/guardian.*.launchd.err.log")
                critical_failures.append("guardian not running (hardened)")

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

    # Final verdict — a production install must not report success if any
    # critical step failed. Exit non-zero so scripts/CI and users can trust it.
    print()
    if critical_failures:
        print_error("Protection is INCOMPLETE. Unresolved issues:")
        for problem in critical_failures:
            print_error(f"  - {problem}")
        print_error("Run `deadpush doctor` for details, then re-run `deadpush protect`.")
        raise SystemExit(1)
    print_success("✅ Protection verified. Run `deadpush doctor` anytime to re-check.")


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
    from .guard import guardian_is_running, _scoped_pidfile, _scoped_portfile, _scoped_log_file

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root
    pidfile = _scoped_pidfile(repo_root, hardened)
    running = guardian_is_running(repo_root, hardened)
    if not running and not hardened:
        # Auto-detect hardened guardian when user omits --hardened
        if guardian_is_running(repo_root, hardened=True):
            hardened = True
            pidfile = _scoped_pidfile(repo_root, hardened)
            running = True

    print_header("deadpush Status", f"AI Agent Guardian - {repo_root.name}")

    if running:
        try:
            if pidfile.exists():
                pid = int(pidfile.read_text().strip())
            else:
                import subprocess
                r = subprocess.run(
                    ["sudo", "cat", str(pidfile)],
                    capture_output=True, text=True, timeout=10,
                )
                pid = int(r.stdout.strip()) if r.returncode == 0 else None
            if pid:
                mode = " (hardened)" if hardened else ""
                print_success(f"🟢 Guardian is RUNNING{mode} (PID {pid})")
            else:
                print_success(f"🟢 Guardian is RUNNING{' (hardened)' if hardened else ''}")
        except Exception:
            print_success(f"🟢 Guardian is RUNNING{' (hardened)' if hardened else ''}")
    else:
        from .guard import guardian_killed_uncleanly, guardian_persistence_installed
        killed = guardian_killed_uncleanly(repo_root, hardened)
        installed = guardian_persistence_installed(repo_root, hardened)
        if killed:
            print_warning(f"🔴 Guardian is NOT running for {repo_root.name} — a stale PID file is present.")
            print_error("   This looks like the guardian was KILLED or crashed (a clean stop removes it).")
            print("   If you did not stop it yourself, an agent or process may have terminated it.")
            print("   Restart:  deadpush protect --daemon")
            print("   For a guardian a same-UID agent cannot kill, use hardened mode:")
            print("     deadpush protect --daemon --hardened")
        elif installed:
            print_warning(f"🔴 Guardian is INSTALLED but NOT running for {repo_root.name} — possible tamper.")
            print("   It was set up to run persistently, but nothing is alive now.")
            print("   Restart:  deadpush protect --daemon")
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
            print("Live tail:  deadpush logs -f")
            print("Dashboard:  deadpush dashboard --open")
        except Exception as e:
            print_warning(f"Could not parse recent log: {e}")
    else:
        print_warning("No guardian.log found yet (start the guardian to begin logging).")

    print("\nOther checks:")
    print("  - All repos:     deadpush repos list")
    print("  - Global hub:    deadpush hub open --start")
    print("  - Per-repo quarantines: cd your-repo ; deadpush quarantine list")
    print("  - Health check: deadpush doctor")

    # Show control interface if running
    port_file = _scoped_portfile(repo_root, hardened)
    if not port_file.exists() and hardened:
        port_file = config.repo_root / ".guardian" / "guardian.control.port"
    if port_file.exists():
        try:
            port = port_file.read_text().strip()
            print(f"\nLocal Control Interface: http://127.0.0.1:{port}")
            print(f"  Dashboard (live):      http://127.0.0.1:{port}/dashboard")
            print("  JSON API (agents):     /status, /safety-score, /quarantine-list")
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


@cmd_hooks.command("run-prereceive")
def cmd_hooks_run_prereceive():
    """Server-side enforcement (called by a git `pre-receive` hook).

    Reads pre-receive stdin and REJECTS the push (exit 1) if any incoming commit
    contains block-level violations. Install this on your git server (GitLab,
    Gitea, or a bare repo) — it runs off the developer's machine, so `--no-verify`,
    git plumbing, or killing the local daemon cannot bypass it.
    """
    config = load_config()
    from .hooks import run_prereceive_guardrails
    passed, violations = run_prereceive_guardrails(config.repo_root)
    sys.exit(0 if passed else 1)


@main.command("scan")
@click.option("--base", default=None,
              help="Base commit SHA. Scans commits in --base..--head (e.g. a PR's base sha).")
@click.option("--head", default=None, help="Head commit to scan up to (default: HEAD).")
@click.option("--all", "scan_all", is_flag=True,
              help="Scan every file in --ref's tree instead of a commit range.")
@click.option("--ref", default="HEAD", help="Ref whose whole tree to scan with --all (default: HEAD).")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect from cwd).")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format (default: text).")
def cmd_scan(base, head, scan_all, ref, repo, fmt):
    """Scan git history for block-level guardrail violations (CI / server-side).

    Exits non-zero if any block-level violation is found, so it can gate a merge.
    Wire it into a GitHub Actions check (with branch protection) or a pre-receive
    hook: because it runs OFF the agent's machine, `--no-verify` and git plumbing
    cannot bypass it.

    Examples:
      deadpush scan --base "$BASE_SHA" --head "$HEAD_SHA"   # PR / push range
      deadpush scan --all                                    # whole tree at HEAD
    """
    import json as _json

    from .hooks import scan_range, scan_tree, _print_violations

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root
    head = head or "HEAD"

    if base is not None:
        violations = scan_range(repo_root, base, head)
        target = f"{base[:8] if len(base) >= 8 else base}..{head}"
    else:
        tree_ref = ref if scan_all else head
        violations = scan_tree(repo_root, tree_ref)
        target = tree_ref

    if fmt == "json":
        print(_json.dumps({
            "target": target,
            "clean": not violations,
            "count": len(violations),
            "violations": violations,
        }, indent=2))
    else:
        if violations:
            _print_violations(
                f"deadpush — scan of {target} found {len(violations)} block-level violation(s):",
                violations,
                "Rejected. Remove the flagged content before this can be merged/pushed.",
            )
        else:
            print_success(f"deadpush — scan of {target} is clean (no block-level violations).")

    sys.exit(1 if violations else 0)


@main.command("intercept")
@click.option("--daemon", is_flag=True, help="Run as persistent background daemon")
@click.option(
    "--allow-self-protect",
    is_flag=True,
    help="Allow a persistent guardian on the deadpush source repo (not recommended)",
)
@click.option(
    "--no-fanotify",
    is_flag=True,
    help="Disable Linux fanotify pre-write deny in the guardian (watchdog-only)",
)
def cmd_intercept(daemon, allow_self_protect, no_fanotify):
    """Start the file interception daemon (alias for `deadpush guard`).

    Uses the watchdog-based guardian to monitor all file writes and
    enforce guardrails. The staging-based intercept has been removed;
    the guardian daemon covers every write through the filesystem.
    """
    from .config import dev_repo_guard_refusal
    from .guard import run_guardian

    config = load_config()
    refusal = dev_repo_guard_refusal(
        config.repo_root,
        allow_self_protect=allow_self_protect,
        persistent=daemon,
    )
    if refusal:
        print_error(refusal.split("\n")[0])
        for line in refusal.split("\n")[1:]:
            print(line)
        raise SystemExit(2)
    run_guardian(
        intervention=True,
        daemon=daemon,
        strict=False,
        allow_self_protect=allow_self_protect,
        enable_fanotify=not no_fanotify,
    )


@main.command("mcp-proxy")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), default=None,
              help="MCP config JSON (use with --server)")
@click.option("--server", "server_name", default=None, help="MCP server name from --config")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root for guardrail checks")
@click.argument("downstream", nargs=-1, type=click.UNPROCESSED)
def cmd_mcp_proxy(config_path, server_name, repo, downstream):
    """Transparent MCP proxy — scan tools/call before downstream servers execute.

    Wrap a single MCP server:

        deadpush mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem .

    Or load from config:

        deadpush mcp-proxy --config .cursor/mcp.json --server filesystem
    """
    from .mcp_proxy import run_mcp_proxy

    repo_root = Path(repo).resolve() if repo else None
    downstream_cmd = list(downstream) if downstream else None
    raise SystemExit(run_mcp_proxy(
        downstream_cmd,
        config_path=Path(config_path) if config_path else None,
        server_name=server_name,
        repo_root=repo_root,
    ))


@main.command("run")
@click.option("--sandbox", is_flag=True, help="T2: run command in sandbox (Seatbelt on macOS, fanotify on Linux)")
@click.option("--hardened", is_flag=True, help="Use hardened state paths")
@click.option("--backend", default=None, type=click.Choice(["seatbelt", "linux", "noop"]),
              help="Force a specific enforcement backend")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect)")
@click.option(
    "--no-gpc",
    is_flag=True,
    help="Disable mandatory GPC for this sandbox session (not T2-complete)",
)
@click.argument("cmd", nargs=-1, required=True)
def cmd_run(sandbox, hardened, backend, repo, no_gpc, cmd):
    """Run a command inside a deadpush sandbox session (T2).

    Example:

        deadpush run --sandbox -- python my_agent_script.py
    """
    from .run_session import describe_session, run_sandbox

    repo_root = Path(repo).resolve() if repo else None
    if not sandbox:
        print_warning("Running without --sandbox (T0). Use --sandbox for T2 confined I/O.")
        import subprocess
        raise SystemExit(subprocess.run(list(cmd)).returncode)

    info = describe_session(repo_root, backend_prefer=backend)
    backend_name = info["backend"]["name"]
    print(f"Tier T2 sandbox — backend: {backend_name}")
    if info.get("gpc", {}).get("mandatory") and not no_gpc:
        print(f"  GPC mandatory — socket: {info['gpc']['socket']}")
    if backend_name == "noop":
        print_warning(
            "OS sandbox unavailable — using T2-partial (noop). "
            "Subprocess has normal filesystem access; enforcement is via git-wrapper, "
            "MCP proxy, and guardian quarantine only."
        )
    elif info["backend"].get("last_error"):
        print_warning(info["backend"]["last_error"])
    raise SystemExit(run_sandbox(
        list(cmd),
        repo_root=repo_root,
        hardened=hardened,
        backend_prefer=backend,
        require_gpc=not no_gpc,
    ))


@main.command("git-wrapper", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def cmd_git_wrapper(args):
    """Internal: git shim used by deadpush run --sandbox."""
    from .git_wrapper import main as git_main
    raise SystemExit(git_main(list(args)))


@main.command("configure")
@click.argument("target", type=click.Choice(["cursor", "claude", "vscode", "all"]))
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect)")
@click.option("--unwrap", is_flag=True, help="Restore original MCP server commands")
def cmd_configure(target, repo, unwrap):
    """Wrap IDE MCP servers to route tools/call through deadpush mcp-proxy (T1).

    Example:

        deadpush configure all
        deadpush configure cursor --unwrap
    """
    from .config import load_config
    from .configure import (
        configure_all_ides,
        configure_claude_mcp,
        configure_cursor_mcp,
        configure_vscode_mcp,
    )

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    if target == "all":
        result = configure_all_ides(config.repo_root, unwrap=unwrap)
        action = "unwrapped" if unwrap else "proxied"
        print_success(f"IDE MCP configuration {action}")
        for item in result.get("configured", []):
            for name, detail in item.items():
                print(f"  {name}: {detail.get('path')} ({', '.join(detail.get('servers', []))})")
        if result.get("skipped"):
            print(f"  Skipped (not found): {', '.join(result['skipped'])}")
        if result.get("gpc_snippet"):
            print(f"  GPC agent snippet: {result['gpc_snippet']}")
        return

    fn = {"cursor": configure_cursor_mcp, "claude": configure_claude_mcp, "vscode": configure_vscode_mcp}[target]
    result = fn(config.repo_root, unwrap=unwrap)

    action = "unwrapped" if unwrap else "proxied"
    print_success(f"MCP servers {action} via deadpush mcp-proxy")
    print(f"  Config: {result['path']}")
    if result.get("backup"):
        print(f"  Backup: {result['backup']}")
    print(f"  Servers: {', '.join(result.get('servers', [])) or '(none)'}")


@main.command("verify-audit")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect)")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable summary")
def cmd_verify_audit(repo, as_json):
    """Verify the tamper-evident audit hash chain for this repo."""
    import json as json_mod

    from .audit import audit_log_path, audit_summary, verify_audit_chain
    from .config import load_config

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    path = audit_log_path(config.repo_root)
    ok, errors = verify_audit_chain(path)
    summary = audit_summary(config.repo_root)

    if as_json:
        print(json_mod.dumps({"valid": ok, "errors": errors, **summary}, indent=2))
        raise SystemExit(0 if ok else 1)

    print_header("Audit chain verification", str(path))
    print(f"  Entries: {summary['entries']}")
    if summary.get("by_event"):
        print(f"  Events: {summary['by_event']}")
    if ok:
        print_success("Audit chain is valid — no tampering detected.")
    else:
        print_error("Audit chain verification FAILED:")
        for err in errors[:10]:
            print(f"  - {err}")
    raise SystemExit(0 if ok else 1)


@main.command("export-sarif")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None)
@click.option("-o", "--output", type=click.Path(dir_okay=False), default=None,
              help="Write SARIF file (default: stdout)")
@click.option("--max-entries", default=500, show_default=True, type=int)
def cmd_export_sarif(repo, output, max_entries):
    """Export audit trail guardrail events as SARIF 2.1.0 for GitHub Security tab."""
    import json as json_mod

    from .audit import export_sarif
    from .config import load_config

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    sarif = export_sarif(config.repo_root, max_entries=max_entries)
    text = json_mod.dumps(sarif, indent=2)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        print_success(f"SARIF written to {output}")
    else:
        print(text)


@main.command("gpc-listen")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None)
@click.option("--hardened", is_flag=True)
def cmd_gpc_listen(repo, hardened):
    """Subscribe to Guardian Push Channel events (debug/integration)."""
    import json

    from .config import load_config
    from .gpc import GpcClient, GpcMessage

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)

    def on_msg(msg: GpcMessage) -> None:
        print(f"[GPC {msg.type}] {json.dumps(msg.payload, default=str)}")
    client = GpcClient(config.repo_root, hardened=hardened, on_message=on_msg)
    print(f"Listening on {client.socket_path} (Ctrl+C to stop)")
    try:
        client.connect_and_listen(blocking=True)
    except KeyboardInterrupt:
        client.stop()


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
@click.option("--all", "stop_all", is_flag=True,
              help="Stop guardians for every known repo (see: deadpush repos list)")
@click.option("--hardened", is_flag=True, help="Stop a hardened guardian")
@click.option("--force", is_flag=True, help="Force cleanup of stale lock/PID files (use if guardian crashed)")
def cmd_stop(repo, stop_all, hardened, force):
    """Stop the deadpush guardian and clean up.

    Sends SIGTERM to the guardian (which saves safety score with a clean-shutdown
    marker so restart doesn't trigger the "killed by agent" penalty), unloads the
    launchd plist, kills shadow processes, removes immutable flags from hooks,
    and cleans up PID / lock files.

    Use ``--all`` to stop every known repo in one shot, then verify with
    ``pgrep -fl deadpush`` (should print nothing).
    """
    from .guard import (
        stop_guardian_for_repo,
        stop_guardian_by_id,
        kill_orphan_guardian_processes,
        count_running_guardians,
    )
    from .state import discover_repos

    if stop_all:
        print_header("deadpush stop --all", "Stopping every known guardian")
        seen_paths: set[str] = set()
        seen_ids: set[str] = set()
        stopped = 0
        for h in (False, True):
            for entry in discover_repos(hardened=h):
                rid = entry["id"]
                path = entry.get("path") or ""
                if path and path not in seen_paths:
                    seen_paths.add(path)
                    label = entry.get("label") or path
                    if stop_guardian_for_repo(path, hardened=entry.get("hardened", h), force=force):
                        print_success(f"Stopped {label} ({path})")
                        stopped += 1
                    elif force:
                        print_info(f"Cleaned state for {label}")
                        stopped += 1
                elif rid not in seen_ids:
                    seen_ids.add(rid)
                    if stop_guardian_by_id(rid, hardened=h):
                        print_success(f"Stopped guardian id={rid}")
                        stopped += 1
        orphans = kill_orphan_guardian_processes()
        if orphans:
            print_warning(f"Sent SIGTERM to {orphans} orphan process(es)")
        remaining = count_running_guardians()
        if remaining:
            print_error(f"{remaining} guardian/shadow process(es) still running — try: pgrep -fl deadpush")
        else:
            print_success("No guardian processes running.")
        return

    from .config import load_config

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root
    if stop_guardian_for_repo(repo_root, hardened=hardened, force=force):
        print_success(f"Guardian stopped for {repo_root.name}. Restart with: deadpush protect")
    elif force:
        print_success("Forced cleanup complete.")
    else:
        print_info("No guardian was running.")



@main.group("repos")
def cmd_repos():
    """List and manage per-repo guardian state under ~/.deadpush/repos/."""
    pass


@cmd_repos.command("list")
@click.option("--hardened", is_flag=True, help="List hardened (/var/db/deadpush) repos only")
def cmd_repos_list(hardened):
    """Show all known repos with id, path, and running status."""
    from .state import discover_repos, state_dir

    entries = discover_repos(hardened=hardened)
    if not entries:
        print_info(f"No repos registered under {state_dir(hardened)}")
        return

    print_header("deadpush repos", str(state_dir(hardened)))
    print(f"{'ID':<14} {'STATUS':<10} {'LABEL':<22} PATH")
    print("-" * 72)
    for e in entries:
        status = "RUNNING" if e.get("running") else "stopped"
        pid = f" pid={e['pid']}" if e.get("pid") and e.get("running") else ""
        label = (e.get("label") or e["id"])[:22]
        path = e.get("path") or "(unknown path)"
        print(f"{e['id']:<14} {status + pid:<10} {label:<22} {path}")


@cmd_repos.command("clean")
@click.option("--older-than", default=30, type=int, help="Remove stopped repos unseen for N days")
@click.option("--dry-run", is_flag=True, help="Show what would be removed")
def cmd_repos_clean(older_than, dry_run):
    """Prune state dirs for repos that are stopped and stale."""
    import shutil
    from datetime import datetime, timedelta, timezone

    from .state import discover_repos, repo_state_dir, state_dir

    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than)
    removed = 0
    for entry in discover_repos(hardened=False):
        if entry.get("running"):
            continue
        path = entry.get("path")
        if not path:
            continue
        d = repo_state_dir(path, hardened=False)
        manifest = d / "manifest.json"
        if manifest.exists():
            try:
                m = json.loads(manifest.read_text(encoding="utf-8"))
                last = datetime.fromisoformat(m.get("last_seen", "1970-01-01T00:00:00+00:00"))
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if last > cutoff:
                    continue
            except Exception:
                pass
        if dry_run:
            print(f"would remove {d}")
        else:
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    if dry_run:
        print_info("Dry run only — no files deleted.")
    else:
        print_success(f"Removed {removed} stale repo state dir(s) under {state_dir(False) / 'repos'}")


@main.command("logs")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect from cwd)")
@click.option("-f", "--follow", is_flag=True, help="Tail log live (like tail -f)")
@click.option("--lines", "-n", default=40, type=int, help="Number of lines to show (default 40)")
def cmd_logs(repo, follow, lines):
    """Show guardian log for the current (or given) repo."""
    import subprocess

    from .guard import _scoped_log_file

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    log = _scoped_log_file(config.repo_root, hardened=False)
    if not log.exists():
        print_warning(f"No log yet: {log}")
        return
    if follow:
        subprocess.run(["tail", "-f", str(log)])
        return
    text = log.read_text(errors="ignore")
    chunk = text.strip().splitlines()[-lines:] if text.strip() else []
    for line in chunk:
        click.echo(line)
    print(f"\n({log})")


@main.command("dashboard")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), default=None,
              help="Repo root (default: auto-detect from cwd)")
@click.option("--open", "open_browser", is_flag=True, help="Open in default browser")
def cmd_dashboard(repo, open_browser):
    """Open the live guardian dashboard (http://127.0.0.1:PORT/dashboard)."""
    import webbrowser

    from .guard import _scoped_portfile, guardian_is_running

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root
    if not guardian_is_running(repo_root, hardened=False):
        print_error("Guardian is not running. Start with: deadpush protect --daemon")
        return
    port_file = _scoped_portfile(repo_root, hardened=False)
    if not port_file.exists():
        print_error("Control port file missing — is the guardian fully started?")
        return
    port = port_file.read_text().strip()
    url = f"http://127.0.0.1:{port}/dashboard"
    print(url)
    if open_browser:
        webbrowser.open(url)


@main.group("hub")
def cmd_hub():
    """Global multi-repo dashboard (all guardians in one view)."""
    pass


@cmd_hub.command("start")
@click.option("--port", default=8742, type=int, help="Hub listen port (default 8742)")
@click.option("--daemon", is_flag=True, help="Run hub in background")
def hub_start(port, daemon):
    """Start the global deadpush hub on localhost."""
    from .hub import hub_is_running, hub_url, start_hub

    if hub_is_running():
        print_success(f"Hub already running at {hub_url()}")
        return
    pid = start_hub(port=port, daemon=daemon)
    if daemon:
        print_success(f"Hub started (PID {pid}): {hub_url()}/hub")
        print("  Open: deadpush hub open")
    else:
        print_info("Hub stopped.")


@cmd_hub.command("stop")
def hub_stop():
    """Stop the global deadpush hub."""
    from .hub import hub_is_running, stop_hub

    if not hub_is_running():
        print_info("Hub is not running.")
        return
    stop_hub()
    print_success("Hub stopped.")


@cmd_hub.command("status")
def hub_status():
    """Show whether the global hub is running."""
    from .hub import hub_is_running, hub_url
    from .state import hub_pidfile

    print_header("deadpush Hub")
    if hub_is_running():
        pid = hub_pidfile().read_text().strip()
        print_success(f"Hub RUNNING (PID {pid}) — {hub_url()}/hub")
    else:
        print_warning("Hub is not running. Start with: deadpush hub start --daemon")


@cmd_hub.command("open")
@click.option("--start", is_flag=True, help="Start hub in background if not running")
def hub_open(start):
    """Open the global hub in your browser."""
    import webbrowser

    from .hub import hub_is_running, hub_url, start_hub

    if not hub_is_running():
        if start:
            start_hub(daemon=True)
        else:
            print_error("Hub is not running. Start with: deadpush hub start --daemon")
            print("  Or: deadpush hub open --start")
            return
    url = f"{hub_url()}/hub"
    print(url)
    webbrowser.open(url)


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
        _scoped_pidfile, _scoped_lockfile, _scoped_portfile, _scoped_token_file,
        _scoped_plist_label, _scoped_plist_path, _scoped_systemd_unit_path, _state_dir
    )
    from .hooks import _make_mutable
    import subprocess
    import os
    import shutil

    config = load_config()
    repo_root = config.repo_root

    pidfile = _scoped_pidfile(repo_root, hardened)
    lockfile = _scoped_lockfile(repo_root, hardened)
    portfile = _scoped_portfile(repo_root, hardened)
    tokenfile = _scoped_token_file(repo_root, hardened)
    plist_label = _scoped_plist_label(repo_root)
    plist_path = _scoped_plist_path(repo_root, hardened)
    state_dir = _state_dir(hardened)

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

    # 2. Unload the OS service (launchd on macOS, systemd on Linux). A missing
    #    service manager (e.g. no `launchctl` on Linux) must never crash uninstall.
    print("[2/6] Unloading background service...")
    try:
        if sys.platform == "darwin":
            if hardened:
                subprocess.run(["sudo", "launchctl", "bootout", "system", plist_label], capture_output=True, timeout=10)
            else:
                uid = os.getuid()
                subprocess.run(["launchctl", "bootout", f"gui/{uid}/{plist_label}"], capture_output=True, timeout=10)
            print("  Launchd service unloaded")
        elif sys.platform.startswith("linux"):
            unit = _scoped_systemd_unit_path(repo_root, hardened).name
            scope = [] if hardened else ["--user"]
            subprocess.run(["systemctl", *scope, "disable", "--now", unit], capture_output=True, timeout=10)
            print("  systemd unit disabled")
    except Exception:
        pass  # service manager absent (e.g. launchctl on Linux) or not running

    # 3. Remove the service unit file (launchd plist on macOS, systemd unit on Linux).
    print("[3/6] Removing service unit...")
    unit_path = _scoped_systemd_unit_path(repo_root, hardened) if sys.platform.startswith("linux") else plist_path
    try:
        if hardened:
            subprocess.run(["sudo", "rm", "-f", str(unit_path)], capture_output=True, timeout=10)
        elif unit_path.exists():
            unit_path.unlink()
        print(f"  Removed {unit_path.name}")
    except Exception:
        pass
    if sys.platform.startswith("linux"):
        try:
            subprocess.run(["systemctl", *([] if hardened else ["--user"]), "daemon-reload"],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    # 4. Clean up state files
    print("[4/6] Cleaning state files...")
    for f in [pidfile, lockfile, portfile, tokenfile]:
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

    # 5. Remove hardened user/group and ACLs (platform-aware: chmod/dscl on
    #    macOS, setfacl/userdel on Linux; best-effort, never crashes uninstall).
    if hardened:
        print("[5/6] Removing hardened user, group, and ACLs...")
        from .guard import teardown_hardened_environment
        try:
            for line in teardown_hardened_environment(repo_root):
                print(f"  {line}")
        except Exception as e:
            print_warning(f"  Hardened teardown issue: {e}")

    # Remove immutable flags from hooks. In hardened mode these are root-immutable
    # (schg), so clearing requires sudo — pass system=hardened.
    try:
        hooks_dir = config.repo_root / ".git" / "hooks"
        if hooks_dir.exists():
            for hook in hooks_dir.iterdir():
                if hook.is_file() and not hook.name.endswith(".sample"):
                    _make_mutable(hook, system=hardened)
            print("  Removed immutable flags from hooks")
    except Exception:
        pass

    # Remove deadpush-installed git hooks so nothing lingers after uninstall.
    try:
        from .hooks import uninstall_deadpush_hooks
        removed_hooks = uninstall_deadpush_hooks(repo_root, system=hardened)
        if removed_hooks:
            print(f"  Removed git hooks: {', '.join(removed_hooks)}")
    except Exception as e:
        print_warning(f"  Could not remove git hooks: {e}")

    # Remove the protection marker so hooks no longer fail closed on this repo.
    try:
        from .config import remove_install_marker
        remove_install_marker(repo_root)
    except Exception:
        pass

    # 6. Remove deadpush's own now-empty directories so the repo is left pristine.
    #    Everything here is best-effort and strictly non-destructive: a directory is
    #    only removed when it has no remaining contents, so we never delete user
    #    config, feedback data, or quarantined files.
    print("[6/6] Cleaning up...")

    def _rmdir_if_empty(path: Path) -> bool:
        try:
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()
                return True
        except Exception:
            pass
        return False

    if _rmdir_if_empty(repo_root / ".guardian"):
        print("  Removed empty .guardian directory")

    # .deadpush holds deadpush's bookkeeping (install marker, hook checksums,
    # feedback). Remove install-owned leaf files first, prune now-empty subdirs
    # (e.g. feedback/, hooks/), then drop the dir itself only if nothing
    # user-relevant (config.toml, rules.json, real feedback data) remains.
    deadpush_dir = repo_root / ".deadpush"
    if deadpush_dir.is_dir():
        for owned in (
            "installed",
            "bootstrap_paths.json",
            "audit.chain.jsonl",
            "gpc_overrides.jsonl",
            "mcp_proxy_blocks.jsonl",
        ):
            try:
                (deadpush_dir / owned).unlink(missing_ok=True)
            except OSError:
                pass
        for child in list(deadpush_dir.iterdir()):
            if child.is_dir():
                _rmdir_if_empty(child)
    if _rmdir_if_empty(deadpush_dir):
        print("  Removed empty .deadpush directory")

    # Quarantine dir: remove only when empty — never delete quarantined files.
    if _rmdir_if_empty(repo_root / ".deadpush-quarantine"):
        print("  Removed empty .deadpush-quarantine directory")

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
        _scoped_pidfile, _scoped_portfile,
        _scoped_plist_label, _scoped_safety_score_file,
        _scoped_log_file, _state_dir,
        guardian_is_running,
    )
    import subprocess
    import os
    import json

    config = load_config(explicit_root=Path(repo).resolve() if repo else None)
    repo_root = config.repo_root

    pidfile = _scoped_pidfile(repo_root, hardened)
    portfile = _scoped_portfile(repo_root, hardened)
    plist_label = _scoped_plist_label(repo_root)
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
    running = guardian_is_running(repo_root, hardened)
    if running:
        check("Guardian process", True, f"PID file: {pidfile} (running)")
    else:
        from .guard import guardian_killed_uncleanly, guardian_persistence_installed
        if guardian_killed_uncleanly(repo_root, hardened):
            check("Guardian process", False,
                  "NOT running — stale PID file present (killed/crashed, not a clean stop)")
            print("      → If you did not stop it, an agent/process may have killed it. "
                  "Restart: deadpush protect --daemon (or --hardened for an unkillable guardian).")
        elif guardian_persistence_installed(repo_root, hardened):
            check("Guardian process", False,
                  "INSTALLED but NOT running — possible tamper. Restart: deadpush protect --daemon")
        else:
            check("Guardian process", False, f"not running (PID file: {pidfile})")

    if running:
        try:
            if pidfile.exists():
                pid_text = pidfile.read_text().strip()
            elif hardened:
                r = subprocess.run(
                    ["sudo", "cat", str(pidfile)],
                    capture_output=True, text=True, timeout=10,
                )
                pid_text = r.stdout.strip() if r.returncode == 0 else ""
            else:
                pid_text = ""
            if pid_text:
                check("Process alive", True, f"PID {pid_text}")
            else:
                check("Process alive", True, "responding on control port or launchd")
        except Exception:
            check("Process alive", False, "PID file exists but unreadable")
    else:
        check("Process alive", False, "No running guardian")

    # 2. Launchd / systemd
    if hardened:
        try:
            r = subprocess.run(
                ["sudo", "launchctl", "print", f"system/{plist_label}"],
                capture_output=True, text=True, timeout=10,
            )
            loaded = r.returncode == 0 and "state = running" in r.stdout
            check("LaunchDaemon loaded", loaded, plist_label)
        except Exception:
            check("LaunchDaemon loaded", False, "Could not check")
    else:
        try:
            r = subprocess.run(["launchctl", "list", plist_label], capture_output=True, text=True, timeout=10)
            loaded = r.returncode == 0 and plist_label in r.stdout
            check("LaunchAgent loaded", loaded, plist_label)
        except Exception:
            check("LaunchAgent loaded", False, "Could not check")

    # 3. State directory
    check("State directory", state_dir.exists() and state_dir.is_dir(), str(state_dir))

    # 3b. Protection marker + hook integrity (drives fail-closed behavior)
    from .config import read_install_marker
    marker = read_install_marker(repo_root)
    if marker is None:
        check("Protection marker", False, "repo not protected — run `deadpush protect`")
    else:
        pinned = marker.get("python", "?") if isinstance(marker, dict) else "?"
        interp_ok = (not isinstance(marker, dict)) or (not pinned) or Path(pinned).exists()
        check(
            "Protection marker",
            interp_ok,
            f"python={pinned}" if interp_ok else f"pinned interpreter missing: {pinned}",
        )
        if not interp_ok:
            print("      → Hooks will fail closed. Re-run `deadpush protect` to re-pin.")

    try:
        from .hooks import verify_hooks_installed
        hook_problems = verify_hooks_installed(repo_root)
        hookspath_problems = [p for p in hook_problems if p.startswith("core.hooksPath")]
        file_problems = [p for p in hook_problems if not p.startswith("core.hooksPath")]
        check(
            "Git hooks",
            not file_problems,
            "pre-push, pre-commit, post-commit OK" if not file_problems else ", ".join(file_problems),
        )
        if hookspath_problems:
            check("core.hooksPath", False, hookspath_problems[0].replace("core.hooksPath ", ""))
            print("      → git hooks are being bypassed. Run `deadpush protect` to restore "
                  "(a running guardian auto-repairs this).")
        else:
            check("core.hooksPath", True, "not hijacked")
    except Exception as e:
        check("Git hooks", False, f"could not verify: {e}")

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
            import pwd
            import stat
            st = state_dir.stat()
            mode = stat.S_IMODE(st.st_mode)
            mode_ok = mode == 0o700
            if hardened:
                try:
                    dead_uid = pwd.getpwnam("_deadpush").pw_uid
                    owner_ok = st.st_uid == dead_uid
                except KeyError:
                    owner_ok = False
            else:
                owner_ok = st.st_uid == os.getuid()
            check("State dir permissions", mode_ok and owner_ok, f"mode={oct(mode)}, uid={st.st_uid}")
        except Exception:
            check("State dir permissions", False, "could not check")

    # 9. Sandbox backends + guardrail plugins
    print()
    print("  Sandbox backends:")
    try:
        from .run_session import describe_backends
        from .plugins import load_plugins, plugin_load_errors

        backends = describe_backends(repo_root)
        selected = backends["selected"]
        os_sandbox = selected.get("os_sandbox", False)
        check(
            "Selected sandbox backend",
            True,
            f"{selected.get('name')} ({selected.get('tier')})"
            + (" — OS syscall confinement" if os_sandbox else " — T2-partial, no OS sandbox"),
        )
        if selected.get("name") == "noop":
            print("      → Run on macOS (Seatbelt) or Linux 5.13+ (fanotify) for full T2.")
        for b in backends["available"]:
            mark = "← selected" if b.get("name") == selected.get("name") else (
                "available" if b.get("available") else "unavailable"
            )
            print(f"      · {b.get('name')}: {mark}")

        load_plugins(reload=True)
        plugin_errs = plugin_load_errors()
        loaded = load_plugins()
        check(
            "Guardrail plugins",
            not plugin_errs,
            f"{len(loaded)} loaded" if not plugin_errs else "; ".join(plugin_errs[:2]),
        )
        if plugin_errs:
            print("      → Fix or uninstall broken entry-point plugins in pyproject.toml.")
    except Exception as e:
        check("Sandbox backends", False, str(e))

    # 10. Audit trail
    try:
        from .audit import audit_summary

        audit = audit_summary(repo_root)
        check(
            "Audit chain",
            audit.get("valid", True),
            f"{audit.get('entries', 0)} entries at {audit.get('path')}",
        )
        if audit.get("errors"):
            for err in audit["errors"][:3]:
                print(f"      → {err}")
    except Exception as e:
        check("Audit chain", False, str(e))

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
@click.option(
    "--allow-self-protect",
    is_flag=True,
    help="Allow init on the deadpush source repo (not recommended)",
)
@click.option(
    "--no-fanotify",
    is_flag=True,
    help="Disable Linux fanotify pre-write deny in the guardian (watchdog-only)",
)
def cmd_init(mode, daemon, force, allow_self_protect, no_fanotify):
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
    from .config import dev_repo_guard_refusal, load_config
    from .guard import setup_autostart, setup_hardened_environment, run_guardian
    from .hooks import (
        install_hook, install_precommit_hook, install_postcommit_hook,
        verify_hooks_installed, setup_mcp_discovery, setup_github_guard_action
    )

    config = load_config()
    repo_root = config.repo_root

    refusal = dev_repo_guard_refusal(
        repo_root,
        allow_self_protect=allow_self_protect,
        full_setup=True,
    )
    if refusal:
        print_error(refusal.split("\n")[0])
        for line in refusal.split("\n")[1:]:
            print(line)
        raise SystemExit(2)

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
        # Hooks were installed above as user-immutable. Now that privilege
        # separation (and a cached sudo credential) is in place, re-lock them
        # root-immutable (schg) so a same-UID agent cannot delete or modify them.
        try:
            install_hook(repo_root, system=True)
            install_precommit_hook(repo_root, system=True)
            install_postcommit_hook(repo_root, system=True)
            print_success("  Git hooks locked root-immutable (schg).")
        except Exception as e:
            print_warning(f"  Could not lock hooks root-immutable: {e}")
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
                run_guardian(
                    intervention=True,
                    daemon=True,
                    strict=False,
                    allow_self_protect=allow_self_protect,
                    enable_fanotify=not no_fanotify,
                )
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
    print("  T2 sandbox sessions: deadpush run --sandbox -- <agent-cmd>")
    print("  MCP proxy: deadpush mcp-proxy -- <mcp-server-cmd>")
    print("  Guarantee tiers: docs/guarantees.md")
    print("  View dashboard at: http://127.0.0.1:<port>/dashboard")

    return 0

if __name__ == "__main__":
    main()
