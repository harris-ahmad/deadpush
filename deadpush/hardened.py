"""
deadpush Hardened Environment Module

Handles privilege-separated (hardened) mode setup/teardown:
  - _HARDENED_STATE_DIR / _HARDENED_VENV_DIR constants
  - Python/venv bootstrap helpers
  - ACL grant/revoke for _deadpush system account
  - setup_autostart (launchd / systemd units)
  - setup_hardened_environment / teardown_hardened_environment
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .config import repo_id as _repo_id
from . import state as _state


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_HARDENED_STATE_DIR = Path("/var/db/deadpush")
_HARDENED_VENV_DIR = _HARDENED_STATE_DIR / "venv"

# macOS ACE granted to _deadpush on parent dirs so it can traverse into the
# repo (e.g. ~/Documents mode 700).
_HARDENED_TRAVERSE_ACE = "_deadpush allow list,search,readattr,readextattr,readsecurity"


# ---------------------------------------------------------------------------
# Path helpers (delegate to state; patchable in tests)
# ---------------------------------------------------------------------------

def _state_dir(hardened: bool = False) -> Path:
    return _state.state_dir(hardened)


def _scoped_plist_path(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_plist_path(repo_root, hardened)


def _scoped_plist_label(repo_root: Path) -> str:
    return _state.scoped_plist_label(repo_root)


def _scoped_systemd_unit_path(repo_root: Path, hardened: bool = False) -> Path:
    return _state.scoped_systemd_unit_path(repo_root, hardened)


# ---------------------------------------------------------------------------
# Python / venv helpers
# ---------------------------------------------------------------------------

def _hardened_python() -> Path:
    return _HARDENED_VENV_DIR / "bin" / "python"


def _deadpush_source_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _find_bootstrap_python() -> str:
    """Python interpreter for creating the hardened venv (must be system-wide)."""
    import shutil as _shutil

    for candidate in (
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ):
        if Path(candidate).exists():
            return candidate
    found = _shutil.which("python3")
    if found:
        return found
    import sys as _sys
    return _sys.executable


# ---------------------------------------------------------------------------
# File write helpers
# ---------------------------------------------------------------------------

def _is_system_path(path: Path) -> bool:
    s = str(path)
    return s.startswith("/Library/") or s.startswith("/etc/")


def _write_privileged_file(path: Path, content: str, sudo_fn=None) -> None:
    """Write a config file that may require root (LaunchDaemons, systemd system units)."""
    import subprocess
    import tempfile

    if not _is_system_path(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return

    def _sudo(cmd, check=True, timeout=60):
        if sudo_fn is not None:
            return sudo_fn(cmd, check=check, timeout=timeout)
        full = ["sudo"] + cmd
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(full)} failed: {r.stderr.strip()}")
        return r

    with tempfile.NamedTemporaryFile(mode="w", suffix=path.suffix, delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        _sudo(["mkdir", "-p", str(path.parent)])
        _sudo(["cp", tmp, str(path)])
        _sudo(["chmod", "644", str(path)], check=False)
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# Auto-start (launchd / systemd)
# ---------------------------------------------------------------------------

def setup_autostart(
    repo_root: Path,
    hardened: bool = False,
    _sudo=None,
    *,
    enable_fanotify: bool = True,
) -> str:
    """Generate OS-specific auto-start configuration for the guardian daemon.

    - On Linux: writes ~/.config/systemd/user/deadpush-guardian.<repoid>.service
    - On macOS: writes ~/Library/LaunchAgents/com.deadpush.guardian.<repoid>.plist
    - In hardened mode: writes to system paths for the _deadpush user.

    ``enable_fanotify`` is honored in the generated unit/plist (``--no-fanotify``
    when False).

    Returns a string with the file path + exact commands the user should run to enable it.
    Safe to call multiple times (idempotent overwrite).
    """
    import sys as _sys

    home = Path.home()
    if hardened:
        exe = str(_hardened_python())
    else:
        exe = _sys.executable
    rid = _repo_id(str(repo_root))
    fanotify_cli = "" if enable_fanotify else " --no-fanotify"
    fanotify_plist = "" if enable_fanotify else "\n        <string>--no-fanotify</string>"

    if _sys.platform.startswith("linux"):
        unit_path = _scoped_systemd_unit_path(repo_root, hardened)
        if not _is_system_path(unit_path):
            unit_path.parent.mkdir(parents=True, exist_ok=True)
        env_line = f'Environment="PATH=/usr/local/bin:/usr/bin:/bin:{home}/.local/bin"'
        wanted_by = "multi-user.target" if hardened else "default.target"
        content = f"""[Unit]
Description=deadpush AI Agent Guardian ({rid}) - persistent background protection
After=network.target

[Service]
Type=simple
ExecStart={exe} -m deadpush_bootstrap guard --daemon{' --hardened' if hardened else ''}{fanotify_cli}
Restart=always
RestartSec=5
WorkingDirectory={repo_root}
Nice=10
{env_line}
{'User=_deadpush' if hardened else ''}

[Install]
WantedBy={wanted_by}
"""
        _write_privileged_file(unit_path, content, _sudo)
        return f"""Linux{' systemd system' if hardened else ' systemd --user'} unit written:
  {unit_path}

To enable auto-start{' on boot' if hardened else ' on login / reboot'} (run these once):
  systemctl{'' if hardened else ' --user'} daemon-reload
  systemctl{'' if hardened else ' --user'} enable --now deadpush-guardian.{rid}.service

Useful commands:
  systemctl{'' if hardened else ' --user'} status deadpush-guardian.{rid}.service
  journalctl{'' if hardened else ' --user'} -u deadpush-guardian.{rid} -f
  systemctl{'' if hardened else ' --user'} stop deadpush-guardian.{rid}.service
"""

    elif _sys.platform == "darwin":
        plist_label = _scoped_plist_label(repo_root)
        plist_path = _scoped_plist_path(repo_root, hardened)
        log_dir = _state_dir(hardened)
        if not hardened:
            log_dir.mkdir(parents=True, exist_ok=True)
        hardened_args = ""
        user_name = ""
        if hardened:
            hardened_args = "\n        <string>--hardened</string>"
            user_name = """
    <key>UserName</key>
    <string>_deadpush</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/var/db/deadpush/venv/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>"""
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{plist_label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>-m</string>
        <string>deadpush_bootstrap</string>
        <string>guard</string>
        <string>--daemon</string>{hardened_args}{fanotify_plist}
    </array>
    <key>WorkingDirectory</key>
    <string>{repo_root}</string>{user_name}
    <key>WatchPaths</key>
    <array>
        <string>{repo_root}/.git/HEAD</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>{log_dir}/guardian.{rid}.launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/guardian.{rid}.launchd.err.log</string>
</dict>
</plist>
"""
        _write_privileged_file(plist_path, content, _sudo)
        return f"""macOS{' LaunchDaemon' if hardened else ' LaunchAgent'} plist written:
  {plist_path}

To load (start now + on{' boot' if hardened else ' login/reboot'}):
  {'sudo launchctl bootstrap system' if hardened else 'launchctl load'} {plist_path}

To unload / stop:
  {'sudo launchctl bootout system ' + plist_label if hardened else 'launchctl unload ' + str(plist_path)}

Logs: tail -f {log_dir}/guardian.{rid}.launchd.*.log
(Also file logs at {log_dir}/guardian.log )
"""

    else:
        return f"""Auto-start unit generation not supported on this platform ({_sys.platform}).
You can still achieve "survive reboot" by:
  - Adding `deadpush guard --daemon` to your shell's startup (~/.bashrc, ~/.zshrc, etc) with nohup or similar, or
  - Using your distro's service manager manually pointing at: {exe} -m deadpush_bootstrap guard --daemon
  - Or cron with @reboot (advanced).
See `deadpush guard --daemon` for the core persistent mode.
"""


# ---------------------------------------------------------------------------
# launchctl bootstrap helper (hardened only, macOS)
# ---------------------------------------------------------------------------

def _launchctl_bootstrap_system(plist_path: Path, label: str, _sudo, repo_root: Path | None = None) -> None:
    """Load a system LaunchDaemon (bootstrap on modern macOS, load as fallback)."""
    import time

    plist_s = str(plist_path)
    expected_py = str(_hardened_python())

    # Preflight: hardened venv must be importable as _deadpush
    _sudo(["-u", "_deadpush", expected_py, "-c", "import deadpush.cli"], check=True)

    # Fully unload stale job (plist edits do not apply until bootout + bootstrap)
    _sudo(["launchctl", "bootout", f"system/{label}"], check=False)
    _sudo(["launchctl", "bootout", "system", plist_s], check=False)
    _sudo(["launchctl", "unload", "-w", plist_s], check=False)
    time.sleep(1)

    r = _sudo(["launchctl", "bootstrap", "system", plist_s], check=False)
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").lower()
        if "already" not in err and "loaded" not in err:
            _sudo(["launchctl", "load", "-w", plist_s])

    _sudo(["launchctl", "enable", f"system/{label}"], check=False)
    _sudo(["launchctl", "kickstart", "-k", f"system/{label}"], check=False)
    time.sleep(2)

    status = _sudo(["launchctl", "print", f"system/{label}"], check=False)
    out = (status.stdout or "") + (status.stderr or "")
    if "state = running" in out and expected_py in out:
        return

    rid = _repo_id(str(repo_root)) if repo_root else "unknown"
    err_log = _HARDENED_STATE_DIR / f"guardian.{rid}.launchd.err.log"
    log_tail = _sudo(["tail", "-30", str(err_log)], check=False).stdout or ""
    raise RuntimeError(
        "LaunchDaemon did not enter running state after bootstrap.\n"
        f"Expected interpreter: {expected_py}\n"
        f"launchctl print:\n{out.strip()}\n"
        f"stderr log ({err_log}):\n{log_tail.strip() or '(empty)'}"
    )


# ---------------------------------------------------------------------------
# ACL helpers
# ---------------------------------------------------------------------------

def _hardened_traverse_dirs(repo_root: Path):
    """Yield existing parent dirs (under $HOME) that need _deadpush traverse access.

    Walks up from the repo toward $HOME, stopping at the filesystem root or a
    system dir. Shared by setup (grant) and teardown (revoke) so the two can
    never drift out of sync.
    """
    repo_root = repo_root.resolve()
    home = Path.home().resolve()
    skip = {Path("/"), Path("/Users")}
    cur = repo_root.parent
    while cur != cur.parent:
        if cur in skip:
            break
        try:
            under_home = cur.is_relative_to(home)
        except AttributeError:
            under_home = str(cur).startswith(str(home) + os.sep) or cur == home
        if not under_home:
            break
        if cur.exists():
            yield cur
        cur = cur.parent


def _apply_hardened_traverse_acls(repo_root: Path, _sudo) -> None:
    """Grant _deadpush traverse access to parent dirs (e.g. ~/Documents mode 700)."""
    if sys.platform == "darwin":
        for cur in _hardened_traverse_dirs(repo_root):
            _sudo(["chmod", "+a", _HARDENED_TRAVERSE_ACE, str(cur)])
    elif sys.platform.startswith("linux"):
        for cur in _hardened_traverse_dirs(repo_root):
            _sudo(["setfacl", "-m", "u:_deadpush:--x", str(cur)], check=False)


def _apply_hardened_repo_acls(repo_root: Path, _sudo=None) -> None:
    """Grant _deadpush read + intervention ACLs on the protected repo tree."""
    import subprocess as _sp

    def run(cmd, **kwargs):
        if _sudo is not None:
            return _sudo(cmd, **kwargs)
        return _sp.run(["sudo"] + cmd, capture_output=True, text=True, timeout=30, **kwargs)

    repo_root = repo_root.resolve()
    quarantine_dir = repo_root / ".deadpush-quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    if sys.platform == "darwin":
        intervention = (
            "_deadpush allow list,readattr,readsecurity,search,read,readextattr,"
            "write,append,add_file,add_subdirectory,delete,delete_child,"
            "file_inherit,directory_inherit"
        )
        run(["chmod", "+a", intervention, str(repo_root)])
        guardian_dir = repo_root / ".guardian"
        guardian_dir.mkdir(parents=True, exist_ok=True)
        run(
            ["chmod", "+a",
             "_deadpush allow write,append,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit",
             str(guardian_dir)],
            timeout=15,
        )
    elif sys.platform.startswith("linux"):
        run(["setfacl", "-R", "-m", "u:_deadpush:rwx", str(repo_root)])
        guardian_dir = repo_root / ".guardian"
        guardian_dir.mkdir(parents=True, exist_ok=True)
        run(["setfacl", "-R", "-m", "u:_deadpush:rwx", str(guardian_dir)], timeout=15)


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def teardown_hardened_environment(repo_root: Path, _sudo=None) -> list[str]:
    """Reverse ``setup_hardened_environment``: revoke every _deadpush ACL (repo
    tree, ``.guardian``, and the parent traverse dirs) and delete the _deadpush
    user/group.

    Platform-aware (macOS ``chmod``/``dscl``, Linux ``setfacl``/``userdel``) and
    strictly best-effort: a missing tool or an absent ACL/account entry is a
    no-op, never a hard failure. ACLs are revoked BEFORE the account is deleted
    so name-based removal still resolves. Returns a list of human-readable
    actions taken.
    """
    import subprocess as _sp

    actions: list[str] = []

    def run(cmd):
        try:
            if _sudo is not None:
                return _sudo(cmd, check=False)
            return _sp.run(["sudo", *cmd], capture_output=True, text=True, timeout=30)
        except Exception:
            return None

    repo_root = repo_root.resolve()
    guardian_dir = repo_root / ".guardian"

    if sys.platform == "darwin":
        run(["chmod", "-R", "-N", str(repo_root)])
        if guardian_dir.exists():
            run(["chmod", "-R", "-N", str(guardian_dir)])
        for cur in _hardened_traverse_dirs(repo_root):
            run(["chmod", "-a", _HARDENED_TRAVERSE_ACE, str(cur)])
        actions.append("Cleared _deadpush ACLs")
        run(["dscl", ".", "-delete", "/Users/_deadpush"])
        run(["dscl", ".", "-delete", "/Groups/_deadpush"])
        actions.append("Removed _deadpush user and group")
    elif sys.platform.startswith("linux"):
        run(["setfacl", "-R", "-x", "u:_deadpush", str(repo_root)])
        if guardian_dir.exists():
            run(["setfacl", "-R", "-x", "u:_deadpush", str(guardian_dir)])
        for cur in _hardened_traverse_dirs(repo_root):
            run(["setfacl", "-x", "u:_deadpush", str(cur)])
        actions.append("Cleared _deadpush ACLs")
        run(["userdel", "_deadpush"])
        run(["groupdel", "_deadpush"])
        actions.append("Removed _deadpush user and group")
    return actions


# ---------------------------------------------------------------------------
# Account management helpers
# ---------------------------------------------------------------------------

def _deadpush_account_valid() -> bool:
    """Return True if _deadpush resolves in the passwd database."""
    import pwd
    try:
        pwd.getpwnam("_deadpush")
        return True
    except KeyError:
        return False


def _find_free_system_id(kind: str, start: int = 400, end: int = 499) -> str:
    """Find an unused UID/GID in a safe system range (macOS dscl)."""
    import subprocess

    r = subprocess.run(
        ["dscl", ".", "-list", f"/{kind}", "UniqueID" if kind == "Users" else "PrimaryGroupID"],
        capture_output=True, text=True, timeout=30,
    )
    used: set[int] = set()
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    used.add(int(parts[-1]))
                except ValueError:
                    pass
    for candidate in range(start, end):
        if candidate not in used:
            return str(candidate)
    raise RuntimeError(f"No free {'UID' if kind == 'Users' else 'GID'} in range {start}-{end - 1}")


def _ensure_deadpush_account(_sudo, lines: list[str]) -> None:
    """Create or repair the _deadpush system user used by hardened mode."""
    import grp
    import subprocess
    import sys as _sys

    if _deadpush_account_valid():
        lines.append("User _deadpush already exists")
        return

    if _sys.platform == "darwin":
        # Remove broken dscl records (exist in Directory Service but not in passwd).
        if subprocess.run(
            ["dscl", ".", "-read", "/Users/_deadpush"],
            capture_output=True, timeout=10,
        ).returncode == 0:
            _sudo(["dscl", ".", "-delete", "/Users/_deadpush"], check=False)
            lines.append("Removed broken _deadpush user record")

        try:
            grp.getgrnam("_deadpush")
        except KeyError:
            if subprocess.run(
                ["dscl", ".", "-read", "/Groups/_deadpush"],
                capture_output=True, timeout=10,
            ).returncode == 0:
                _sudo(["dscl", ".", "-delete", "/Groups/_deadpush"], check=False)
                lines.append("Removed broken _deadpush group record")
            gid = _find_free_system_id("Groups")
            _sudo(["dscl", ".", "-create", "/Groups/_deadpush"])
            _sudo(["dscl", ".", "-create", "/Groups/_deadpush", "PrimaryGroupID", gid])
            _sudo(["dscl", ".", "-create", "/Groups/_deadpush", "RealName", "deadpush Guardian"])
            lines.append(f"Created _deadpush group (GID {gid})")
        else:
            lines.append("Group _deadpush already exists")

        gid = str(grp.getgrnam("_deadpush").gr_gid)
        uid = _find_free_system_id("Users")
        _sudo(["dscl", ".", "-create", "/Users/_deadpush"])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "UserShell", "/usr/bin/false"])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "NFSHomeDirectory", "/var/empty"])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "UniqueID", uid])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "PrimaryGroupID", gid])
        _sudo(["dscl", ".", "-create", "/Users/_deadpush", "RealName", "deadpush Guardian"])
        _sudo(["dscl", ".", "-passwd", "/Users/_deadpush", "*"], check=False)
        _sudo(["dscl", ".", "-append", "/Groups/_deadpush", "GroupMembership", "_deadpush"], check=False)
        lines.append(f"Created _deadpush user (UID {uid}, GID {gid})")
    else:
        try:
            grp.getgrnam("_deadpush")
            lines.append("Group _deadpush already exists")
        except KeyError:
            _sudo(["groupadd", "--system", "_deadpush"])
            lines.append("Created _deadpush system group")
        _sudo([
            "useradd", "--system", "--no-create-home",
            "--shell", "/usr/sbin/nologin",
            "--home-dir", "/var/empty",
            "--gid", "_deadpush",
            "_deadpush",
        ])
        lines.append("Created _deadpush system user")

    if not _deadpush_account_valid():
        raise RuntimeError(
            "_deadpush account setup failed — user not visible to the system. "
            "Try: sudo dscl . -delete /Users/_deadpush && deadpush protect --daemon"
        )


def _ensure_hardened_venv(_sudo, lines: list[str]) -> None:
    """Install deadpush into a dedicated venv owned by _deadpush (not the dev venv)."""
    venv = _HARDENED_VENV_DIR
    py = venv / "bin" / "python"
    if not py.exists():
        bootstrap_py = _find_bootstrap_python()
        _sudo([bootstrap_py, "-m", "venv", str(venv)])
        lines.append(f"Created hardened venv at {venv}")
    else:
        lines.append(f"Hardened venv already exists at {venv}")

    _sudo(["chown", "-R", "_deadpush:_deadpush", str(venv)])

    # How we populate the hardened venv depends on how deadpush itself was installed:
    #  - dev/source checkout: install the working tree so hardened mode tracks local changes.
    #  - normal pip/wheel install: install the matching version from PyPI.
    source = _deadpush_source_root()
    if (source / "pyproject.toml").exists():
        target = str(source)
        origin = f"source {source}"
    else:
        from . import __version__ as _dp_version
        target = f"deadpush=={_dp_version}"
        origin = f"PyPI ({target})"

    pip = str(venv / "bin" / "pip")
    _sudo([pip, "install", "--upgrade", "pip"], check=False)
    _sudo([pip, "install", target])
    _sudo(["chown", "-R", "_deadpush:_deadpush", str(venv)])
    lines.append(f"Installed deadpush into hardened venv from {origin}")


def _setup_hardened_policy(repo_root: Path, _sudo, lines: list[str]) -> None:
    """Create the root-owned policy dir + marker for a hardened install.

    This is what makes hardened mode a real boundary: guardrail policy
    (rules.json / learned_patterns.json) and the fail-closed marker live here,
    owned by _deadpush and readable-but-not-writable by the user, so a same-UID
    agent cannot weaken enforcement by editing in-repo `.deadpush/` files.
    """
    import json as _json
    import tempfile
    import time as _time
    from .config import hardened_policy_dir, hardened_install_marker

    pol_root = _HARDENED_STATE_DIR / "policy"
    pol_dir = hardened_policy_dir(repo_root)
    _sudo(["mkdir", "-p", str(pol_dir)])

    def _install_file(dst: Path, content: str) -> None:
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".tmp", delete=False, encoding="utf-8") as tf:
                tf.write(content)
                tmp = tf.name
            _sudo(["cp", tmp, str(dst)])
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # Migrate existing in-repo policy so the operator's current config carries over.
    for fname in ("rules.json", "learned_patterns.json"):
        src = repo_root / ".deadpush" / fname
        dst = pol_dir / fname
        if src.exists() and not dst.exists():
            try:
                _install_file(dst, src.read_text(encoding="utf-8"))
            except Exception:
                pass

    # Root-owned marker: its presence is the trustworthy signal that this repo
    # is a hardened install (the agent can neither forge nor delete it).
    payload = _json.dumps({
        "mode": "hardened",
        "installed_at": _time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "repo": str(repo_root),
    }, indent=2)
    _install_file(hardened_install_marker(repo_root), payload)

    # _deadpush owns the policy tree; perms let the user traverse + read the
    # authoritative policy but never write it.
    _sudo(["chown", "-R", "_deadpush:_deadpush", str(pol_root)])
    _sudo(["chmod", "-R", "a+rX", str(pol_root)])
    lines.append(f"Created root-owned policy dir {pol_dir}")


# ---------------------------------------------------------------------------
# Top-level setup
# ---------------------------------------------------------------------------

def setup_hardened_environment(repo_root: Path, auto_load: bool = True) -> str:
    """One-time sudo setup for hardened mode: create _deadpush user, state
    directory, repo ACLs, install daemon plist, and load it.

    Uses ``sudo`` for every privileged operation. The user will be prompted
    for their password once (then cached for 5 minutes on macOS).

    Returns a multi-line summary of what was done.
    """
    import subprocess
    import sys as _sys

    lines: list[str] = []

    def _sudo(cmd, check=True, timeout=60):
        full = ["sudo"] + cmd
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(full)} failed: {r.stderr.strip()}")
        return r

    _ensure_deadpush_account(_sudo, lines)

    # Create state directory. 0711 (not 0700) so the user can *traverse* it to
    # execute the root-owned hardened venv interpreter and read the root-owned
    # policy — but not list it, and secret files (control token) stay 0600.
    state = _HARDENED_STATE_DIR
    _sudo(["mkdir", "-p", str(state)])
    _sudo(["chown", "_deadpush:_deadpush", str(state)])
    _sudo(["chmod", "0711", str(state)])
    lines.append(f"Created state dir {state}")

    _ensure_hardened_venv(_sudo, lines)

    # Root-owned policy + fail-closed marker (agent cannot tamper with these).
    _setup_hardened_policy(repo_root, _sudo, lines)

    _apply_hardened_traverse_acls(repo_root, _sudo)
    lines.append(f"Granted _deadpush traverse ACLs to {repo_root}")

    # Intervention ACLs on repo (quarantine, restore, feedback)
    _apply_hardened_repo_acls(repo_root, _sudo)
    lines.append(f"Granted _deadpush intervention ACLs on {repo_root}")

    # Write plist / systemd unit in hardened mode
    autostart_info = setup_autostart(repo_root, hardened=True, _sudo=_sudo)
    _ = autostart_info
    lines.append("Generated daemon configuration")

    # Load the daemon
    if auto_load:
        if _sys.platform == "darwin":
            plist_path = _scoped_plist_path(repo_root, hardened=True)
            label = _scoped_plist_label(repo_root)
            _launchctl_bootstrap_system(plist_path, label, _sudo, repo_root)
            lines.append(f"Loaded launchd daemon: {plist_path}")
        elif _sys.platform.startswith("linux"):
            rid = _repo_id(str(repo_root))
            _sudo(["systemctl", "daemon-reload"])
            _sudo(["systemctl", "enable", "--now", f"deadpush-guardian.{rid}.service"])
            lines.append("Enabled and started systemd service")

    lines.append("")
    lines.append("Hardened mode setup complete.")
    lines.append("The guardian now runs as _deadpush — the AI agent cannot kill or modify it.")
    return "\n".join(lines)
