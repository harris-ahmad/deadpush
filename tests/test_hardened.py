from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from deadpush import guard


@pytest.fixture
def hardened_env(tmp_path, monkeypatch):
    """Simulate a writable hardened environment by redirecting state and
    autostart paths to a temp directory."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    monkeypatch.setattr(guard, "_state_dir", lambda hardened=False: state_dir)
    rid_fn = guard._repo_id
    if sys.platform == "darwin":
        monkeypatch.setattr(
            guard,
            "_scoped_plist_path",
            lambda r, hardened=False: state_dir
            / f"com.deadpush.guardian.{rid_fn(str(r))}.plist",
        )
    elif sys.platform.startswith("linux"):
        monkeypatch.setattr(
            guard,
            "_scoped_systemd_unit_path",
            lambda r, hardened=False: state_dir
            / f"deadpush-guardian.{rid_fn(str(r))}.service",
        )
    return state_dir


class TestEnsureDeadpushAccount:
    def test_skips_when_user_already_valid(self, monkeypatch):
        monkeypatch.setattr(guard, "_deadpush_account_valid", lambda: True)
        lines: list[str] = []
        calls: list[list[str]] = []

        def _sudo(cmd, check=True, timeout=60):
            calls.append(cmd)
            return None

        guard._ensure_deadpush_account(_sudo, lines)
        assert lines == ["User _deadpush already exists"]
        assert calls == []

    def test_find_free_system_id_skips_used(self, monkeypatch):
        from types import SimpleNamespace

        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: SimpleNamespace(
                returncode=0, stdout="foo 401\nbar 402\n",
            ),
        )
        assert guard._find_free_system_id("Users", start=400, end=405) == "400"

    def test_darwin_repairs_broken_user_with_separate_dscl_calls(self, monkeypatch):
        from types import SimpleNamespace

        valid_checks = iter([False, True])
        monkeypatch.setattr(guard, "_deadpush_account_valid", lambda: next(valid_checks))
        monkeypatch.setattr(guard, "_find_free_system_id", lambda kind: "450")

        class FakeGrp:
            gr_gid = 449

        monkeypatch.setattr("grp.getgrnam", lambda name: FakeGrp())

        def fake_run(cmd, **kwargs):
            if cmd[:3] == ["dscl", ".", "-read"] and cmd[3] == "/Users/_deadpush":
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(returncode=1)

        monkeypatch.setattr("subprocess.run", fake_run)

        sudo_cmds: list[list[str]] = []

        def _sudo(cmd, check=True, timeout=60):
            sudo_cmds.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        lines: list[str] = []
        monkeypatch.setattr("sys.platform", "darwin")
        guard._ensure_deadpush_account(_sudo, lines)

        assert ["dscl", ".", "-delete", "/Users/_deadpush"] in sudo_cmds
        assert ["dscl", ".", "-create", "/Users/_deadpush"] in sudo_cmds
        assert ["dscl", ".", "-create", "/Users/_deadpush", "UserShell", "/usr/bin/false"] in sudo_cmds
        assert ["dscl", ".", "-create", "/Users/_deadpush", "UniqueID", "450"] in sudo_cmds
        assert "Removed broken _deadpush user record" in lines
        assert "Created _deadpush user (UID 450, GID 449)" in lines


class TestStateDir:
    def test_default_is_home_dot_deadpush(self):
        assert guard._state_dir() == Path.home() / ".deadpush"
        assert not guard._is_hardened()

    def test_hardened_returns_var_db(self):
        assert guard._is_hardened(hardened=True)
        assert guard._state_dir(hardened=True) == guard._HARDENED_STATE_DIR

    def test_is_hardened_idempotent(self):
        assert guard._is_hardened(hardened=True)
        assert guard._is_hardened(hardened=True)
        assert guard._state_dir(hardened=True) == Path("/var/db/deadpush")


class TestScopedPaths:
    def test_scoped_pidfile_default(self):
        repo = Path("/tmp/test-repo")
        path = guard._scoped_pidfile(repo)
        assert str(path).startswith(str(Path.home() / ".deadpush"))
        assert path.name.endswith(".pid")
        assert guard._repo_id(str(repo)) in path.name

    def test_scoped_pidfile_hardened(self):
        repo = Path("/tmp/test-repo")
        path = guard._scoped_pidfile(repo, hardened=True)
        assert str(path).startswith("/var/db/deadpush")
        assert path.name.endswith(".pid")

    def test_scoped_lockfile_follows_state_dir(self):
        path = guard._scoped_lockfile(Path("/tmp/test-repo"), hardened=True)
        assert str(path).startswith("/var/db/deadpush")

    def test_scoped_portfile_follows_state_dir(self):
        path = guard._scoped_portfile(Path("/tmp/test-repo"), hardened=True)
        assert str(path).startswith("/var/db/deadpush")
        assert "port" in path.name

    def test_scoped_suspend_file_follows_state_dir(self):
        path = guard._scoped_suspend_file(Path("/tmp/test-repo"), hardened=True)
        assert str(path).startswith("/var/db/deadpush")
        assert "suspended" in path.name

    def test_scoped_plist_label_includes_repo_id(self):
        label = guard._scoped_plist_label(Path("/tmp/test-repo"))
        assert label.startswith("com.deadpush.guardian.")
        assert guard._repo_id("/tmp/test-repo") in label

    @pytest.mark.skipif(sys.platform != "darwin", reason="LaunchAgents are macOS-only")
    def test_scoped_plist_path_default_launchagents(self):
        path = guard._scoped_plist_path(Path("/tmp/test-repo"))
        assert str(path).startswith(str(Path.home() / "Library" / "LaunchAgents"))
        assert path.name.endswith(".plist")

    @pytest.mark.skipif(sys.platform != "darwin", reason="LaunchDaemons are macOS-only")
    def test_scoped_plist_path_hardened_launchdaemons(self):
        path = guard._scoped_plist_path(Path("/tmp/test-repo"), hardened=True)
        assert str(path).startswith("/Library/LaunchDaemons")
        assert path.name.endswith(".plist")

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="systemd units are Linux-only")
    def test_scoped_systemd_unit_path_default_user(self):
        path = guard._scoped_systemd_unit_path(Path("/tmp/test-repo"))
        assert str(path).startswith(str(Path.home() / ".config/systemd/user"))
        assert path.name.endswith(".service")

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="systemd units are Linux-only")
    def test_scoped_systemd_unit_path_hardened_system(self):
        path = guard._scoped_systemd_unit_path(Path("/tmp/test-repo"), hardened=True)
        assert str(path).startswith("/etc/systemd/system")
        assert path.name.endswith(".service")


class TestRepoId:
    def test_repo_id_is_deterministic(self):
        assert guard._repo_id("/foo/bar") == guard._repo_id("/foo/bar")

    def test_repo_id_different_for_different_paths(self):
        assert guard._repo_id("/foo/bar") != guard._repo_id("/foo/baz")

    def test_repo_id_is_12_hex_chars(self):
        rid = guard._repo_id("/some/random/path")
        assert len(rid) == 12
        assert all(c in "0123456789abcdef" for c in rid)


@pytest.mark.skipif(sys.platform != "darwin", reason="LaunchAgents are macOS-only")
class TestSetupAutostartDefault:
    # NOTE: these MUST take `hardened_env`. Without it, setup_autostart writes a
    # real plist into ~/Library/LaunchAgents (the path is derived from Path.home(),
    # not from tmp_path), which litters the developer's machine and triggers a
    # macOS "App can run in the background" notification on every test run.
    def test_returns_launchagent_string(self, tmp_path, hardened_env):
        result = guard.setup_autostart(tmp_path, hardened=False)
        assert "LaunchAgent" in result

    def test_creates_plist_in_launchagents(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=False)
        plist_path = guard._scoped_plist_path(tmp_path)
        assert plist_path.exists()

    def test_plist_no_hardened_args(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=False)
        text = guard._scoped_plist_path(tmp_path).read_text()
        assert "--hardened" not in text

    def test_plist_has_working_directory(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=False)
        text = guard._scoped_plist_path(tmp_path).read_text()
        assert str(tmp_path) in text


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="systemd user units are Linux-only")
class TestSetupAutostartLinuxDefault:
    # See note above: without `hardened_env` these write real unit files into
    # ~/.config/systemd/user, polluting the developer's machine.
    def test_returns_systemd_user_string(self, tmp_path, hardened_env):
        result = guard.setup_autostart(tmp_path, hardened=False)
        assert "systemd --user" in result

    def test_creates_user_unit(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=False)
        unit_path = guard._scoped_systemd_unit_path(tmp_path)
        assert unit_path.exists()

    def test_unit_no_hardened_args(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=False)
        text = guard._scoped_systemd_unit_path(tmp_path).read_text()
        assert "--hardened" not in text

    def test_unit_has_working_directory(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=False)
        text = guard._scoped_systemd_unit_path(tmp_path).read_text()
        assert str(tmp_path) in text


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS hardened tests use LaunchDaemons")
class TestSetupAutostartHardened:
    def test_returns_system_unit_string(self, tmp_path, hardened_env):
        result = guard.setup_autostart(tmp_path, hardened=True)
        assert "systemd system" in result

    def test_creates_unit(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        unit_path = guard._scoped_systemd_unit_path(tmp_path, hardened=True)
        assert unit_path.exists()

    def test_unit_contains_user_name(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        text = guard._scoped_systemd_unit_path(tmp_path, hardened=True).read_text()
        assert "_deadpush" in text

    def test_unit_contains_daemon_and_hardened_args(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        text = guard._scoped_systemd_unit_path(tmp_path, hardened=True).read_text()
        assert "--daemon" in text
        assert "--hardened" in text

    def test_sets_state_dir(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        assert guard._is_hardened(hardened=True)

    def test_unit_has_working_directory(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        text = guard._scoped_systemd_unit_path(tmp_path, hardened=True).read_text()
        assert str(tmp_path) in text


@pytest.mark.skipif(sys.platform != "darwin", reason="LaunchDaemons are macOS-only")
class TestSetupAutostartHardenedDarwin:
    def test_returns_launchdaemon_string(self, tmp_path, hardened_env):
        result = guard.setup_autostart(tmp_path, hardened=True)
        assert "LaunchDaemon" in result

    def test_creates_plist(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        plist_path = guard._scoped_plist_path(tmp_path, hardened=True)
        assert plist_path.exists()

    def test_plist_contains_user_name(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        text = guard._scoped_plist_path(tmp_path, hardened=True).read_text()
        assert "_deadpush" in text

    def test_plist_contains_daemon_and_hardened_args(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        text = guard._scoped_plist_path(tmp_path, hardened=True).read_text()
        assert "--daemon" in text
        assert "--hardened" in text

    def test_plist_has_working_directory(self, tmp_path, hardened_env):
        guard.setup_autostart(tmp_path, hardened=True)
        text = guard._scoped_plist_path(tmp_path, hardened=True).read_text()
        assert str(tmp_path) in text


class TestMcpHardened:
    def test_auto_detects_via_shared_port(self, temp_repo, monkeypatch):
        import os
        os.chdir(temp_repo)

        from deadpush.mcp_server import run_mcp

        shared = temp_repo / ".guardian"
        shared.mkdir(parents=True)
        (shared / "guardian.control.port").write_text("9999")

        monkeypatch.setattr("sys.stdin", None)
        monkeypatch.setattr("sys.stdout", None)

        with pytest.raises((AttributeError, TypeError, RuntimeError)):
            run_mcp()
        assert guard._is_hardened(hardened=True)

    def test_explicit_hardened_flag(self, temp_repo, monkeypatch):
        import os
        os.chdir(temp_repo)

        from deadpush.mcp_server import run_mcp

        monkeypatch.setattr("sys.stdin", None)
        monkeypatch.setattr("sys.stdout", None)

        with pytest.raises((AttributeError, TypeError, RuntimeError)):
            run_mcp(hardened=True)
        assert guard._is_hardened(hardened=True)

    def test_default_no_hardened_detection(self, temp_repo, monkeypatch):
        import os
        os.chdir(temp_repo)

        from deadpush.mcp_server import run_mcp

        monkeypatch.setattr("sys.stdin", None)
        monkeypatch.setattr("sys.stdout", None)

        with pytest.raises((AttributeError, TypeError, RuntimeError)):
            run_mcp()
        assert not guard._is_hardened(hardened=False)


class TestTeardownHardenedEnvironment:
    """teardown_hardened_environment must reverse setup on BOTH platforms and
    never crash on a missing tool (the launchctl/dscl-on-Linux class of bug)."""

    @staticmethod
    def _recorder():
        calls: list[list[str]] = []

        def _sudo(cmd, check=True, timeout=60):
            calls.append(cmd)
            return None

        return calls, _sudo

    def test_linux_uses_setfacl_and_userdel(self, tmp_path, monkeypatch):
        monkeypatch.setattr(guard.sys, "platform", "linux")
        (tmp_path / ".guardian").mkdir()
        calls, _sudo = self._recorder()

        actions = guard.teardown_hardened_environment(tmp_path, _sudo=_sudo)

        repo = str(tmp_path.resolve())
        guardian = str((tmp_path / ".guardian").resolve())
        assert ["setfacl", "-R", "-x", "u:_deadpush", repo] in calls
        assert ["setfacl", "-R", "-x", "u:_deadpush", guardian] in calls
        assert ["userdel", "_deadpush"] in calls
        assert ["groupdel", "_deadpush"] in calls
        # No macOS-only tools on Linux.
        assert not any(c[0] in ("dscl", "chmod") for c in calls)
        assert "Removed _deadpush user and group" in actions

    def test_darwin_uses_chmod_and_dscl(self, tmp_path, monkeypatch):
        monkeypatch.setattr(guard.sys, "platform", "darwin")
        (tmp_path / ".guardian").mkdir()
        calls, _sudo = self._recorder()

        guard.teardown_hardened_environment(tmp_path, _sudo=_sudo)

        repo = str(tmp_path.resolve())
        assert ["chmod", "-R", "-N", repo] in calls
        assert ["dscl", ".", "-delete", "/Users/_deadpush"] in calls
        assert ["dscl", ".", "-delete", "/Groups/_deadpush"] in calls
        # No Linux-only tools on macOS.
        assert not any(c[0] in ("setfacl", "userdel", "groupdel") for c in calls)

    def test_acls_revoked_before_account_deleted(self, tmp_path, monkeypatch):
        """Name-based ACL removal must run before the account is deleted."""
        monkeypatch.setattr(guard.sys, "platform", "linux")
        calls, _sudo = self._recorder()

        guard.teardown_hardened_environment(tmp_path, _sudo=_sudo)

        last_setfacl = max(i for i, c in enumerate(calls) if c[0] == "setfacl")
        first_userdel = next(i for i, c in enumerate(calls) if c[0] == "userdel")
        assert last_setfacl < first_userdel

    def test_missing_tool_does_not_raise(self, tmp_path, monkeypatch):
        """A missing service/ACL tool (e.g. dscl on Linux) must be a no-op."""
        monkeypatch.setattr(guard.sys, "platform", "linux")

        def boom(*a, **k):
            raise FileNotFoundError("setfacl")

        monkeypatch.setattr("subprocess.run", boom)
        # No _sudo -> uses subprocess directly; must swallow the error.
        actions = guard.teardown_hardened_environment(tmp_path)
        assert isinstance(actions, list)
