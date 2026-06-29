from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from deadpush import guard
from deadpush.config import Config


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
    def test_returns_launchagent_string(self, tmp_path):
        result = guard.setup_autostart(tmp_path, hardened=False)
        assert "LaunchAgent" in result

    def test_creates_plist_in_launchagents(self, tmp_path):
        guard.setup_autostart(tmp_path, hardened=False)
        plist_path = guard._scoped_plist_path(tmp_path)
        assert plist_path.exists()

    def test_plist_no_hardened_args(self, tmp_path):
        guard.setup_autostart(tmp_path, hardened=False)
        text = guard._scoped_plist_path(tmp_path).read_text()
        assert "--hardened" not in text

    def test_plist_has_working_directory(self, tmp_path):
        guard.setup_autostart(tmp_path, hardened=False)
        text = guard._scoped_plist_path(tmp_path).read_text()
        assert str(tmp_path) in text


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="systemd user units are Linux-only")
class TestSetupAutostartLinuxDefault:
    def test_returns_systemd_user_string(self, tmp_path):
        result = guard.setup_autostart(tmp_path, hardened=False)
        assert "systemd --user" in result

    def test_creates_user_unit(self, tmp_path):
        guard.setup_autostart(tmp_path, hardened=False)
        unit_path = guard._scoped_systemd_unit_path(tmp_path)
        assert unit_path.exists()

    def test_unit_no_hardened_args(self, tmp_path):
        guard.setup_autostart(tmp_path, hardened=False)
        text = guard._scoped_systemd_unit_path(tmp_path).read_text()
        assert "--hardened" not in text

    def test_unit_has_working_directory(self, tmp_path):
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
