"""Tests for refusing persistent guardians on the deadpush source repo."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from deadpush.cli import main
from deadpush.config import dev_repo_guard_refusal, is_guardian_dev_repo


@pytest.fixture
def dev_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "deadpush-src"
    repo.mkdir()
    (repo / "deadpush").mkdir()
    (repo / "deadpush" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "deadpush"\nversion = "0.0.0"\n',
        encoding="utf-8",
    )
    return repo


@pytest.fixture
def consumer_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "myapp"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('[project]\nname = "myapp"\n', encoding="utf-8")
    (repo / ".git").mkdir()
    return repo


class TestDevRepoDetection:
    def test_detects_deadpush_source(self, dev_repo: Path):
        assert is_guardian_dev_repo(dev_repo) is True

    def test_ignores_consumer_project(self, consumer_repo: Path):
        assert is_guardian_dev_repo(consumer_repo) is False


class TestDevRepoGuardRefusal:
    def test_blocks_protect_on_dev_repo(self, dev_repo: Path):
        msg = dev_repo_guard_refusal(dev_repo, full_setup=True)
        assert msg is not None
        assert "Refusing to protect" in msg

    def test_blocks_daemon_on_dev_repo(self, dev_repo: Path):
        msg = dev_repo_guard_refusal(dev_repo, persistent=True)
        assert msg is not None
        assert "persistent guardian" in msg

    def test_allows_foreground_guard_on_dev_repo(self, dev_repo: Path):
        assert dev_repo_guard_refusal(dev_repo, persistent=False) is None

    def test_allow_self_protect_override(self, dev_repo: Path):
        assert dev_repo_guard_refusal(dev_repo, persistent=True, allow_self_protect=True) is None
        assert dev_repo_guard_refusal(dev_repo, full_setup=True, allow_self_protect=True) is None

    def test_consumer_repo_never_blocked(self, consumer_repo: Path):
        assert dev_repo_guard_refusal(consumer_repo, full_setup=True) is None
        assert dev_repo_guard_refusal(consumer_repo, persistent=True) is None


class TestGuardCLI:
    def test_guard_daemon_refused_on_dev_repo(self, dev_repo: Path, monkeypatch):
        monkeypatch.chdir(dev_repo)
        runner = CliRunner()
        result = runner.invoke(main, ["guard", "--daemon"])
        assert result.exit_code == 2
        assert "persistent guardian" in result.output

    def test_guard_foreground_allowed_on_dev_repo(self, dev_repo: Path, monkeypatch):
        monkeypatch.setattr("deadpush.guard.WATCHDOG_AVAILABLE", False)
        monkeypatch.chdir(dev_repo)
        runner = CliRunner()
        result = runner.invoke(main, ["guard"])
        assert result.exit_code == 0
        assert "watchdog" in result.output.lower()

    def test_guard_daemon_allowed_with_flag(self, dev_repo: Path, monkeypatch):
        monkeypatch.setattr("deadpush.guard.WATCHDOG_AVAILABLE", False)
        monkeypatch.chdir(dev_repo)
        runner = CliRunner()
        result = runner.invoke(main, ["guard", "--daemon", "--allow-self-protect"])
        assert result.exit_code == 0

    def test_protect_refused_on_dev_repo(self, dev_repo: Path, monkeypatch):
        monkeypatch.chdir(dev_repo)
        runner = CliRunner()
        result = runner.invoke(main, ["protect"])
        assert result.exit_code == 2
        assert "Refusing to protect" in result.output

    def test_intercept_daemon_refused(self, dev_repo: Path, monkeypatch):
        monkeypatch.chdir(dev_repo)
        runner = CliRunner()
        result = runner.invoke(main, ["intercept", "--daemon"])
        assert result.exit_code == 2
