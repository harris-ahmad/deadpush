"""Tests for git hook bypass detection in sandbox sessions."""

from __future__ import annotations

from deadpush.git_escape import detect_git_config_escape


def test_detect_core_hookspath_escape():
    assert detect_git_config_escape(["-c", "core.hooksPath=/tmp/evil", "commit"])
    assert detect_git_config_escape(["commit", "-c", "core.hooksPath=/tmp/evil"])


def test_detect_init_templatedir_escape():
    assert detect_git_config_escape(["-c", "init.templateDir=/tmp/evil", "init"])


def test_allows_normal_git():
    assert detect_git_config_escape(["status"]) is None
    assert detect_git_config_escape(["commit", "-m", "ok"]) is None
    assert detect_git_config_escape(["-c", "user.email=test@test.com", "commit"]) is None
