"""Tests for RuntimeConfig — agent-configurable guardrail rules."""

from __future__ import annotations

import json

from deadpush.rules import RuntimeConfig


class TestRuntimeConfig:
    def test_defaults(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        cfg = rc.to_dict()
        assert cfg["allowed_patterns"] == []
        assert cfg["ignored_paths"] == []
        assert cfg["guardrail_levels"]["prompt_injection"] == "block"
        assert cfg["guardrail_levels"]["debris"] == "warn"
        assert cfg["guardrail_levels"]["sensitive"] == "block"
        assert cfg["guardrail_levels"]["destructive"] == "warn"

    def test_add_allowed_pattern(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.add_allowed_pattern(r"safe_eval\(data\)", "Known safe eval")
        assert len(rc._data["allowed_patterns"]) == 1
        assert rc._data["allowed_patterns"][0]["pattern"] == r"safe_eval\(data\)"

    def test_remove_allowed_pattern(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.add_allowed_pattern("test_pattern", "desc")
        assert rc.remove_allowed_pattern("test_pattern") is True
        assert len(rc._data["allowed_patterns"]) == 0

    def test_remove_nonexistent_pattern(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        assert rc.remove_allowed_pattern("nonexistent") is False

    def test_is_allowed(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.add_allowed_pattern("safe_fn", "")
        assert rc.is_allowed("call safe_fn here") is True
        assert rc.is_allowed("call eval here") is False

    def test_ignore_path(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.ignore_path("generated/*")
        assert rc.is_path_ignored("generated/foo.py") is True
        assert rc.is_path_ignored("src/app.py") is False

    def test_ignore_path_exact(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.ignore_path("secrets.py")
        assert rc.is_path_ignored("secrets.py") is True
        assert rc.is_path_ignored("src/secrets.py") is False

    def test_remove_ignored_path(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.ignore_path("test.py")
        assert rc.remove_ignored_path("test.py") is True
        assert rc.is_path_ignored("test.py") is False

    def test_guardrail_levels(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.set_guardrail_level("security", "warn")
        assert rc.get_guardrail_level("security") == "warn"
        rc.set_guardrail_level("security", "block")
        assert rc.get_guardrail_level("security") == "block"
        rc.set_guardrail_level("security", "off")
        assert rc.get_guardrail_level("security") == "off"

    def test_invalid_guardrail_level(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        import pytest as _pytest
        with _pytest.raises(ValueError, match="Level must be one of"):
            rc.set_guardrail_level("security", "invalid")

    def test_reset(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.add_allowed_pattern("p1", "")
        rc.ignore_path("ignored.py")
        rc.set_guardrail_level("debris", "off")
        rc.reset()
        cfg = rc.to_dict()
        assert cfg["allowed_patterns"] == []
        assert cfg["ignored_paths"] == []
        assert cfg["guardrail_levels"]["debris"] == "warn"

    def test_persistence(self, temp_dir):
        """Verify config survives RuntimeConfig instance recreation."""
        rc1 = RuntimeConfig(temp_dir)
        rc1.add_allowed_pattern("persistent_pattern", "testing")
        rc1.set_guardrail_level("secret", "off")

        rc2 = RuntimeConfig(temp_dir)
        cfg = rc2.to_dict()
        assert len(cfg["allowed_patterns"]) == 1
        assert cfg["allowed_patterns"][0]["pattern"] == "persistent_pattern"
        assert cfg["guardrail_levels"]["secret"] == "off"

    def test_file_created(self, temp_dir):
        rc = RuntimeConfig(temp_dir)
        rc.add_allowed_pattern("p", "")
        assert (temp_dir / ".deadpush" / "rules.json").exists()
        data = json.loads((temp_dir / ".deadpush" / "rules.json").read_text())
        assert len(data["allowed_patterns"]) == 1

    def test_load_corrupted_file(self, temp_dir):
        rules_dir = temp_dir / ".deadpush"
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / "rules.json").write_text("invalid json{{{")
        rc = RuntimeConfig(temp_dir)  # should not crash
        assert rc._data["allowed_patterns"] == []

    def test_default_rules_not_mutated(self, temp_dir):
        from deadpush.rules import DEFAULT_RULES
        before = len(DEFAULT_RULES["allowed_patterns"])
        rc = RuntimeConfig(temp_dir)
        rc.add_allowed_pattern("p", "")
        rc.reset()
        assert len(DEFAULT_RULES["allowed_patterns"]) == before
