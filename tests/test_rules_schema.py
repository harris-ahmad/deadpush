"""Validate rules.json JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

from deadpush.rules import DEFAULT_RULES


def test_rules_schema_matches_defaults():
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "rules.v2.schema.json").read_text())
    assert schema["type"] == "object"
    assert "guardrail_levels" in schema["properties"]
    for key in DEFAULT_RULES["guardrail_levels"]:
        assert key in schema["properties"]["guardrail_levels"]["properties"]
