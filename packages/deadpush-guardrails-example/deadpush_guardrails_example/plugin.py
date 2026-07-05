"""Example guardrail plugin — blocks TODO/FIXME in src/ paths."""

from __future__ import annotations

import re

from deadpush.intercept import Violation
from deadpush.plugins import BaseGuardrailPlugin, CheckContext

_TODO = re.compile(r"\b(TODO|FIXME|HACK)\b", re.IGNORECASE)


class NoTodoInSrcPlugin(BaseGuardrailPlugin):
    name = "no_todo_in_src"
    category = "debris"

    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        if not rel_path.startswith("src/"):
            return []
        violations: list[Violation] = []
        for i, line in enumerate(source.splitlines(), 1):
            if _TODO.search(line):
                violations.append(Violation(
                    self.category,
                    f"TODO/FIXME marker not allowed in src/: {line.strip()[:80]}",
                    i,
                    "low",
                ))
        return violations
