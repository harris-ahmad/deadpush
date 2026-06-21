"""
Test Quality Analyzer — detects weak, trivial, or sabotaged AI-generated tests.

AI coding agents frequently produce tests that pass trivially:
- No assertions (test runs but verifies nothing)
- Tautological assertions (assert True, assert 1 == 1)
- Overly broad exception catching (test never fails)
- Implementation mirroring (test reimplements the logic it's testing)
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ASSERT_KEYWORDS = {
    "assert", "assertEqual", "assertEquals", "assertTrue", "assertFalse",
    "assertIs", "assertIsNot", "assertIsNone", "assertIsNotNone",
    "assertIn", "assertNotIn", "assertRaises", "assertAlmostEqual",
    "assertGreater", "assertLess", "assertRegex", "assertCountEqual",
    "assertDictEqual", "assertListEqual", "assertSetEqual", "assertTupleEqual",
    "assertMultiLineEqual", "assertSequenceEqual",
    "expect", "toHaveBeenCalled", "toHaveBeenCalledWith",
    "toBe", "toEqual", "toMatch", "toContain", "toBeTruthy",
    "toBeFalsy", "toBeNull", "toBeUndefined", "toBeDefined",
    "toThrow", "toThrowError", "toStrictEqual", "toHaveProperty",
    "should", "should.equal", "should.eql", "should.be",
    "expectThat", "assertThat", "verify",
    "assert_not_called", "assert_called_once", "assert_called_with",
    "assert_has_calls", "assert_any_call", "assert_not_awaited",
}

TAUTOLOGY_PATTERNS = [
    re.compile(r'assert\s+True\b'),
    re.compile(r'assert\s+False\b'),
    re.compile(r'assert\s+1\s*==\s*1'),
    re.compile(r'assert\s+0\s*==\s*0'),
    re.compile(r'assert\s+"[^"]*"\s*==\s*"[^"]*"'),
    re.compile(r'assertEqual\(True,\s*True\)'),
    re.compile(r'assertEqual\(False,\s*False\)'),
    re.compile(r'\.toBe\(true\)'),
    re.compile(r'\.toBe\(false\)'),
    re.compile(r'\.toEqual\(\{[^}]*\},\s*\{[^}]*\}\)'),
    re.compile(r'assert\s+is\s+None\s*\n'),
]


BROAD_CATCH_PATTERNS = [
    re.compile(r'except\s+Exception\s*:'),
    re.compile(r'except\s*:'),
    re.compile(r'catch\s*\(\s*(err|e|error)\s*\)\s*\{'),
]


@dataclass
class TestIssue:
    """A quality issue found in a test file."""
    file: str
    line: int
    issue_type: str  # "no_assertions" | "tautology" | "broad_catch" | "empty_test"
    description: str
    confidence: float = 0.9


class TestAnalyzer:
    """Analyzes test files for quality issues common in AI-generated code."""

    # ------------------------------------------------------------------
    # Python-specific: AST-based analysis
    # ------------------------------------------------------------------
    def _analyze_python_test(self, path: Path, rel_path: str) -> list[TestIssue]:
        """Deep analysis of Python test files using AST."""
        issues: list[TestIssue] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, Exception):
            return issues

        for node in ast.walk(tree):
            # Find test functions (def test_* or def *_test)
            if isinstance(node, ast.FunctionDef) and (node.name.startswith("test_") or node.name.endswith("_test")):
                self._check_python_test_function(node, source, path, rel_path, issues)

            # Find test classes (class Test*)
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and (item.name.startswith("test_") or item.name.endswith("_test")):
                        self._check_python_test_function(item, source, path, rel_path, issues)

        return issues

    def _check_python_test_function(self, node: ast.FunctionDef, source: str, path: Path, rel_path: str, issues: list[TestIssue]):
        """Check a single Python test function for quality issues."""
        func_source = ast.get_source_segment(source, node) or ""

        # Count assertion calls
        has_assertion = False
        has_tautology = False
        for child in ast.walk(node):
            # Direct assert statements
            if isinstance(child, ast.Assert):
                has_assertion = True
                # Check for tautologies
                if isinstance(child.test, ast.Constant):
                    if child.test.value is True or child.test.value is False:
                        has_tautology = True
                        issues.append(TestIssue(
                            file=rel_path,
                            line=child.lineno or node.lineno,
                            issue_type="tautology",
                            description=f"Tautological assertion 'assert {child.test.value}' in test '{node.name}'",
                            confidence=0.95,
                        ))
                elif isinstance(child.test, ast.Compare):
                    if self._is_self_comparison(child.test):
                        has_tautology = True
                        issues.append(TestIssue(
                            file=rel_path,
                            line=child.lineno or node.lineno,
                            issue_type="tautology",
                            description=f"Self-comparison assertion in test '{node.name}'",
                            confidence=0.92,
                        ))

            # assertEqual/assertTrue/etc method calls
            elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if child.func.attr in ("assertEqual", "assertEquals") and len(child.args) == 2:
                    has_assertion = True
                    if self._is_self_comparison_of_args(child.args[0], child.args[1]):
                        has_tautology = True
                        issues.append(TestIssue(
                            file=rel_path,
                            line=child.lineno or node.lineno,
                            issue_type="tautology",
                            description=f"Self-comparison assertEqual in test '{node.name}'",
                            confidence=0.92,
                        ))
                elif child.func.attr in ("assertTrue", "assertFalse"):
                    has_assertion = True
                    if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, bool):
                        has_tautology = True
                        issues.append(TestIssue(
                            file=rel_path,
                            line=child.lineno or node.lineno,
                            issue_type="tautology",
                            description=f"Tautological assert{child.func.attr} in test '{node.name}'",
                            confidence=0.95,
                        ))

        # Check for broad exception catching
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                if child.type is None:
                    issues.append(TestIssue(
                        file=rel_path,
                        line=child.lineno or node.lineno,
                        issue_type="broad_catch",
                        description=f"Bare 'except:' in test '{node.name}' — test will never fail",
                        confidence=0.93,
                    ))

        # Check if test is completely empty or just pass/docstring
        body_lines = [b for b in node.body if not isinstance(b, (ast.Expr, ast.Pass, ast.Constant))]
        if not [b for b in node.body if not isinstance(b, (ast.Expr, ast.Pass))] and not has_assertion:
            issues.append(TestIssue(
                file=rel_path,
                line=node.lineno,
                issue_type="empty_test",
                description=f"Test '{node.name}' is empty (only docstring/pass)",
                confidence=0.98,
            ))

        # No assertions at all
        if not has_assertion and not has_tautology:
            # Only flag if it has real code (not just pass/docstring)
            has_code = any(
                isinstance(b, (ast.Assign, ast.Call, ast.With, ast.For, ast.While))
                for b in node.body
            )
            if has_code:
                issues.append(TestIssue(
                    file=rel_path,
                    line=node.lineno,
                    issue_type="no_assertions",
                    description=f"Test '{node.name}' has no assertions — verifies nothing",
                    confidence=0.90,
                ))

    def _is_self_comparison(self, compare: ast.Compare) -> bool:
        """Check if comparison is against itself (e.g., x == x)."""
        if len(compare.ops) == 1 and len(compare.comparators) == 1:
            left = compare.left
            right = compare.comparators[0]
            if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                return left.id == right.id
            if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
                return left.value == right.value
        return False

    def _is_self_comparison_of_args(self, arg1, arg2) -> bool:
        """Check if two AST nodes represent the same expression."""
        if isinstance(arg1, ast.Name) and isinstance(arg2, ast.Name):
            return arg1.id == arg2.id
        if isinstance(arg1, ast.Constant) and isinstance(arg2, ast.Constant):
            return arg1.value == arg2.value
        return False

    # ------------------------------------------------------------------
    # Generic (JS/TS/Go/Rust): regex-based analysis
    # ------------------------------------------------------------------
    def _analyze_generic_test(self, path: Path, rel_path: str) -> list[TestIssue]:
        """Regex-based test quality check for non-Python languages."""
        issues: list[TestIssue] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            lines = source.splitlines()
        except Exception:
            return issues

        # Find test functions by common patterns
        test_func_pattern = re.compile(
            r'(?:it|test|describe)\s*\(?\s*[\'"]([^\'"]+)[\'"]\s*,?\s*(?:function\s*\(|\(|async\s*\(|=>)'
        )
        # Jest/Vitest: test('name', () => { ... })
        # Go: func Test*(t *testing.T)
        # Rust: #[test] fn test_*

        # For JS/TS, find test blocks and check for assertions
        in_test = False
        test_name = ""
        test_start = 0
        open_parens = 0
        has_assert = False
        has_tautology = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detect test function start
            match = test_func_pattern.search(line)
            if match and ("=>" in stripped or "function" in stripped):
                if in_test:
                    # Previous test had no assertions
                    if not has_assert:
                        issues.append(TestIssue(
                            file=rel_path,
                            line=test_start + 1,
                            issue_type="no_assertions",
                            description=f"Test '{test_name}' has no assertions",
                            confidence=0.85,
                        ))
                test_name = match.group(1)
                test_start = i
                in_test = True
                has_assert = False

                # Count braces for scope tracking
                open_parens = stripped.count("{") - stripped.count("}")
                continue

            if in_test:
                # Track braces for end of test
                open_parens += stripped.count("{") - stripped.count("}")
                if open_parens <= 0:
                    in_test = False
                    if not has_assert:
                        issues.append(TestIssue(
                            file=rel_path,
                            line=test_start + 1,
                            issue_type="no_assertions",
                            description=f"Test '{test_name}' has no assertions",
                            confidence=0.85,
                        ))
                    continue

                # Check for assertions
                if any(kw in stripped for kw in ASSERT_KEYWORDS):
                    has_assert = True

                # Check for tautologies
                for pat in TAUTOLOGY_PATTERNS:
                    if pat.search(stripped):
                        has_tautology = True
                        issues.append(TestIssue(
                            file=rel_path,
                            line=i + 1,
                            issue_type="tautology",
                            description=f"Tautological assertion in test '{test_name}': {stripped[:60]}",
                            confidence=0.92,
                        ))

        return issues

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze_file(self, path: Path, rel_path: str) -> list[TestIssue]:
        """Analyze a single source file for test quality issues."""
        # Only analyze test files
        rel_str = rel_path.lower()
        is_test_file = (
            rel_str.startswith("test") or "/test" in rel_str or "\\test" in rel_str
            or rel_str.startswith("spec") or "/spec" in rel_str
            or rel_str.endswith("_test.go") or rel_str.endswith("_test.rs")
            or rel_str.endswith(".test.js") or rel_str.endswith(".test.ts")
            or rel_str.endswith(".spec.js") or rel_str.endswith(".spec.ts")
            or rel_str.endswith("_test.py") or rel_str.endswith("_test.rs")
        )
        if not is_test_file:
            return []

        if path.suffix == ".py":
            return self._analyze_python_test(path, rel_path)
        else:
            return self._analyze_generic_test(path, rel_path)

    def analyze_batch(self, files: list[Any]) -> list[TestIssue]:
        """Analyze all test files in a batch."""
        all_issues: list[TestIssue] = []
        for f in files:
            if not getattr(f, "is_text", True):
                continue
            try:
                issues = self.analyze_file(f.path, str(getattr(f, "rel_path", f.path)))
                all_issues.extend(issues)
            except Exception:
                pass
        return all_issues
