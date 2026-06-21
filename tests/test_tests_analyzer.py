"""Tests for the Test Quality Analyzer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.tests import TestAnalyzer, TestIssue


class TestTestAnalyzer:
    def _make_analyzer(self):
        return TestAnalyzer()

    # --- Python tests ---

    def test_analyze_python_no_assertions(self, temp_dir):
        f = temp_dir / "test_foo.py"
        f.write_text("def test_something():\n    x = 1 + 1\n")
        issues = self._make_analyzer().analyze_file(f, "test_foo.py")
        assert any(i.issue_type == "no_assertions" for i in issues)

    def test_analyze_python_with_assertion(self, temp_dir):
        f = temp_dir / "test_foo.py"
        f.write_text("def test_something():\n    assert 1 + 1 == 2\n")
        issues = self._make_analyzer().analyze_file(f, "test_foo.py")
        assert len(issues) == 0

    def test_tautological_assert_true(self, temp_dir):
        f = temp_dir / "test_bar.py"
        f.write_text("def test_bar():\n    assert True\n")
        issues = self._make_analyzer().analyze_file(f, "test_bar.py")
        assert any(i.issue_type == "tautology" for i in issues)

    def test_tautological_assert_equal(self, temp_dir):
        f = temp_dir / "test_baz.py"
        f.write_text("def test_baz():\n    assert 1 == 1\n")
        issues = self._make_analyzer().analyze_file(f, "test_baz.py")
        assert any(i.issue_type == "tautology" for i in issues)

    def test_empty_test(self, temp_dir):
        f = temp_dir / "test_empty.py"
        f.write_text("def test_empty():\n    pass\n")
        issues = self._make_analyzer().analyze_file(f, "test_empty.py")
        assert any(i.issue_type == "empty_test" for i in issues)

    def test_bare_except(self, temp_dir):
        f = temp_dir / "test_except.py"
        f.write_text("def test_except():\n    try:\n        x = 1\n    except:\n        pass\n")
        issues = self._make_analyzer().analyze_file(f, "test_except.py")
        assert any(i.issue_type == "broad_catch" for i in issues)

    def test_test_class(self, temp_dir):
        f = temp_dir / "test_class.py"
        f.write_text("class TestFoo:\n    def test_bar(self):\n        result = 1 + 1\n        assert result == 2\n")
        issues = self._make_analyzer().analyze_file(f, "test_class.py")
        assert len(issues) == 0

    def test_non_test_file_skipped(self, temp_dir):
        f = temp_dir / "app.py"
        f.write_text("def test():\n    pass\n")
        issues = self._make_analyzer().analyze_file(f, "app.py")
        assert len(issues) == 0

    def test_assertEqual_self_comparison(self, temp_dir):
        f = temp_dir / "test_self.py"
        f.write_text("def test_self():\n    x = 1\n    self.assertEqual(x, x)\n")
        issues = self._make_analyzer().analyze_file(f, "test_self.py")
        assert any(i.issue_type == "tautology" for i in issues)

    def test_assertTrue_with_bool_const(self, temp_dir):
        f = temp_dir / "test_true.py"
        f.write_text("def test_true():\n    self.assertTrue(True)\n")
        issues = self._make_analyzer().analyze_file(f, "test_true.py")
        assert any(i.issue_type == "tautology" for i in issues)

    # --- Generic (JS/TS) tests ---

    def test_js_no_assertions(self, temp_dir):
        f = temp_dir / "app.test.js"
        f.write_text("test('adds numbers', () => {\n  const result = 1 + 2;\n});\n")
        issues = self._make_analyzer().analyze_file(f, "app.test.js")
        assert any(i.issue_type == "no_assertions" for i in issues)

    def test_js_with_expect(self, temp_dir):
        f = temp_dir / "app.test.js"
        f.write_text("test('adds numbers', () => {\n  expect(1 + 2).toBe(3);\n});\n")
        issues = self._make_analyzer().analyze_file(f, "app.test.js")
        assert len(issues) == 0

    def test_jest_describe_it(self, temp_dir):
        # The regex JS/TS analyzer is simplistic — it treats `describe` as a test
        # that contains `it` blocks. The `it` blocks are found, so only the
        # outer `describe` is flagged as no-assertions.
        f = temp_dir / "suite.test.ts"
        f.write_text("describe('math', () => {\n  it('adds', () => {\n    expect(1+1).toBe(2);\n  });\n});\n")
        issues = self._make_analyzer().analyze_file(f, "suite.test.ts")
        # Outer 'describe' block flagged (no direct assertions), inner 'it' is fine
        assert len(issues) == 1
        assert issues[0].issue_type == "no_assertions"

    def test_syntax_error_does_not_crash(self, temp_dir):
        f = temp_dir / "test_bad.py"
        f.write_text("def test_bad(:\n    pass\n")  # syntax error
        issues = self._make_analyzer().analyze_file(f, "test_bad.py")
        assert len(issues) == 0

    def test_issue_dataclass(self):
        i = TestIssue("file.py", 10, "tautology", "test has tautology", 0.95)
        assert i.file == "file.py"
        assert i.issue_type == "tautology"
        assert i.confidence == 0.95
