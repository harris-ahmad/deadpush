"""Tests for the Stale Comment Detector."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.comments import StaleCommentDetector, StaleDocIssue


class TestStaleCommentDetector:
    def _make_detector(self):
        return StaleCommentDetector()

    def test_no_docstring(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text("def public_func():\n    pass\n")
        issues = self._make_detector().analyze_file(f, "module.py")
        assert any(i.issue_type == "missing_doc" for i in issues)

    def test_private_function_no_docstring(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text("def _private():\n    pass\n")
        issues = self._make_detector().analyze_file(f, "module.py")
        assert len(issues) == 0

    def test_stale_param(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text('''def process(a, b):
    """Process data.

    Args:
        a: first param
        b: second param
        c: this param doesn't exist
    """
    return a + b
''')
        issues = self._make_detector().analyze_file(f, "module.py")
        stale = [i for i in issues if i.issue_type == "stale_param"]
        assert any("c" in i.description for i in stale)

    def test_undocumented_params(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text('''def process(a, b, c):
    """Process data.

    Args:
        a: first param
    """
    return a + b + c
''')
        issues = self._make_detector().analyze_file(f, "module.py")
        missing = [i for i in issues if i.issue_type == "missing_doc" and "b" in i.description and "c" in i.description]
        assert any("b" in i.description for i in missing)

    def test_missing_return_doc(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text('''def compute():
    """Compute something."""
    return 42
''')
        issues = self._make_detector().analyze_file(f, "module.py")
        assert any(i.issue_type == "missing_return_doc" for i in issues)

    def test_complete_docstring(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text('''def compute(a, b):
    """Compute sum.

    :param a: first
    :param b: second
    :return: result
    """
    return a + b
''')
        issues = self._make_detector().analyze_file(f, "module.py")
        assert len(issues) == 0

    def test_async_function(self, temp_dir):
        f = temp_dir / "async_mod.py"
        f.write_text("async def fetch_data():\n    return 'data'\n")
        issues = self._make_detector().analyze_file(f, "async_mod.py")
        assert any(i.issue_type == "missing_doc" for i in issues)

    def test_rst_style_params(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text('''def process(a, b):
    """Process.

    :param a: first
    :param b: second
    :return: result
    """
    return a + b
''')
        issues = self._make_detector().analyze_file(f, "module.py")
        assert len(issues) == 0

    def test_param_tag_style(self, temp_dir):
        f = temp_dir / "module.py"
        f.write_text('''def process(a, b):
    """Process.

    @param a: first
    @param b: second
    @return: result
    """
    return a + b
''')
        issues = self._make_detector().analyze_file(f, "module.py")
        assert len(issues) == 0

    def test_syntax_error_does_not_crash(self, temp_dir):
        f = temp_dir / "bad.py"
        f.write_text("def bad(:\n    pass\n")
        issues = self._make_detector().analyze_file(f, "bad.py")
        assert len(issues) == 0

    def test_jsdoc_stale_param(self, temp_dir):
        f = temp_dir / "app.ts"
        f.write_text('''/**
 * Process data.
 * @param a - first param
 * @param x - suspiciously short name
 */
function process(a: string) {
    return a;
}
''')
        issues = self._make_detector().analyze_file(f, "app.ts")
        stale = [i for i in issues if i.issue_type == "stale_param"]
        assert len(stale) >= 1

    def test_jsdoc_missing_return(self, temp_dir):
        f = temp_dir / "math.js"
        f.write_text('''/**
 * Add two numbers.
 * @param {number} a
 * @param {number} b
 */
function add(a, b) {
    return a + b;
}
''')
        issues = self._make_detector().analyze_file(f, "math.js")
        assert any(i.issue_type == "missing_return_doc" for i in issues)

    def test_jsdoc_complete(self, temp_dir):
        f = temp_dir / "math.js"
        f.write_text('''/**
 * Add two numbers.
 * @param {number} first
 * @param {number} second
 * @returns {number}
 */
function add(first, second) {
    return first + second;
}
''')
        issues = self._make_detector().analyze_file(f, "math.js")
        assert len(issues) == 0

    def test_issue_dataclass(self):
        i = StaleDocIssue("file.py", 10, "func", "stale_param", "param not found", 0.9)
        assert i.function == "func"
        assert i.issue_type == "stale_param"
