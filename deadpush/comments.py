"""
Stale Comment Detection — finds docstrings that reference non-existent parameters.

AI agents frequently write verbose documentation that drifts from the actual
implementation. This module compares documented parameters in docstrings with
actual function signatures, flagging mismatches.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


PARAM_SECTION_PATTERNS = [
    re.compile(r'Args:\s*', re.MULTILINE),
    re.compile(r'Params?:\s*', re.MULTILINE),
    re.compile(r'Parameters\s*[-:]\s*', re.MULTILINE),
    re.compile(r'Keyword\s+Args?:\s*', re.MULTILINE),
    re.compile(r'Keyword\s+Parameters:\s*', re.MULTILINE),
    re.compile(r'Attributes:\s*', re.MULTILINE),
    re.compile(r'Fields:\s*', re.MULTILINE),
]

DOC_PARAM_PATTERN = re.compile(r'^\s{4}(\w+)\s*[(:]', re.MULTILINE)
PARAM_TAG_PATTERN = re.compile(r'@param\s+\{?\w*\}?\s*(\w+)')
COLON_PARAM_PATTERN = re.compile(r':param\s+(\w+)\s*:')
RETURN_TAG_PATTERN = re.compile(r'@returns?\s+\{?\w*\}?\s*(.*)')
RETURN_SECTION_PATTERN = re.compile(r'Returns:\s*\n((?:\s{4}.+\n?)*)', re.MULTILINE)


@dataclass
class StaleDocIssue:
    """A documentation mismatch issue."""
    file: str
    line: int
    function: str
    issue_type: str  # "missing_doc" | "stale_param" | "missing_return_doc"
    description: str
    confidence: float = 0.85


class StaleCommentDetector:
    """Detects stale documentation by comparing docstrings with actual code."""

    # ------------------------------------------------------------------
    # Python: AST-based analysis
    # ------------------------------------------------------------------
    def _extract_python_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        """Extract actual parameter names from a function definition."""
        params: set[str] = set()
        for arg in node.args.args:
            if arg.arg not in ("self", "cls"):
                params.add(arg.arg)
        if node.args.vararg:
            params.add(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            params.add(f"**{node.args.kwarg.arg}")
        for arg in node.args.kwonlyargs:
            params.add(arg.arg)
        for arg in node.args.posonlyargs:
            if arg.arg not in ("self", "cls"):
                params.add(arg.arg)
        return params

    def _extract_doc_params_python(self, docstring: str) -> set[str]:
        """Extract documented parameter names from a Python docstring."""
        doc_params: set[str] = set()

        # Google-style: Args:\n    param_name: description
        for section_pat in PARAM_SECTION_PATTERNS:
            section_match = section_pat.search(docstring)
            if section_match:
                rest = docstring[section_match.end():]
                for m in DOC_PARAM_PATTERN.finditer(rest):
                    doc_params.add(m.group(1))

        # RST-style: :param name: description
        doc_params.update(COLON_PARAM_PATTERN.findall(docstring))

        # Epydoc/Google: @param name: description
        doc_params.update(PARAM_TAG_PATTERN.findall(docstring))

        return doc_params

    def _check_python_file(self, path: Path, rel_path: str) -> list[StaleDocIssue]:
        """Analyze a single Python file for stale docstring issues."""
        issues: list[StaleDocIssue] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, Exception):
            return issues

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                docstring = ast.get_docstring(node) or ""
                actual_params = self._extract_python_params(node)
                doc_params = self._extract_doc_params_python(docstring) if docstring else set()

                if not docstring and node.name != "__init__":
                    # Only flag public functions without docs
                    if not node.name.startswith("_"):
                        issues.append(StaleDocIssue(
                            file=rel_path,
                            line=node.lineno,
                            function=node.name,
                            issue_type="missing_doc",
                            description=f"Function '{node.name}' has no docstring",
                            confidence=0.80,
                        ))
                    continue

                if not docstring:
                    continue

                # Stale params: documented but not in actual signature
                stale = doc_params - actual_params
                for param in stale:
                    issues.append(StaleDocIssue(
                        file=rel_path,
                        line=node.lineno,
                        function=node.name,
                        issue_type="stale_param",
                        description=f"Parameter '{param}' documented in '{node.name}' but not in actual signature",
                        confidence=0.90,
                    ))

                # Missing docs: actual params not documented (only for non-trivial functions)
                if actual_params and not node.name.startswith("_"):
                    undocumented = actual_params - doc_params
                    if undocumented and len(actual_params) > 1:
                        issues.append(StaleDocIssue(
                            file=rel_path,
                            line=node.lineno,
                            function=node.name,
                            issue_type="missing_doc",
                            description=f"Parameters undocumented in '{node.name}': {', '.join(sorted(undocumented))}",
                            confidence=0.75,
                        ))

                # Check return documentation
                has_return = any(
                    isinstance(child, (ast.Return, ast.Yield, ast.YieldFrom))
                    for child in ast.walk(node)
                )
                if has_return and docstring:
                    returns_doc = (
                        "@return" in docstring
                        or "@returns" in docstring
                        or "Returns:" in docstring
                        or ":return:" in docstring
                    )
                    if not returns_doc and node.name != "__init__":
                        issues.append(StaleDocIssue(
                            file=rel_path,
                            line=node.lineno,
                            function=node.name,
                            issue_type="missing_return_doc",
                            description=f"Function '{node.name}' has return statement(s) but no @return documented",
                            confidence=0.78,
                        ))

        return issues

    # ------------------------------------------------------------------
    # JS/TS: regex-based analysis
    # ------------------------------------------------------------------
    def _check_js_like_file(self, path: Path, rel_path: str) -> list[StaleDocIssue]:
        """Analyze JS/TS file for stale JSDoc issues using regex."""
        issues: list[StaleDocIssue] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return issues

        # Find function definitions with JSDoc comments
        # Pattern: /** ... */ then function name(...)
        func_pattern = re.compile(
            r'/\*\*\s*\n((?:[^*]|\*[^/])*)\*/\s*\n(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\('
        )
        arrow_pattern = re.compile(
            r'/\*\*\s*\n((?:[^*]|\*[^/])*)\*/\s*\n(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\s*)?\('
        )
        method_pattern = re.compile(
            r'/\*\*\s*\n((?:[^*]|\*[^/])*)\*/\s*\n\s*(\w+)\s*\(\s*[^)]*\)\s*\{'
        )

        for pattern, label in [(func_pattern, "function"), (arrow_pattern, "arrow"), (method_pattern, "method")]:
            for match in pattern.finditer(source):
                jsdoc = match.group(1)
                func_name = match.group(2) if label != "method" else match.group(2)
                if not func_name:
                    continue

                # Extract @param tags from JSDoc
                doc_params = set(PARAM_TAG_PATTERN.findall(jsdoc))

                # We can't easily get actual params from regex, so just flag stale @param names
                # that are misspelled or don't match common patterns
                # For JS/TS, we look for @param names that are very short or unusual
                for param in doc_params:
                    if len(param) <= 1:
                        issues.append(StaleDocIssue(
                            file=rel_path,
                            line=source[:match.start()].count("\n") + 1,
                            function=func_name,
                            issue_type="stale_param",
                            description=f"Suspicious @param '{param}' in JSDoc for '{func_name}' — very short name",
                            confidence=0.70,
                        ))
                    elif not re.match(r'^[a-z_]\w*$', param, re.IGNORECASE):
                        issues.append(StaleDocIssue(
                            file=rel_path,
                            line=source[:match.start()].count("\n") + 1,
                            function=func_name,
                            issue_type="stale_param",
                            description=f"Unusual @param '{param}' in JSDoc for '{func_name}'",
                            confidence=0.65,
                        ))

                # Check for @returns
                has_return_tag = bool(RETURN_TAG_PATTERN.search(jsdoc))
                if not has_return_tag and "function" in label:
                    # Estimate if function has return by checking for 'return' keyword
                    func_body_start = match.end()
                    func_body = source[func_body_start:func_body_start + 500]
                    if "return " in func_body and not has_return_tag:
                        issues.append(StaleDocIssue(
                            file=rel_path,
                            line=source[:match.start()].count("\n") + 1,
                            function=func_name,
                            issue_type="missing_return_doc",
                            description=f"Function '{func_name}' has 'return' but no @returns in JSDoc",
                            confidence=0.74,
                        ))

        return issues

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze_file(self, path: Path, rel_path: str) -> list[StaleDocIssue]:
        """Analyze a single file for stale documentation."""
        if path.suffix == ".py":
            return self._check_python_file(path, rel_path)
        elif path.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".mts", ".cjs", ".cts"):
            return self._check_js_like_file(path, rel_path)
        return []

    def analyze_batch(self, files: list[Any]) -> list[StaleDocIssue]:
        """Analyze all source files for stale documentation issues."""
        all_issues: list[StaleDocIssue] = []
        for f in files:
            if not getattr(f, "is_text", True):
                continue
            try:
                issues = self.analyze_file(f.path, str(getattr(f, "rel_path", f.path)))
                all_issues.extend(issues)
            except Exception:
                pass
        return all_issues
