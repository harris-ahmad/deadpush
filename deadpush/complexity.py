"""
Complexity Gate — tracks cyclomatic complexity per file and alerts on spikes.

Vibe coding sessions can silently balloon complexity as AI agents add features
without considering maintainability. This module computes McCabe cyclomatic
complexity per file, caches a baseline, and warns when complexity increases
beyond a threshold (default: 20%).
"""

from __future__ import annotations

import ast
import json
import math
import re
import time
from pathlib import Path
from typing import Any


COMPLEXITY_CACHE_FILE = Path.home() / ".deadpush" / "complexity_cache.json"
COMPLEXITY_CACHE_MAX_AGE = 604800  # 1 week
DEFAULT_THRESHOLD_PCT = 20


# ---------------------------------------------------------------------------
# Cyclomatic Complexity Calculators
# ---------------------------------------------------------------------------

def _compute_python_complexity(source: str) -> int:
    """Compute McCabe cyclomatic complexity for Python source using AST."""
    complexity = 1  # base
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0

    for node in ast.walk(tree):
        # Decision points
        if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.With, ast.AsyncWith)):
            complexity += 1
        elif isinstance(node, ast.ExceptHandler):
            complexity += 1
        elif isinstance(node, ast.Assert):
            complexity += 1
        # Boolean operators increase paths
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        # ternary / if-expressions
        elif isinstance(node, ast.IfExp):
            complexity += 1
        # match/case (Python 3.10+)
        elif isinstance(node, ast.Match):
            complexity += len(node.cases)
        # comprehensions
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            complexity += len(node.generators)

    return complexity


def _compute_js_like_complexity(source: str) -> int:
    """Compute approximate complexity for JS/TS using regex pattern counting."""
    complexity = 1
    patterns = [
        r'\bif\s*\(', r'\belse\s+if\b', r'\belse\b',
        r'\bfor\s*\(', r'\bwhile\s*\(', r'\bdo\s*\{',
        r'\bswitch\s*\(', r'\bcase\s+',
        r'\bcatch\s*\(', r'\bfinally\b',
        r'\b&&\b', r'\b\|\|\b',
        r'\?.*:.*',
    ]
    for p in patterns:
        complexity += len(re.findall(p, source))
    return complexity


def _compute_go_complexity(source: str) -> int:
    complexity = 1
    patterns = [
        r'\bif\b', r'\belse\b', r'\bfor\b', r'\brange\b',
        r'\bswitch\b', r'\bcase\b', r'\bselect\b',
    ]
    for p in patterns:
        complexity += len(re.findall(p, source))
    return complexity


def _compute_rust_complexity(source: str) -> int:
    complexity = 1
    patterns = [
        r'\bif\b', r'\belse\b', r'\bfor\b', r'\bwhile\b',
        r'\bmatch\b', r'=>', r'\bif let\b', r'\bwhile let\b',
    ]
    for p in patterns:
        complexity += len(re.findall(p, source))
    return complexity


def _compute_cpp_complexity(source: str) -> int:
    complexity = 1
    patterns = [
        r'\bif\s*\(', r'\belse\b', r'\bfor\s*\(', r'\bwhile\s*\(',
        r'\bswitch\s*\(', r'\bcase\b', r'\bcatch\s*\(',
        r'\b&&\b', r'\b\|\|\b', r'\?',
    ]
    for p in patterns:
        complexity += len(re.findall(p, source))
    return complexity


def _compute_java_complexity(source: str) -> int:
    complexity = 1
    patterns = [
        r'\bif\s*\(', r'\belse\b', r'\bfor\s*\(', r'\bwhile\s*\(',
        r'\bdo\s*\{', r'\bswitch\s*\(', r'\bcase\b',
        r'\bcatch\s*\(', r'\bfinally\b', r'\b&&\b', r'\b\|\|\b',
        r'\?', r'\binstanceof\b',
    ]
    for p in patterns:
        complexity += len(re.findall(p, source))
    return complexity


_COMPLEXITY_FUNCS: dict[str, Any] = {
    ".py": _compute_python_complexity,
    ".js": _compute_js_like_complexity,
    ".jsx": _compute_js_like_complexity,
    ".mjs": _compute_js_like_complexity,
    ".cjs": _compute_js_like_complexity,
    ".ts": _compute_js_like_complexity,
    ".tsx": _compute_js_like_complexity,
    ".mts": _compute_js_like_complexity,
    ".cts": _compute_js_like_complexity,
    ".go": _compute_go_complexity,
    ".rs": _compute_rust_complexity,
    ".c": _compute_cpp_complexity,
    ".cpp": _compute_cpp_complexity,
    ".cc": _compute_cpp_complexity,
    ".cxx": _compute_cpp_complexity,
    ".h": _compute_cpp_complexity,
    ".hpp": _compute_cpp_complexity,
    ".java": _compute_java_complexity,
    ".kt": _compute_java_complexity,
}


def compute_complexity(path: Path) -> int | None:
    """Compute cyclomatic complexity for a source file. Returns None on failure."""
    suffix = path.suffix.lower()
    func = _COMPLEXITY_FUNCS.get(suffix)
    if func is None:
        return None
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        return func(source)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Complexity Tracker
# ---------------------------------------------------------------------------

class ComplexityTracker:
    """Tracks complexity baseline per file and detects significant increases."""

    def __init__(self, threshold_pct: int = DEFAULT_THRESHOLD_PCT):
        self.threshold_pct = threshold_pct
        self.cache_file = COMPLEXITY_CACHE_FILE
        self._cache: dict[str, dict[str, Any]] = {}
        self._load_cache()

    def _load_cache(self):
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                now = time.time()
                self._cache = {
                    k: v for k, v in data.items()
                    if now - v.get("baseline_at", 0) < COMPLEXITY_CACHE_MAX_AGE
                }
            except Exception:
                self._cache = {}

    def _save_cache(self):
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(
                json.dumps(self._cache, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

    def get_baseline(self, file_path: str) -> int | None:
        """Get cached baseline complexity for a file."""
        entry = self._cache.get(file_path)
        if entry:
            return entry.get("complexity")
        return None

    def check_complexity(self, file_path: str, path: Path) -> dict[str, Any] | None:
        """Check file complexity against baseline. Returns alert dict if threshold exceeded."""
        current = compute_complexity(path)
        if current is None:
            return None

        baseline = self.get_baseline(file_path)

        if baseline is not None and baseline > 0:
            increase = current - baseline
            pct_increase = (increase / baseline) * 100
            increase_ratio = current / baseline

            if pct_increase >= self.threshold_pct:
                return {
                    "file": file_path,
                    "baseline": baseline,
                    "current": current,
                    "increase": increase,
                    "pct_increase": round(pct_increase, 1),
                    "threshold_pct": self.threshold_pct,
                    "exceeded": True,
                }
        else:
            # First time seeing this file — set baseline
            self._cache[file_path] = {
                "complexity": current,
                "baseline_at": time.time(),
            }
            self._save_cache()

            if current > 30:
                return {
                    "file": file_path,
                    "baseline": None,
                    "current": current,
                    "increase": None,
                    "pct_increase": None,
                    "threshold_pct": self.threshold_pct,
                    "exceeded": False,
                    "note": f"Initial complexity is high ({current}). Consider refactoring.",
                }

        return None

    def update_baseline(self, file_path: str, complexity: int):
        """Update baseline after confirming the change is intentional."""
        self._cache[file_path] = {
            "complexity": complexity,
            "baseline_at": time.time(),
        }
        self._save_cache()
