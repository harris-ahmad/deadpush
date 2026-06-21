"""Multi-factor deadness scoring for dead code candidates.

Combines 6 independent signals into a single alive_score (0.0 = dead, 1.0 = alive).
False positives are weighted as worse than false negatives — when evidence is
ambiguous, the scorer abstains (tier = "uncertain").
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .config import Config
from .graph import CallGraph, Symbol
from .registration import RegistrationDetector
from .importgraph import ImportAnalyzer


@dataclass
class DeadnessResult:
    """Result of multi-factor scoring for a single symbol."""
    alive_score: float
    tier: Literal["high", "medium", "low", "uncertain"]
    factors: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


ABSTAIN_NAMES: set[str] = {
    "__init__", "__repr__", "__str__", "__len__", "__call__",
    "__enter__", "__exit__", "__iter__", "__next__", "__getitem__",
    "__setitem__", "__delitem__", "__contains__", "__bool__",
    "__hash__", "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__",
    "__add__", "__sub__", "__mul__", "__truediv__", "__floordiv__",
    "__del__", "__new__", "__delattr__", "__getattr__", "__setattr__",
    "__getattribute__", "__format__", "__reduce__", "__reduce_ex__",
    "__sizeof__", "__subclasshook__", "__init_subclass__",
    "__class_getitem__", "__instancecheck__", "__subclasscheck__",
    "__aenter__", "__aexit__", "__aiter__", "__anext__",
    "__await__", "__aenter__", "__aexit__",
}

KNOWN_HANDLER_CLASSES: set[str] = {
    "FileSystemEventHandler",
    "BaseHTTPRequestHandler",
    "StreamRequestHandler",
    "SimpleHTTPRequestHandler",
    "threading.Thread",
    "ABC",
    "Protocol",
}


def _should_abstain(sym: Symbol, reg: RegistrationDetector) -> bool:
    """Return True if this symbol should never be flagged as dead."""
    name = sym.name
    if name in ABSTAIN_NAMES:
        return True
    if name.startswith("__") and name.endswith("__"):
        return True
    if reg.is_registered(sym.id):
        return True
    return False


class MultiFactorDeadnessScorer:
    """Score a single symbol using 6 independent factors."""

    WEIGHTS = {
        "in_degree": 0.35,
        "registration": 0.25,
        "string_ref": 0.15,
        "import_count": 0.15,
        "entry_point": 0.05,
        "git_freshness": 0.05,
    }

    def __init__(
        self,
        config: Config,
        repo_root: Path,
        graph: CallGraph,
        registration: RegistrationDetector,
        imports: ImportAnalyzer,
        roots: set[str],
        all_file_paths: list[Path],
    ):
        self.config = config
        self.repo_root = repo_root
        self.graph = graph
        self.registration = registration
        self.imports = imports
        self.roots = roots
        self.all_file_paths = all_file_paths
        self._blame_cache: dict[str, dict[int, float]] = {}
        self._log_cache: dict[str, tuple[float, float]] = {}

    def score(self, sym: Symbol) -> DeadnessResult | None:
        """Score a single symbol. Returns None if abstention applies."""
        if _should_abstain(sym, self.registration):
            return None

        factors: dict[str, float] = {}
        reasons: list[str] = []

        f1 = self._factor_in_degree(sym)
        factors["in_degree"] = f1
        if f1 >= 0.8:
            reasons.append("Has multiple callers in the call graph")
        elif f1 <= 0.2:
            reasons.append("No callers in the call graph")

        f2 = self.registration.score(sym.id)
        factors["registration"] = f2
        if f2 >= 0.8:
            reasons.append("Registered via decorator or framework pattern")
        elif f2 >= 0.4:
            reasons.append("Appears in a registration context (dict/list/decorator)")

        f3 = self._factor_string_ref(sym)
        factors["string_ref"] = f3
        if f3 >= 0.5:
            reasons.append("Name referenced as string literal elsewhere")

        f4 = self._factor_import_count(sym)
        factors["import_count"] = f4
        if f4 >= 0.7:
            reasons.append("Imported by other modules")
        elif f4 <= 0.2:
            reasons.append("Not imported by any other module")

        f5 = self._factor_entry_point(sym)
        factors["entry_point"] = f5
        if f5 >= 0.8:
            reasons.append("Reachable from a detected entry point")

        f6 = self._factor_git_freshness(sym)
        factors["git_freshness"] = f6
        if f6 >= 0.7:
            reasons.append("Recently modified")
        elif f6 <= 0.2:
            reasons.append("Not modified recently or never")

        alive_score = sum(
            self.WEIGHTS[k] * factors[k]
            for k in self.WEIGHTS
        )

        tier = self._classify(alive_score)

        return DeadnessResult(
            alive_score=round(alive_score, 3),
            tier=tier,
            factors=factors,
            reasons=reasons,
        )

    def _factor_in_degree(self, sym: Symbol) -> float:
        """Score based on how many callers this symbol has in the call graph."""
        incoming = self.graph.incoming(sym.id)
        count = len(incoming)
        if count == 0:
            return 0.0
        if count == 1:
            return 0.3
        if count <= 3:
            return 0.6
        return 0.9

    def _factor_string_ref(self, sym: Symbol) -> float:
        """Score based on whether the symbol's name appears as a string literal."""
        count = self.imports.count_string_references(sym.name, sym.path)
        if count == 0:
            return 0.0
        if count <= 2:
            return 0.3
        if count <= 5:
            return 0.6
        return 0.8

    def _factor_import_count(self, sym: Symbol) -> float:
        """Score based on how many files import this symbol."""
        count = self.imports.count_external_imports(sym.name, sym.path)
        if count == 0:
            return 0.0
        if count == 1:
            return 0.4
        if count <= 3:
            return 0.7
        return 1.0

    def _factor_entry_point(self, sym: Symbol) -> float:
        """Score based on entry point reachability."""
        if sym.id in self.roots:
            return 1.0
        if sym.is_entry_point:
            return 0.9
        if self.registration.is_entry_point_file(sym.path):
            return 0.5
        return 0.0

    def _factor_git_freshness(self, sym: Symbol) -> float:
        """Score based on git blame (when was the symbol last modified)."""
        rel = self._rel_path(sym.path)
        try:
            file_path = self.repo_root / rel
            if not file_path.exists():
                return 0.0

            if rel not in self._blame_cache:
                self._blame_cache[rel] = self._blame_file(file_path)

            cache = self._blame_cache[rel]
            if not cache:
                return self._factor_git_log_fallback(sym.name, rel)

            age_days = cache.get(sym.line)
            if age_days is None:
                return 0.0
            if age_days < 7:
                return 0.9
            if age_days < 30:
                return 0.7
            if age_days < 90:
                return 0.5
            if age_days < 365:
                return 0.3
            return 0.0
        except Exception:
            return self._factor_git_log_fallback(sym.name, rel)

    def _blame_file(self, file_path: Path) -> dict[int, float]:
        """Run git blame on a file and return {line_number: age_days}."""
        try:
            result = subprocess.run(
                ["git", "blame", "--porcelain", str(file_path)],
                capture_output=True, text=True, check=False, timeout=10,
                cwd=self.repo_root,
            )
            if result.returncode != 0:
                return {}
            now = time.time()
            line_dates: dict[int, float] = {}
            current_line = 1
            for line in result.stdout.splitlines():
                if line.startswith("author-time "):
                    commit_time = int(line.split()[1])
                    age_days = (now - commit_time) / 86400
                    line_dates[current_line] = age_days
                    current_line += 1
                elif line.startswith("\t"):
                    current_line += 1
                elif line.startswith("boundary"):
                    pass
            return line_dates
        except Exception:
            return {}

    def _factor_git_log_fallback(self, name: str, rel: str) -> float:
        """Fallback: use git log -S to count recent mentions."""
        key = (name, rel)
        if key in self._log_cache:
            return self._log_cache[key][0]
        try:
            result = subprocess.run(
                ["git", "log", "-S", name, "--oneline", "-20", "--", rel],
                capture_output=True, text=True, check=False, timeout=10,
                cwd=self.repo_root,
            )
            if result.returncode == 0 and result.stdout.strip():
                count = len(result.stdout.splitlines())
                score = min(0.7, 0.1 + count * 0.03)
                self._log_cache[key] = (score, 0.0)
                return score
        except Exception:
            pass
        self._log_cache[key] = (0.0, 0.0)
        return 0.0

    def _rel_path(self, abs_path: str) -> str:
        try:
            return str(Path(abs_path).relative_to(self.repo_root))
        except ValueError:
            return abs_path

    def _classify(self, score: float) -> Literal["high", "medium", "low", "uncertain"]:
        if score <= 0.2:
            return "high"
        if score <= 0.4:
            return "medium"
        if score <= 0.7:
            return "low"
        return "uncertain"
