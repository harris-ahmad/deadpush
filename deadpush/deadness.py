"""Multi-factor deadness scoring for dead code candidates.

Combines 6 independent signals into a single alive_score (0.0 = dead, 1.0 = alive).
False positives are weighted as worse than false negatives — when evidence is
ambiguous, the scorer abstains (tier = "uncertain").

New in Phase 3:
- Call-chain-aware deadness: propagates penalty through the call graph
- Test-aware deadness: symbols unreferenced in tests get lower confidence
- Composite signal: merges all 8 factors into one score
"""

from __future__ import annotations

import ast
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .config import Config
from .graph import CallGraph, Symbol
from .registration import RegistrationDetector
from .importgraph import ImportAnalyzer

# Module-level blame cache shared across scorer instances (TTL: 60s)
_GLOBAL_BLAME_CACHE: dict[str, tuple[float, dict[int, float]]] = {}

import time as _time


@dataclass
class DeadnessResult:
    """Result of multi-factor scoring for a single symbol."""
    alive_score: float
    tier: Literal["high", "medium", "low", "uncertain"]
    factors: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    uncertainty: str = ""


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
    """Score a single symbol using 8 independent factors.

    Factors (weight):
      in_degree (0.30)   — how many callers in the call graph
      registration (0.20) — framework registration patterns
      string_ref (0.10)  — name appears as string literal elsewhere
      import_count (0.10) — imported by other modules
      entry_point (0.05) — reachable from entry points
      git_freshness (0.05) — recently modified (git blame)
      call_chain (0.10)  — callers are live (propagated from call graph)
      test_coverage (0.10) — referenced in test files
    """

    WEIGHTS = {
        "in_degree": 0.30,
        "registration": 0.20,
        "string_ref": 0.10,
        "import_count": 0.10,
        "entry_point": 0.05,
        "git_freshness": 0.05,
        "call_chain": 0.10,
        "test_coverage": 0.10,
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
        test_file_paths: list[Path] | None = None,
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
        # Phase 3: call-chain propagation + test coverage
        self._call_chain_scores: dict[str, float] = {}
        self._test_file_refs: set[str] = self._build_test_refs(test_file_paths or [])
        self._git_history_checked = False
        self._git_history_has_commits = False

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

        f7 = self._factor_call_chain(sym)
        factors["call_chain"] = f7
        if f7 >= 0.8:
            reasons.append("Called by live symbols in call graph")
        elif f7 <= 0.2:
            reasons.append("All callers appear to be dead code")

        f8 = self._factor_test_coverage(sym)
        factors["test_coverage"] = f8
        if f8 >= 0.7:
            reasons.append("Referenced in test files")
        elif f8 <= 0.2:
            reasons.append("Not referenced in any test file")

        alive_score = sum(
            self.WEIGHTS[k] * factors[k]
            for k in self.WEIGHTS
        )

        tier = self.classify(alive_score)

        uncertainty_parts: list[str] = []
        if tier == "uncertain":
            uncertainty_parts.append(f"alive_score {alive_score:.3f} in uncertain range (>0.7)")
        rel = self._rel_path(sym.path)
        if rel not in self._blame_cache:
            uncertainty_parts.append("git blame data not available")
        if not self._test_file_refs:
            uncertainty_parts.append("no test files found for coverage analysis")

        return DeadnessResult(
            alive_score=round(alive_score, 3),
            tier=tier,
            factors=factors,
            reasons=reasons,
            uncertainty="; ".join(uncertainty_parts) if uncertainty_parts else "",
        )

    def _build_test_refs(self, test_file_paths: list[Path]) -> set[str]:
        """Pre-scan test files for symbol name references."""
        refs: set[str] = set()
        for fp in test_file_paths:
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            # Match import-like and string references
            for m in re.finditer(r"(?:import\s+(\w+)|from\s+(\w+)|['\"](\w+?)['\"])", text):
                for g in m.groups():
                    if g and len(g) > 1 and g.isidentifier():
                        refs.add(g)
            # Match function calls and attribute access
            tree = None
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if len(node.func.id) > 1:
                        refs.add(node.func.id)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if len(node.func.attr) > 1:
                        refs.add(node.func.attr)
                elif isinstance(node, ast.Name):
                    if isinstance(node.ctx, ast.Load) and len(node.id) > 1:
                        refs.add(node.id)
        return refs

    def _factor_test_coverage(self, sym: Symbol) -> float:
        """Score based on whether the symbol is referenced in test files."""
        name = sym.name.lower()
        if not self._test_file_refs:
            return 0.5  # neutral when no test files exist
        if name in self._test_file_refs or name in {r.lower() for r in self._test_file_refs}:
            return 0.9
        # Check registration detector string refs that came from test files
        if self.registration.score(sym.id) > 0:
            return 0.7
        return 0.2

    def compute_call_chain_scores(self, alive_scores: dict[str, float]) -> None:
        """Pass 2: propagate deadness through the call graph.

        For each symbol, compute what fraction of its callers are alive
        (alive_score > 0.2).  If all callers are dead, the symbol's
        call_chain factor drops accordingly.
        """
        for sym_id in alive_scores:
            incoming = self.graph.incoming(sym_id)
            if not incoming:
                self._call_chain_scores[sym_id] = 0.0
                continue
            live_callers = 0
            total_callers = 0
            seen: set[str] = set()
            for edge in incoming:
                caller = edge.src
                if caller in seen:
                    continue
                seen.add(caller)
                total_callers += 1
                caller_score = alive_scores.get(caller)
                if caller_score is None:
                    # Caller that wasn't scored (abstained) — treat as alive
                    live_callers += 1
                elif caller_score > 0.2:
                    live_callers += 1
            self._call_chain_scores[sym_id] = live_callers / total_callers if total_callers else 0.0

    def _factor_call_chain(self, sym: Symbol) -> float:
        """Score based on whether callers are live (post-propagation)."""
        return self._call_chain_scores.get(sym.id, 0.0)

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

    def _has_git_history(self) -> bool:
        """Check if the repo has any commits (avoids FP for new repos)."""
        if self._git_history_checked:
            return self._git_history_has_commits
        self._git_history_checked = True
        try:
            result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                capture_output=True, text=True, check=False, timeout=5,
                cwd=self.repo_root,
            )
            self._git_history_has_commits = result.returncode == 0 and int(result.stdout.strip()) > 0
        except Exception:
            self._git_history_has_commits = False
        return self._git_history_has_commits

    def _factor_git_freshness(self, sym: Symbol) -> float:
        """Score based on git blame (when was the symbol last modified)."""
        if not self._has_git_history():
            return 0.5  # neutral — no git history to judge freshness
        rel = self._rel_path(sym.path)
        try:
            file_path = self.repo_root / rel
            if not file_path.exists():
                return 0.0

            if rel not in self._blame_cache:
                # Check global cache before blaming
                global _GLOBAL_BLAME_CACHE
                now = _time.time()
                if rel in _GLOBAL_BLAME_CACHE:
                    ts, data = _GLOBAL_BLAME_CACHE[rel]
                    if now - ts < 60:
                        self._blame_cache[rel] = data
                    else:
                        del _GLOBAL_BLAME_CACHE[rel]
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

    def prefetch_blame_data(self, max_workers: int = 10) -> None:
        """Pre-fetch git blame data for all source files in parallel."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        files_to_blame = []
        for f in self.all_file_paths:
            rel = self._rel_path(str(f))
            if rel not in self._blame_cache:
                files_to_blame.append(f)
        if not files_to_blame:
            return
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {pool.submit(self._blame_file, f): f for f in files_to_blame}
            for future in as_completed(future_map):
                f = future_map[future]
                rel = self._rel_path(str(f))
                try:
                    self._blame_cache[rel] = future.result()
                except Exception:
                    pass

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
                elif line.startswith("\t"):
                    current_line += 1
                elif line.startswith("boundary"):
                    pass
            # Seed global cache
            global _GLOBAL_BLAME_CACHE
            _GLOBAL_BLAME_CACHE[self._rel_path(str(file_path))] = (_time.time(), line_dates)
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

    def classify(self, score: float) -> Literal["high", "medium", "low", "uncertain"]:
        if score <= 0.2:
            return "high"
        if score <= 0.4:
            return "medium"
        if score <= 0.7:
            return "low"
        return "uncertain"
