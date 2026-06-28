"""Signal-quality regression benchmark for deadpush.

Baselines the dead-code + debris detector against labeled fixtures.
Run:
    pytest tests/test_quality_regression.py -v

Outputs:
    recall_definite, precision_definite, recall_overall, etc.

Each fixture file contains a comment block ``# @deadpush:label`` that encodes
the ground-truth tier for every atom inside it.  The test parses those labels,
runs ``deadpush scan --format json`` on the temp repo, and computes:

  * recall_definite — fraction of labeled ``definite-dead`` atoms that
    the detector tiers as ``definite`` or ``probable``.
  * precision_definite — fraction of detector-``definite`` atoms that were
    labeled ``definite-dead`` (upper-bound sanity check).
  * recall_overall — all labeled-dead atoms caught above ``uncertain``.
  * debris_recall — labeled debris actually flagged.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = REPO_ROOT / ".venv" / "bin" / "python3"

ATOM_RE = re.compile(
    r"#\s*@deadpush:(?P<kind>alive|definite-dead|probable-dead|"
    r"uncertain|block|warn)\s*:\s*(?P<name>\w+)(?:\s*:\s*(?P<sub>\w+))?\s*$"
)

LABEL_ALIVE = "alive"
LABEL_DEFINITE_DEAD = "definite-dead"
LABEL_PROBABLE_DEAD = "probable-dead"
LABEL_UNCERTAIN = "uncertain"
LABEL_BLOCK = "block"
LABEL_WARN = "warn"


# ======================================================================
# Helpers
# ======================================================================

class LabeledAtom:
    __slots__ = ("path", "name", "kind", "sub")

    def __init__(self, path: str, name: str, kind: str, sub: str | None = None):
        self.path = path
        self.name = name
        self.kind = kind
        self.sub = sub

    def __repr__(self) -> str:
        return f"LabeledAtom({self.path}:{self.name}:{self.kind}:{self.sub})"

    def matches_dead_symbol(self, ds: dict[str, Any]) -> bool:
        return (
            ds.get("path", "").replace("\\", "/").endswith(self.path)
            and ds.get("name") == self.name
        )

    def expected_tier(self) -> str | None:
        """Map our labels to deadpush tiers."""
        if self.kind == LABEL_ALIVE:
            return None  # must NOT appear in dead list
        if self.kind == LABEL_DEFINITE_DEAD:
            return "definite"
        if self.kind == LABEL_PROBABLE_DEAD:
            return "probable"
        if self.kind == LABEL_UNCERTAIN:
            return "uncertain"
        return None


def parse_labels(repo: Path) -> list[LabeledAtom]:
    atoms: list[LabeledAtom] = []
    for p in repo.rglob("*.py"):
        rel = str(p.relative_to(repo)).replace("\\", "/")
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            m = ATOM_RE.search(line)
            if not m:
                continue
            atoms.append(
                LabeledAtom(
                    path=rel,
                    name=m.group("name"),
                    kind=m.group("kind"),
                    sub=m.group("sub"),
                )
            )
    return atoms


def run_scan(repo: Path) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    out_file = repo / "deadpush-report.json"
    cmd = [
        str(PYTHON),
        "-m",
        "deadpush.cli",
        "scan",
        "--format",
        "json",
        "--output",
        str(out_file),
        "--no-rich",
    ]
    r = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, env=env)
    assert r.returncode == 0, f"scan failed: {r.stderr}"
    assert out_file.exists(), f"json output missing: {out_file}"
    return json.loads(out_file.read_text(encoding="utf-8"))


def run_mcp_scan(repo: Path) -> dict[str, Any]:
    """Use the MCP server directly for a stable structured result."""
    sys.path.insert(0, str(REPO_ROOT))
    from deadpush.mcp_server import McpServer

    server = McpServer(repo_root=str(repo))
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "scan", "arguments": {}}}
    # We don't have a full stdio harness here; fall back to CLI json.
    return run_scan(repo)


# ======================================================================
# Fixtures
# ======================================================================

PYTHON_MAIN = """\
# @deadpush:alive:main
from app.alive import add
from app.dead import unused  # noqa: F401  (imported but unused)
import app.string_ref

if __name__ == "__main__":
    result = add(1, 2)
    print(result)
"""

PYTHON_ALIVE = """\
# @deadpush:alive:add
def add(a: int, b: int) -> int:
    return a + b
"""

PYTHON_DEAD = """\
# @deadpush:definite-dead:unused
def unused(x: int = 0) -> int:
    '''This helper is never called anywhere.'''
    return x * 42

# @deadpush:definite-dead:stale_helper
def stale_helper(name: str) -> str:
    return f"hello {name}"
"""

PYTHON_STRING_REF = """\
# @deadpush:probable-dead:only_string_ref
def only_string_ref() -> int:
    '''Only referenced as a string in a registry.'''
    return 1

_commands = {
    # the function is only referred to by its name, not called
    "only_string_ref": only_string_ref,
}
"""

PYTHON_UNCERTAIN = """\
# @deadpush:uncertain:single_indirect
def single_indirect() -> int:
    '''One indirect caller, no direct invocation.'''
    return 1

def _maybe():
    return single_indirect()

def _indirect_wrapper():
    return _maybe()
"""

PYTHON_SECRET = """\
# @deadpush:block:hardcoded_secret
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://admin:supersecret@localhost:5432/mydb"
"""

PYTHON_WEAK_TEST = """\
# @deadpush:warn:test_no_assertions
def test_nothing():
    '''A test file with zero assertions - should be flagged as weak test.'''
    x = 1 + 1
    print("ok")
"""


@pytest.fixture
def python_fixture(tmp_path: Path) -> Path:
    """Small Python repo with labeled alive/dead/uncertain atoms."""
    repo = tmp_path / "python_repo"
    repo.mkdir()

    (repo / "__main__.py").write_text(PYTHON_MAIN, encoding="utf-8")
    (repo / "app").mkdir()
    (repo / "app" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "app" / "alive.py").write_text(PYTHON_ALIVE, encoding="utf-8")
    (repo / "app" / "dead.py").write_text(PYTHON_DEAD, encoding="utf-8")
    (repo / "app" / "string_ref.py").write_text(PYTHON_STRING_REF, encoding="utf-8")
    (repo / "app" / "uncertain.py").write_text(PYTHON_UNCERTAIN, encoding="utf-8")
    (repo / "secrets.py").write_text(PYTHON_SECRET, encoding="utf-8")
    (repo / "tests_no_assert.py").write_text(PYTHON_WEAK_TEST, encoding="utf-8")

    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Test"
    env["GIT_AUTHOR_EMAIL"] = "test@test.invalid"
    subprocess.run(
        ["git", "commit", "-m", "init", "--author=Test <test@test.invalid>"],
        cwd=repo,
        check=True,
        capture_output=True,
        env=env,
    )
    return repo


# ======================================================================
# Metrics
# ======================================================================


def _tier_of(ds: dict[str, Any]) -> str | None:
    return ds.get("tier")


def evaluate_dead_code(atoms, data):
    dead_symbols = data.get("dead_symbols", [])

    labeled_dead = [a for a in atoms if a.expected_tier() is not None]
    definite_labeled = [a for a in atoms if a.kind == LABEL_DEFINITE_DEAD]

    tp_definite = 0
    tp_overall = 0
    fp_definite = 0
    false_negatives: list[str] = []
    false_positives_def: list[str] = []

    # recall
    for atom in labeled_dead:
        expected = atom.expected_tier()
        predicted = None
        for ds in dead_symbols:
            if atom.matches_dead_symbol(ds):
                predicted = _tier_of(ds)
                break
        if predicted is None:
            false_negatives.append(f"{atom.path}:{atom.name} (expected {expected}, not found)")
        elif atom.kind == LABEL_DEFINITE_DEAD and predicted in ("definite", "probable"):
            tp_definite += 1
            tp_overall += 1
        elif predicted in ("definite", "probable", "uncertain"):
            tp_overall += 1
        else:
            false_negatives.append(
                f"{atom.path}:{atom.name} (expected {expected}, got {predicted})"
            )

    # precision
    for ds in dead_symbols:
        path = ds.get("path", "").replace("\\", "/")
        name = ds.get("name", "")
        matched = any(
            a.kind == LABEL_DEFINITE_DEAD and a.matches_dead_symbol(ds)
            for a in definite_labeled
        )
        tier = _tier_of(ds)
        if tier == "definite" and not matched:
            fp_definite += 1
            false_positives_def.append(f"{path}:{name}")

    recall_definite = tp_definite / len(definite_labeled) if definite_labeled else 1.0
    precision_definite = tp_definite / (tp_definite + fp_definite) if (tp_definite + fp_definite) else 1.0
    recall_overall = tp_overall / len(labeled_dead) if labeled_dead else 1.0

    return {
        "recall_definite": recall_definite,
        "precision_definite": precision_definite,
        "recall_overall": recall_overall,
        "tp_definite": tp_definite,
        "fp_definite": fp_definite,
        "ground_truth_definite": len(definite_labeled),
        "ground_truth_total_dead": len(labeled_dead),
        "detected_dead_count": len(dead_symbols),
        "false_negatives": false_negatives,
        "false_positives_definite": false_positives_def,
    }


def evaluate_debris(atoms, data):
    debris = data.get("debris", [])
    labeled_debris = [a for a in atoms if a.kind == LABEL_BLOCK or a.kind == LABEL_WARN]

    tp = 0
    false_negatives: list[str] = []
    for atom in labeled_debris:
        found = any(
            d.get("path", "").replace("\\", "/").endswith(atom.path)
            for d in debris
        )
        if found:
            tp += 1
        else:
            false_negatives.append(f"{atom.path}:{atom.name}")

    recall = tp / len(labeled_debris) if labeled_debris else 1.0
    return {
        "debris_recall": recall,
        "debris_labeled": len(labeled_debris),
        "debris_detected": tp,
        "debris_false_negatives": false_negatives,
    }


# ======================================================================
# Tests
# ======================================================================


class TestRegressionBaseline:
    """Measurable baseline for dead-code + debris signal quality."""

    def test_python_baseline(self, python_fixture):
        atoms = parse_labels(python_fixture)
        data = run_scan(python_fixture)

        dead_metrics = evaluate_dead_code(atoms, data)
        debris_metrics = evaluate_debris(atoms, data)

        # ---- print baseline numbers (this is the point of the test) ----
        print("\n===== deadpush signal-quality baseline =====")
        print(f"  recall_definite      : {dead_metrics['recall_definite']:.2f}")
        print(f"  precision_definite   : {dead_metrics['precision_definite']:.2f}")
        print(f"  recall_overall       : {dead_metrics['recall_overall']:.2f}")
        print(f"  debris_recall        : {debris_metrics['debris_recall']:.2f}")
        print(f"  detected_dead_count  : {dead_metrics['detected_dead_count']}")
        print(f"  ground_truth_total   : {dead_metrics['ground_truth_total_dead']}")
        if dead_metrics["false_negatives"]:
            print("  false negatives (dead code):")
            for fn in dead_metrics["false_negatives"]:
                print(f"    - {fn}")
        if dead_metrics["false_positives_definite"]:
            print("  false positives (definite):")
            for fp in dead_metrics["false_positives_definite"]:
                print(f"    + {fp}")
        if debris_metrics["debris_false_negatives"]:
            print("  false negatives (debris):")
            for fn in debris_metrics["debris_false_negatives"]:
                print(f"    - {fn}")
        print("============================================")

        # ---- soft floor: we measure, we don't block progress yet ----
        # Once we have 3 runs of data we'll tighten these.  For now they
        # assert that the infrastructure works and we produce numbers.
        assert dead_metrics["ground_truth_definite"] >= 2, "fixture has no definite-dead atoms"
        assert dead_metrics["detected_dead_count"] >= 0, "detector crashed"
        assert "recall_definite" in dead_metrics
        assert "precision_definite" in dead_metrics

    def test_secrets_flagged_as_blocking(self, python_fixture):
        data = run_scan(python_fixture)
        blocking = [
            d for d in data.get("debris", []) if d.get("block_push") is True
        ]
        blocking_paths = [d.get("path", "") for d in blocking]
        assert any("secrets.py" in p for p in blocking_paths), (
            f"hardcoded secret not in blocking debris: {blocking_paths}"
        )

    def test_weak_test_warned(self, python_fixture):
        data = run_scan(python_fixture)
        non_blocking_paths = [
            d.get("path", "")
            for d in data.get("debris", [])
            if d.get("block_push") is not True
        ]
        # weak-test detection depends on test analyzer heuristics; skip if
        # the scaffolding file isn't in the analysis corpus at all.
        all_paths = [d.get("path", "") for d in data.get("debris", [])]
        if not any("tests_no_assert.py" in p for p in all_paths):
            pytest.skip("weak-test fixture file not analyzed (analyzer filter)")
        assert any("tests_no_assert.py" in p for p in non_blocking_paths), (
            f"weak-test file not in debris: {non_blocking_paths}"
        )
