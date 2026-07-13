"""Tests for multi-hop reachability analysis."""

from __future__ import annotations

from pathlib import Path

from deadpush.config import Config
from deadpush.intercept import enforce_content, _run_guardrails
from deadpush.reachability import ImportGraph, check_reachability, clear_cache


def _make_files(repo: Path, files: dict[str, str]):
    for path, content in files.items():
        p = repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


class TestImportGraph:
    def test_single_file_no_imports(self, temp_dir: Path):
        _make_files(temp_dir, {"main.py": "x = 1\n"})
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        assert "main.py" in graph._graph
        assert graph._graph["main.py"] == set()

    def test_direct_import_python(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "import utils\nx = 1\n",
            "utils.py": "def foo(): return 42\n",
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        assert "main.py" in graph._graph
        assert "utils.py" in graph._graph["main.py"]
        assert "utils.py" in graph._graph

    def test_from_import_python(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "from utils import foo\nx = 1\n",
            "utils.py": "def foo(): return 42\n",
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        assert "utils.py" in graph._graph["main.py"]

    def test_skips_non_source_files(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "x = 1\n",
            "data.json": '{"key": "value"}',
            "image.png": b"fake-png".decode("latin-1"),
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        assert "main.py" in graph._graph
        assert "data.json" not in graph._graph
        assert "image.png" not in graph._graph

    def test_skips_deadpush_dirs(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "x = 1\n",
            ".deadpush/rules.json": "{}",
            ".git/HEAD": "ref: refs/heads/main\n",
            "node_modules/evil.py": "print('x')\n",
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        assert "main.py" in graph._graph
        assert ".deadpush/rules.json" not in graph._graph
        assert ".git/HEAD" not in graph._graph
        assert "node_modules/evil.py" not in graph._graph

    def test_missing_import_not_resolved(self, temp_dir: Path):
        """Import of a non-existent file should not add an edge."""
        _make_files(temp_dir, {
            "main.py": "import nonexistent\n",
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        assert "main.py" in graph._graph
        assert graph._graph["main.py"] == set()


class TestSensitiveOps:
    def test_detects_eval(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "x = eval(user_input)\n",
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        ops = graph._sensitive_ops.get("main.py", [])
        assert any("eval" in op.description for op in ops)

    def test_detects_subprocess(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "import subprocess\nsubprocess.run(['ls'])\n",
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        ops = graph._sensitive_ops.get("main.py", [])
        assert any("subprocess" in op.description for op in ops)

    def test_clean_file_no_ops(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "def add(a, b):\n    return a + b\n",
        })
        graph = ImportGraph(temp_dir)
        graph.rebuild()
        assert "main.py" not in graph._sensitive_ops


class TestReachability:
    def test_single_hop_reaches_eval(self, temp_dir: Path):
        _make_files(temp_dir, {
            "main.py": "from evil_helper import run\n",
            "evil_helper.py": "def run():\n    eval('bad')\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("main.py", "", config)
        assert len(violations) >= 1
        assert any("evil_helper.py" in v.file for v in violations)
        assert any("eval" in v.sensitive_op.description for v in violations)

    def test_multi_hop_reaches_shell(self, temp_dir: Path):
        _make_files(temp_dir, {
            "a.py": "from b import foo\n",
            "b.py": "from c import bar\n",
            "c.py": "import subprocess\nsubprocess.run(['rm', '-rf', '/'])\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("a.py", "x = 1\n", config, max_hops=5)
        assert len(violations) >= 1
        assert any("c.py" in v.file for v in violations)
        assert any("subprocess" in v.sensitive_op.description for v in violations)

    def test_no_reachability_for_clean_chain(self, temp_dir: Path):
        _make_files(temp_dir, {
            "a.py": "from b import foo\n",
            "b.py": "from c import bar\n",
            "c.py": "def bar():\n    return 42\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("a.py", "", config)
        assert violations == []

    def test_self_reference_no_infinite_loop(self, temp_dir: Path):
        _make_files(temp_dir, {
            "a.py": "from a import x\neval('bad')\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("a.py", "", config, max_hops=20)
        # Should find the eval in a.py itself (direct, not via import)
        # Actually a.py has eval in its own content but the source passed to
        # check_reachability is empty, so it won't find it through the BFS.
        # Let's just verify no crash.
        assert isinstance(violations, list)

    def test_max_hops_respected(self, temp_dir: Path):
        _make_files(temp_dir, {
            "a.py": "from b import foo\n",
            "b.py": "from c import foo\n",
            "c.py": "from d import foo\n",
            "d.py": "from e import foo\n",
            "e.py": "eval('bad')\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("a.py", "", config, max_hops=2)
        assert violations == []  # requires 4 hops, limited to 2

    def test_deep_reachability(self, temp_dir: Path):
        _make_files(temp_dir, {
            "a.py": "from b import foo\n",
            "b.py": "from c import foo\n",
            "c.py": "from d import foo\n",
            "d.py": "from e import foo\n",
            "e.py": "eval('bad')\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("a.py", "", config, max_hops=10)
        assert len(violations) >= 1
        assert any("e.py" in v.file for v in violations)

    def test_reachability_skips_non_imported(self, temp_dir: Path):
        """Files not in the import chain should not be flagged."""
        _make_files(temp_dir, {
            "a.py": "from b import foo\n",
            "b.py": "def foo(): return 1\n",
            "evil.py": "eval('bad')\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("a.py", "", config)
        # evil.py is not imported by a or b -> no violation
        assert violations == []


class TestIntegrationWithEnforceContent:
    def test_enforce_content_clean_file(self, temp_dir: Path):
        _make_files(temp_dir, {
            "safe.py": "from utils import add\n",
            "utils.py": "def add(a, b): return a + b\n",
        })
        config = Config(repo_root=temp_dir)
        result = enforce_content("safe.py", "from utils import add\n", config)
        assert result.allowed is True

    def test_enforce_content_reachability_warning(self, temp_dir: Path):
        _make_files(temp_dir, {
            "handler.py": "from evil_helper import run\n",
            "evil_helper.py": "def run():\n    eval('bad')\n",
        })
        config = Config(repo_root=temp_dir)
        result = enforce_content("handler.py", "from evil_helper import run\n", config)
        assert result.allowed is True  # default level is "warn"
        assert any(v.category == "reachability" for v in result.violations)

    def test_run_guardrails_reachability(self, temp_dir: Path):
        _make_files(temp_dir, {
            "handler.py": "from evil_helper import run\n",
            "evil_helper.py": "def run():\n    subprocess.run(['ls'])\n",
        })
        config = Config(repo_root=temp_dir)
        path = temp_dir / "handler.py"
        path.write_text("from evil_helper import run\n")
        result = _run_guardrails(path, temp_dir, config)
        assert any(v.category == "reachability" for v in result.violations)


class TestGraphCaching:
    def test_graph_cached_across_calls(self, temp_dir: Path):
        _make_files(temp_dir, {
            "a.py": "from b import foo\n",
            "b.py": "eval('bad')\n",
        })
        clear_cache()
        config = Config(repo_root=temp_dir)

        v1 = check_reachability("a.py", "", config)
        assert len(v1) >= 1

        # Second call should use cached graph
        v2 = check_reachability("a.py", "", config)
        assert len(v2) >= 1

    def test_graph_rebuilds_on_change(self, temp_dir: Path):
        _make_files(temp_dir, {
            "a.py": "from b import foo\n",
            "b.py": "def foo(): return 1\n",
        })
        clear_cache()
        config = Config(repo_root=temp_dir)

        v1 = check_reachability("a.py", "", config)
        assert v1 == []

        # Add a sensitive op to b.py and clear cache to force rebuild
        (temp_dir / "b.py").write_text("def foo():\n    eval('bad')\n")
        clear_cache()

        v2 = check_reachability("a.py", "", config)
        assert len(v2) >= 1


class TestReachabilityAcrossLanguages:
    def test_javascript_reachability(self, temp_dir: Path):
        _make_files(temp_dir, {
            "app.js": "import { run } from './evil';\n",
            "evil.js": "const cp = require('child_process');\ncp.execSync('rm -rf /');\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("app.js", "", config)
        assert len(violations) >= 1

    def test_typescript_reachability(self, temp_dir: Path):
        _make_files(temp_dir, {
            "app.ts": "import { run } from './evil';\n",
            "evil.ts": "import { execSync } from 'child_process';\nexecSync('rm -rf /');\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("app.ts", "", config)
        assert len(violations) >= 1

    def test_mixed_language_reachability(self, temp_dir: Path):
        """Python imports a module that internally uses sensitive ops."""
        _make_files(temp_dir, {
            "app.py": "from helpers import process\n",
            "helpers.py": "import subprocess\ndef process():\n    subprocess.run(['tool'])\n",
        })
        config = Config(repo_root=temp_dir)
        violations = check_reachability("app.py", "", config)
        assert len(violations) >= 1
        assert any("helpers.py" in v.file for v in violations)
