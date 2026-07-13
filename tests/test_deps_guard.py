"""Tests for the Dependency Integrity Guard (typosquat detection)."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.deps_guard import (
    _levenshtein,
    _check_typosquat,
    _check_suspicious_name,
    check_deps,
    get_ecosystem,
    parse_deps,
)
from deadpush.intercept import _check_dependency_integrity, Violation
from deadpush.rules import RuntimeConfig


# ======================================================================
# Levenshtein
# ======================================================================

class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("requests", "requests") == 0

    def test_one_substitution(self):
        assert _levenshtein("requests", "requesrs") == 1

    def test_one_insertion(self):
        assert _levenshtein("flask", "flasks") == 1

    def test_one_deletion(self):
        assert _levenshtein("django", "djang") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0

    def test_empty_vs_nonempty(self):
        assert _levenshtein("", "abc") == 3

    def test_case_sensitive(self):
        assert _levenshtein("Flask", "flask") <= 2


# ======================================================================
# Typosquat detection
# ======================================================================

class TestCheckTyposquat:
    def test_known_package_no_squat(self):
        assert _check_typosquat("requests", "python") == []

    def test_typosquat_levenshtein_1(self):
        suspects = _check_typosquat("requets", "python")
        assert "requests" in suspects

    def test_typosquat_levenshtein_2(self):
        suspects = _check_typosquat("requeests", "python")
        assert "requests" in suspects

    def test_short_name_levenshtein_3(self):
        suspects = _check_typosquat("flaskk", "python")
        assert "flask" in suspects

    def test_no_known_packages_for_ecosystem(self):
        suspects = _check_typosquat("somepackage", "unknown")
        assert suspects == []

    def test_npm_typosquat(self):
        suspects = _check_typosquat("reactt", "npm")
        assert "react" in suspects

    def test_empty_name(self):
        assert _check_typosquat("", "python") == []

    def test_dash_variants(self):
        suspects = _check_typosquat("requets", "python")
        assert "requests" in suspects


# ======================================================================
# Suspicious name checks
# ======================================================================

class TestCheckSuspiciousName:
    def test_normal_name(self):
        assert _check_suspicious_name("requests") == []

    def test_non_ascii(self):
        issues = _check_suspicious_name("requеsts")
        assert any("non-ASCII" in i for i in issues)

    def test_special_chars(self):
        issues = _check_suspicious_name("paçkage!")
        assert any("special" in i or "non-ASCII" in i for i in issues)

    def test_normal_with_underscore(self):
        assert _check_suspicious_name("my_package") == []

    def test_normal_with_dash(self):
        assert _check_suspicious_name("my-package") == []


# ======================================================================
# Ecosystem detection
# ======================================================================

class TestGetEcosystem:
    def test_pyproject(self):
        assert get_ecosystem("pyproject.toml") == "python"

    def test_requirements(self):
        assert get_ecosystem("requirements.txt") == "python"

    def test_package_json(self):
        assert get_ecosystem("package.json") == "npm"

    def test_cargo(self):
        assert get_ecosystem("Cargo.toml") == "rust"

    def test_go_mod(self):
        assert get_ecosystem("go.mod") == "go"

    def test_unknown(self):
        assert get_ecosystem("Gemfile") is None

    def test_path_with_prefix(self):
        assert get_ecosystem("frontend/package.json") == "npm"
        assert get_ecosystem("backend/pyproject.toml") == "python"


# ======================================================================
# Dependency file parsing
# ======================================================================

class TestParseDeps:
    def test_requirements_txt_simple(self):
        source = "requests==2.28.0\nflask>=2.0\n"
        deps = parse_deps(source, "requirements.txt")
        names = {d[0].lower() for d in deps}
        assert "requests" in names
        assert "flask" in names

    def test_requirements_txt_with_comments(self):
        source = "# this is a comment\nrequests==2.28.0\n-flask>=2.0\n"
        deps = parse_deps(source, "requirements.txt")
        names = {d[0].lower() for d in deps}
        assert "requests" in names
        assert "flask" not in names

    def test_pyproject_deps(self):
        source = '''[project]
name = "test"
dependencies = [
    "requests>=2.28",
    "fastapi>=0.100",
]
'''
        deps = parse_deps(source, "pyproject.toml")
        names = {d[0].lower() for d in deps}
        assert "requests" in names
        assert "fastapi" in names

    def test_package_json_deps(self):
        source = '''{
  "dependencies": {
    "react": "^18.0.0",
    "express": "^4.18.0"
  }
}'''
        deps = parse_deps(source, "package.json")
        names = {d[0].lower() for d in deps}
        assert "react" in names
        assert "express" in names

    def test_package_json_dev_deps(self):
        source = '''{
  "devDependencies": {
    "jest": "^29.0.0"
  }
}'''
        deps = parse_deps(source, "package.json")
        names = {d[0].lower() for d in deps}
        assert "jest" in names

    def test_cargo_toml(self):
        source = '''[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["full"] }
'''
        deps = parse_deps(source, "Cargo.toml")
        names = {d[0].lower() for d in deps}
        assert "serde" in names
        assert "tokio" in names

    def test_go_mod(self):
        source = '''module example

require (
    github.com/gorilla/mux v1.8.0
    github.com/gin-gonic/gin v1.9.0
)
'''
        deps = parse_deps(source, "go.mod")
        assert len(deps) == 2

    def test_go_mod_inline(self):
        source = '''module example

require github.com/gorilla/mux v1.8.0
'''
        deps = parse_deps(source, "go.mod")
        assert len(deps) == 1

    def test_unknown_file(self):
        assert parse_deps("anything", "Gemfile") == []

    def test_setup_py_as_unknown(self):
        assert parse_deps("anything", "setup.py") == []

    def test_requirements_txt_editable(self):
        source = "-e git+https://example.com/pkg.git#egg=mypkg\nnumpy>=1.20\n"
        deps = parse_deps(source, "requirements.txt")
        names = {d[0].lower() for d in deps}
        assert "numpy" in names

    def test_pyproject_no_deps(self):
        source = "[project]\nname = 'test'\n"
        deps = parse_deps(source, "pyproject.toml")
        assert deps == []

    def test_package_json_empty(self):
        source = '{}\n'
        deps = parse_deps(source, "package.json")
        assert deps == []

    def test_cargo_toml_no_deps(self):
        source = "[package]\nname = 'test'\n"
        deps = parse_deps(source, "Cargo.toml")
        assert deps == []

    def test_go_mod_no_require(self):
        source = "module example\n"
        deps = parse_deps(source, "go.mod")
        assert deps == []


# ======================================================================
# check_deps — full pipeline
# ======================================================================

class TestCheckDeps:
    def test_clean_pyproject(self):
        vs = check_deps('[project]\ndependencies = ["requests>=2.28"]\n', "pyproject.toml")
        assert vs == []

    def test_typosquat_detected(self):
        vs = check_deps('[project]\ndependencies = ["requets>=2.28"]\n', "pyproject.toml")
        assert len(vs) == 1
        assert vs[0]["category"] == "dependency"
        assert vs[0]["severity"] == "high"

    def test_skip_if_old_source_has_same(self):
        new = '[project]\ndependencies = ["requests>=2.28"]\n'
        old = '[project]\ndependencies = ["requests>=2.28"]\n'
        vs = check_deps(new, "pyproject.toml", old_source=old)
        assert vs == []

    def test_only_additions_checked(self):
        old = '[project]\ndependencies = ["requests>=2.28"]\n'
        new = '[project]\ndependencies = ["requests>=2.28", "requets>=2.28"]\n'
        vs = check_deps(new, "pyproject.toml", old_source=old)
        assert len(vs) >= 1

    def test_unknown_ecosystem(self):
        vs = check_deps("anything", "Gemfile")
        assert vs == []

    def test_requirements_typosquat(self):
        vs = check_deps("requets==2.28.0\n", "requirements.txt")
        assert len(vs) == 1

    def test_package_json_typosquat(self):
        vs = check_deps('{"dependencies": {"reactt": "^18.0.0"}}', "package.json")
        assert len(vs) >= 1

    def test_cargo_typosquat(self):
        vs = check_deps('[dependencies]\nserdee = "1.0"\n', "Cargo.toml")
        assert len(vs) >= 1

    def test_suspicious_name_with_non_ascii(self):
        vs = check_deps('[project]\ndependencies = ["réquests>=2.28"]\n', "pyproject.toml")
        assert any("non-ASCII" in v["description"] for v in vs)

    def test_go_mod_typosquat(self):
        vs = check_deps('module example\nrequire github.com/gorrilla/mux v1.8.0\n', "go.mod")
        assert len(vs) >= 1


# ======================================================================
# Integration with intercept guardrails
# ======================================================================

class TestCheckDependencyIntegrity:
    def test_no_violations(self, temp_dir):
        f = temp_dir / "requirements.txt"
        f.write_text("requests==2.28.0\n")
        vs = _check_dependency_integrity("requests==2.28.0\n", "requirements.txt", temp_dir)
        assert vs == []

    def test_typosquat_violation(self, temp_dir):
        f = temp_dir / "requirements.txt"
        f.write_text("")
        vs = _check_dependency_integrity("requets==2.28.0\n", "requirements.txt", temp_dir)
        assert len(vs) >= 1
        assert vs[0].category == "dependency"

    def test_off_level_skips(self, temp_dir):
        runtime = RuntimeConfig(temp_dir)
        runtime.set_guardrail_level("dependency", "off")
        vs = _check_dependency_integrity("ssss==1.0\n", "requirements.txt", temp_dir, runtime)
        assert vs == []

    def test_allowed_pattern_bypasses(self, temp_dir):
        runtime = RuntimeConfig(temp_dir)
        runtime.add_allowed_pattern("requets")
        vs = _check_dependency_integrity("requets==2.28.0\n", "requirements.txt", temp_dir, runtime)
        assert vs == []

    def test_non_dep_file_no_violations(self, temp_dir):
        vs = _check_dependency_integrity("print('hello')\n", "hello.py", temp_dir)
        assert vs == []

    def test_new_file_no_old_source(self, temp_dir):
        vs = _check_dependency_integrity("requets==2.28.0\n", "requirements.txt", temp_dir)
        assert len(vs) >= 1

    def test_returns_violation_objects(self, temp_dir):
        vs = _check_dependency_integrity("requets==2.28.0\n", "requirements.txt", temp_dir)
        assert all(isinstance(v, Violation) for v in vs)
