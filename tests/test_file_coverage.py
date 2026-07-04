"""Coverage tests for the git-hook file selector (D2).

The watchdog daemon already scans every write; the git hooks previously gated on
a small extension allowlist and so silently skipped extensionless/config files
an agent can abuse (Dockerfile, Makefile, .env, .npmrc, LLM-context files, ...).
`is_enforceable_path` closes that gap. These tests lock in what is/ isn't
scanned so the coverage can't quietly regress.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.intercept import is_enforceable_path  # noqa: E402


ENFORCED = [
    # application / scripting code
    "app.py", "src/main.rs", "index.ts", "server.go", "lib.c", "A.cs",
    "x.swift", "q.sql", "deploy.ps1", "util.rb", "run.sh", "build.zsh",
    # infra / config
    "config.yaml", "pyproject.toml", "settings.ini", "app.cfg", "main.tf",
    "service.conf", "app.properties", "pom.xml", "schema.graphql",
    # docs / text (prompt injection, pasted secrets)
    "README.md", "NOTES.rst", "instructions.txt",
    # credential-bearing text
    "server.pem", "tls.crt", "id_rsa.key",
    # extensionless / sensitive-by-name
    "Dockerfile", "docker/Dockerfile", "Dockerfile.prod", "app.dockerfile",
    "Makefile", "sub/Makefile", "Jenkinsfile", "Gemfile", "Rakefile",
    ".gitignore", ".npmrc", ".bashrc", ".netrc", ".pypirc", ".editorconfig",
    # env variants
    ".env", ".env.local", ".env.production", "config/.env.test",
    # LLM / AI-assistant context files (extensionless)
    ".cursorrules", ".claude_instructions", ".cursorignore",
]

SKIPPED = [
    # binaries / media / archives / compiled
    "logo.png", "photo.jpeg", "bundle.zip", "archive.tar.gz", "mod.pyc",
    "libfoo.so", "app.exe", "data.sqlite", "keystore.p12", "font.woff2",
    # unknown / data formats we intentionally don't scan
    "data.csv", "notes.unknownext", "table.parquet",
]


@pytest.mark.parametrize("path", ENFORCED)
def test_enforced_paths_are_scanned(path):
    assert is_enforceable_path(path) is True, f"{path} should be scanned by hooks"


@pytest.mark.parametrize("path", SKIPPED)
def test_skipped_paths_are_not_scanned(path):
    assert is_enforceable_path(path) is False, f"{path} should NOT be scanned by hooks"


def test_matching_is_case_insensitive():
    assert is_enforceable_path("DOCKERFILE") is True
    assert is_enforceable_path("MyApp.PY") is True
    assert is_enforceable_path(".CursorRules") is True


def test_binary_extension_wins_over_nothing():
    # A private-key-looking name with a binary keystore extension is still skipped.
    assert is_enforceable_path("secrets.p12") is False
    # ...but a text .pem/.key is scanned (catch a committed private key).
    assert is_enforceable_path("secrets.pem") is True
