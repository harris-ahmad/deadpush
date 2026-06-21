"""
Import Hallucination Guard — validates external imports against package registries.

AI coding agents frequently hallucinate package names that don't exist or are
typographical variants of real packages. This module cross-references every
external import found during analysis against PyPI, npm, and crates.io,
flagging unknown packages before they cause runtime failures.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any


REGISTRY_TIMEOUT = 5
CACHE_FILE = Path.home() / ".deadpush" / "import_cache.json"
CACHE_MAX_AGE = 86400

# Well-known stdlib module roots to skip checking (prevents spam).
PYTHON_STDLIB = {
    "os", "sys", "re", "json", "math", "time", "datetime", "pathlib",
    "collections", "itertools", "functools", "typing", "enum", "abc",
    "io", "base64", "hashlib", "hmac", "random", "statistics", "uuid",
    "argparse", "click", "logging", "warnings", "traceback", "inspect",
    "fractions", "decimal", "string", "struct", "textwrap", "pprint",
    "shutil", "tempfile", "glob", "fnmatch", "linecache", "fileinput",
    "pickle", "shelve", "marshal", "dbm", "sqlite3", "copy",
    "array", "weakref", "types", "bisect", "heapq", "operator",
    "subprocess", "threading", "multiprocessing", "concurrent",
    "asyncio", "select", "socket", "ssl", "email", "json", "xml",
    "html", "http", "urllib", "cgi", "webbrowser", "csv", "configparser",
    "netrc", "getpass", "crypt", "platform", "errno", "ctypes",
    "atexit", "signal", "mmap", "sysconfig", "syslog", "pdb", "profile",
    "unittest", "test", "doctest", "locale", "calendar", "difflib",
    "logging", "gettext", "codecs", "encodings", "importlib",
    "pkgutil", "zipimport", "pdb", "gc", "inspect", "ast",
    "compileall", "dis", "py_compile", "pyclbr", "token",
    "tokenize", "keyword", "symbol", "symtable", "tabnanny",
    "pyclbr", "py_compile", "compileall", "dis", "pickletools",
    "wave", "audioop", "chunk", "colorsys", "imghdr", "sndhdr",
    "ossaudiodev", "sunaudiodev", "wave", "cProfile",
    "codeop", "code", "rlcompleter", "runpy",
    "__future__", "__main__", "builtins", "__builtins__",
}

KNOWN_TEST_PACKAGES = {
    "pytest", "unittest", "mock", "coverage", "tox", "nox",
    "hypothesis", "factory_boy", "faker", "responses", "vcrpy",
    "freezegun", "time_machine", "pytest_mock", "pytest_cov",
    "pytest_asyncio", "pytest_xdist", "pytest_fixtures",
    "moto", "localstack", "testcontainers",
}

# Hardcoded well-known public packages to avoid hitting the network for common ones.
WELL_KNOWN_PACKAGES = {
    "django", "flask", "fastapi", "requests", "numpy", "pandas",
    "scipy", "matplotlib", "torch", "tensorflow", "transformers",
    "click", "sqlalchemy", "alembic", "pydantic", "jinja2",
    "werkzeug", "gunicorn", "uvicorn", "celery", "redis",
    "psycopg2", "pymongo", "boto3", "botocore", "aiohttp",
    "httpx", "starlette", "pillow", "opencv_python", "beautifulsoup4",
    "lxml", "sphinx", "black", "ruff", "mypy", "isort", "flake8",
    "pylint", "pre_commit", "poetry", "pip", "setuptools",
    "wheel", "cffi", "cryptography", "bcrypt", "passlib",
    "jwt", "python_jose", "oauthlib", "authlib",
    "pytest", "coverage", "hypothesis", "tox", "pre_commit",
    "loguru", "structlog", "sentry_sdk", "prometheus_client",
    "pydantic_settings", "python_dotenv", "python_multipart",
    "typer", "rich", "colorama", "tqdm", "pyyaml", "toml",
    "orjson", "ujson", "msgpack", "protobuf",
    "grpcio", "grpcio_tools", "kafka_python", "confluent_kafka",
    "elasticsearch", "elasticsearch_dsl", "motor", "beanie",
    "uvloop", "httptools", "websockets", "sse_starlette",
}


class ImportValidator:
    """Validates external imports by checking against package registries."""

    def __init__(self, cache_file: Path = CACHE_FILE):
        self.cache_file = cache_file
        self._cache: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self._load_cache()

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------
    def _load_cache(self):
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                now = time.time()
                self._cache = {
                    k: v for k, v in data.items()
                    if now - v.get("checked_at", 0) < CACHE_MAX_AGE
                }
            except Exception:
                self._cache = {}

    def _save_cache(self):
        if not self._dirty:
            return
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(
                json.dumps(self._cache, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Registry checks
    # ------------------------------------------------------------------
    def _check_pypi(self, package: str) -> bool:
        url = f"https://pypi.org/pypi/{package}/json"
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "deadpush/0.2.0")
            resp = urllib.request.urlopen(req, timeout=REGISTRY_TIMEOUT)
            return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code != 200
        except Exception:
            return False

    def _check_npm(self, package: str) -> bool:
        url = f"https://registry.npmjs.org/{package}/latest"
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "deadpush/0.2.0")
            resp = urllib.request.urlopen(req, timeout=REGISTRY_TIMEOUT)
            return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code != 200
        except Exception:
            return False

    def _check_crates(self, package: str) -> bool:
        url = f"https://crates.io/api/v1/crates/{package}"
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "deadpush/0.2.0")
            resp = urllib.request.urlopen(req, timeout=REGISTRY_TIMEOUT)
            return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code != 200
        except Exception:
            return False

    def _check_registry(self, package: str, suffix: str) -> bool:
        """Determine registry by convention and check."""
        package_lower = package.lower().replace("_", "-").replace(".", "-")

        if suffix in (".py",):
            return self._check_pypi(package_lower)
        elif suffix in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"):
            return self._check_npm(package_lower)
        elif suffix in (".rs",):
            return self._check_crates(package_lower)
        elif suffix in (".go",):
            # Go modules are URLs, too complex to validate generically
            return True
        return True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def validate_batch(self, imports: list[tuple[str, str]]) -> list[dict[str, Any]]:
        """Validate a batch of (package_name, file_suffix) tuples.

        Returns a list of flag dicts for packages that appear to be hallucinated.
        Each dict has: package, reason, confidence, source_files (sample).
        """
        unique_packages: dict[str, dict[str, Any]] = {}

        for pkg_name, suffix in imports:
            root = pkg_name.split(".")[0].split("/")[0].split("-")[0]
            root = root.replace("_", "-")
            if not root or len(root) < 2:
                continue
            if root in PYTHON_STDLIB or root in KNOWN_TEST_PACKAGES or root in WELL_KNOWN_PACKAGES:
                continue

            if root not in unique_packages:
                unique_packages[root] = {
                    "package": root,
                    "suffixes": set(),
                    "sources": [],
                    "exists": None,
                }
            unique_packages[root]["suffixes"].add(suffix)

        if not unique_packages:
            return []

        # Check cache first
        to_check = []
        for name, info in unique_packages.items():
            cached = self._cache.get(name)
            if cached is not None:
                info["exists"] = cached.get("exists", False)
            else:
                to_check.append(name)

        # Batch network check for uncached
        for name in to_check:
            info = unique_packages[name]
            suffix = next(iter(info["suffixes"]))
            exists = self._check_registry(name, suffix)
            info["exists"] = exists
            self._cache[name] = {"exists": exists, "checked_at": time.time()}
            self._dirty = True

        self._save_cache()

        # Build flags for non-existent packages
        flags = []
        for name, info in unique_packages.items():
            if info["exists"] is False:
                flags.append({
                    "category": "hallucinated_import",
                    "confidence": 0.92,
                    "reason": f"Package '{name}' not found on package registry — may be hallucinated by AI",
                    "block": False,
                    "suggestion": f"Verify the package '{name}' exists on the appropriate registry (PyPI/npm/crates.io) before importing. AI models often hallucinate package names.",
                })
            elif info["exists"] is None:
                # timed out or unknown
                pass

        return flags
