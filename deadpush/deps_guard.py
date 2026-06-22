"""
Dependency Integrity Guard — detects typosquats and suspicious package additions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


KNOWN_PACKAGES: dict[str, set[str]] = {
    "python": {
        "requests", "flask", "django", "numpy", "pandas", "fastapi", "scipy",
        "matplotlib", "scikit-learn", "torch", "tensorflow", "pytest", "uvicorn",
        "sqlalchemy", "redis", "celery", "boto3", "click", "jinja2", "werkzeug",
        "pydantic", "alembic", "httpx", "aiohttp", "black", "ruff",
        "mypy", "isort", "flake8", "sphinx", "pillow", "beautifulsoup4",
        "lxml", "pyyaml", "tomli", "jsonschema", "orjson",
        "python-dotenv", "typing-extensions", "attrs",
        "psycopg2-binary", "pymongo", "motor", "grpcio", "protobuf",
        "cryptography", "bcrypt", "jwt", "oauthlib", "passlib",
        "gunicorn", "daphne", "channels",
        "elasticsearch", "loguru", "structlog", "sentry-sdk",
        "prometheus-client", "opentelemetry-api",
        "polars", "dask", "networkx", "nltk",
        "spacy", "transformers", "datasets", "tiktoken", "openai",
        "rich", "typer", "colorama",
        "ray", "joblib", "cloudpickle",
        "websockets", "msgpack", "zstandard",
        "twine", "build", "hatchling", "setuptools", "wheel",
        "coverage", "tox", "pre-commit", "virtualenv",
        "pip", "poetry", "watchdog",
        "anyio", "sniffio", "h11", "httpcore",
        "asyncpg", "aioredis",
        "pyarrow", "shapely", "geopandas", "xarray",
        "sympy", "scrapy", "selenium", "playwright",
        "pygments", "markdown",
        "opencv-python", "scikit-image",
        "torchvision", "torchaudio",
        "wandb", "mlflow", "dvc",
        "kubernetes", "docker",
        "ansible", "paramiko",
    },
    "npm": {
        "react", "react-dom", "lodash", "express", "axios", "next", "vue",
        "typescript", "eslint", "prettier", "webpack", "vite",
        "tailwindcss", "postcss", "autoprefixer", "jest", "mocha",
        "chai", "cypress", "playwright", "storybook",
        "redux", "react-router", "zustand", "zod",
        "mongoose", "prisma", "typeorm",
        "passport", "jsonwebtoken", "bcryptjs",
        "socket.io", "graphql", "apollo-client", "apollo-server",
        "uuid", "date-fns", "dayjs", "moment", "dotenv",
        "ts-node", "esbuild", "rollup",
        "pnpm", "yarn", "bun",
        "cheerio", "puppeteer",
        "sharp", "commander", "yargs",
        "chalk", "winston", "pino",
        "redis", "ioredis",
        "helmet", "cors", "compression", "cookie-parser", "body-parser",
        "aws-sdk", "firebase", "firebase-admin",
        "stripe", "nodemailer",
        "framer-motion", "three", "d3", "chart.js",
        "emotion", "styled-components",
        "react-native", "expo",
    },
    "rust": {
        "serde", "tokio", "reqwest", "clap", "anyhow", "thiserror",
        "rand", "chrono", "log", "tracing", "rayon",
        "futures", "hyper", "actix-web", "axum", "rocket",
        "tonic", "prost", "rustls", "openssl",
        "uuid", "regex", "once_cell", "parking_lot",
        "itertools", "num-traits", "indexmap",
        "serde_json", "serde_yaml", "toml", "csv",
        "sqlx", "diesel", "mongodb",
        "tokio-stream", "tokio-util", "pin-project",
        "bytes", "nom",
        "wasm-bindgen", "wasm-pack",
        "criterion", "tempfile",
        "indicatif", "console",
        "walkdir", "glob", "notify",
        "rust-embed", "mime_guess",
    },
    "go": {
        "gorilla/mux", "gin-gonic/gin", "echo", "fiber", "chi",
        "gorm", "ent",
        "cobra", "viper",
        "zap", "logrus", "zerolog",
        "stretchr/testify",
        "aws/aws-sdk-go", "docker/docker", "kubernetes/client-go",
        "google/uuid",
        "minio/minio-go",
        "go-git/go-git",
        "spf13/afero", "fsnotify/fsnotify",
    },
}


# ---------------------------------------------------------------------------
# Levenshtein distance
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j] + 1,
                prev[j + 1] + 1,
                prev[j] + cost,
            ))
        prev = curr
    return prev[-1]


# ---------------------------------------------------------------------------
# Typosquat and suspicious name checks
# ---------------------------------------------------------------------------

def _check_typosquat(name: str, ecosystem: str) -> list[str]:
    known = KNOWN_PACKAGES.get(ecosystem, set())
    if not name or name.lower() in known:
        return []
    suspects: list[str] = []
    n_clean = name.lower().replace("-", "").replace("_", "").replace("@", "")
    for known_name in known:
        k_clean = known_name.lower().replace("-", "").replace("_", "").replace("/", "")
        dist = _levenshtein(n_clean, k_clean)
        if 0 < dist <= 1:
            suspects.append(known_name)
        elif dist <= 2 and len(n_clean) <= 4:
            suspects.append(known_name)
    return suspects


def _check_suspicious_name(name: str) -> list[str]:
    issues: list[str] = []
    non_ascii = sum(1 for c in name if ord(c) > 127)
    if non_ascii > 0:
        issues.append(f"Package name contains {non_ascii} non-ASCII character(s)")
    name_clean = name.lower().replace("-", "").replace("_", "").replace(".", "")
    if not name_clean.isalnum():
        special = sum(1 for c in name_clean if not c.isalnum())
        if special > 0:
            issues.append(f"Package name contains {special} special character(s)")
    return issues


# ---------------------------------------------------------------------------
# Dependency file parsing
# ---------------------------------------------------------------------------

_REQUIREMENTS_LINE_RE = re.compile(
    r'^([a-zA-Z_][a-zA-Z0-9_.-]*?)(?:\[[^\]]*\])?\s*(?:>=|<=|!=|==|~=|>|<|@)\s*'
)
_REQUIREMENTS_NAME_RE = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_.-]*)')
_PACKAGE_JSON_KEY = re.compile(r'"(@?[a-zA-Z_][a-zA-Z0-9_./-]*?)"\s*:')


def _extract_toml_deps(source: str) -> list[tuple[str, int]]:
    """Extract dependency names from TOML using tomllib (stdlib, Python 3.11+)."""
    import tomllib

    deps: list[tuple[str, int]] = []
    try:
        data = tomllib.loads(source)
    except Exception:
        return deps

    def _add(name: str) -> None:
        """Find the line number for a dependency name."""
        pkg = re.split(r'[>=<!~@]', name.split("[")[0].strip())[0].strip()
        if not pkg or not re.match(r'^[a-zA-Z_]', pkg):
            return
        line = _find_toml_line(source, pkg)
        deps.append((pkg, line))

    # PEP 621: [project] dependencies = ["pkg>=1.0"]
    project = data.get("project", {})
    for dep_str in project.get("dependencies", []):
        if isinstance(dep_str, str):
            _add(dep_str)

    # PEP 621: [project.optional-dependencies] name = ["pkg>=1.0"]
    for dep_list in project.get("optional-dependencies", {}).values():
        for dep_str in dep_list:
            if isinstance(dep_str, str):
                _add(dep_str)

    # Poetry: [tool.poetry.dependencies] pkg = "^1.0"
    poetry = data.get("tool", {}).get("poetry", {})
    for key in ("dependencies", "dev-dependencies"):
        for dep_name in poetry.get(key, {}):
            _add(dep_name)

    # Poetry modern: [tool.poetry.group.{any}.dependencies]
    for group_name, group_data in poetry.get("group", {}).items():
        for dep_name in group_data.get("dependencies", {}):
            _add(dep_name)

    # Pipfile: [packages] / [dev-packages]
    for section_name in ("packages", "dev-packages"):
        for dep_name in data.get(section_name, {}):
            _add(dep_name)

    return deps


def _find_toml_line(source: str, name: str) -> int:
    """Find approximate line number for a dependency name in TOML source."""
    lines = source.splitlines()
    clean = name.split("[")[0].strip().lower()
    for i, line in enumerate(lines, 1):
        stripped = line.strip().lower()
        # Match key = ... or "key" = ... or 'key' = ...
        if re.match(rf'^["\']?{re.escape(clean)}["\']?\s*=', stripped):
            return i
    return 1


def _extract_requirements_txt(source: str) -> list[tuple[str, int]]:
    deps: list[tuple[str, int]] = []
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        m = _REQUIREMENTS_LINE_RE.match(stripped)
        if m:
            deps.append((m.group(1), i))
        elif "==" in stripped or ">=" in stripped:
            name = stripped.split("==")[0].split(">=")[0].strip()
            if re.match(r'^[a-zA-Z_]', name):
                deps.append((name, i))
        else:
            m2 = _REQUIREMENTS_NAME_RE.match(stripped)
            if m2:
                deps.append((m2.group(1), i))
    return deps


def _extract_package_json(source: str) -> list[tuple[str, int]]:
    deps: list[tuple[str, int]] = []
    with_braces = re.compile(r'"(?:devDependencies|dependencies)"\s*:\s*\{')
    for m in with_braces.finditer(source):
        block_start = m.end()
        depth = 1
        pos = block_start
        while depth > 0 and pos < len(source):
            ch = source[pos]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            pos += 1
        block = source[block_start:pos-1]
        for km in _PACKAGE_JSON_KEY.finditer(block):
            line = source[:block_start + km.start()].count("\n") + 1
            deps.append((km.group(1), line))
    return deps


def _extract_cargo_toml(source: str) -> list[tuple[str, int]]:
    deps: list[tuple[str, int]] = []
    in_deps = False
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps = stripped[1:-1].strip().lower() == "dependencies"
            continue
        if in_deps and not stripped.startswith("#"):
            m = re.match(r'^([a-zA-Z_][a-zA-Z0-9_-]*?)\s*=', stripped)
            if m:
                deps.append((m.group(1), i))
    return deps


def _extract_go_mod(source: str) -> list[tuple[str, int]]:
    deps: list[tuple[str, int]] = []
    in_require = False
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require:
            parts = stripped.split()
            if parts and not parts[0].startswith("//"):
                deps.append((parts[0], i))
        if stripped.startswith("require ") and not stripped.endswith("("):
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append((parts[1], i))
    return deps


ECOSYSTEM_FOR_FILE: dict[str, str] = {
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "Pipfile": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    "package.json": "npm",
    "Cargo.toml": "rust",
    "go.mod": "go",
}

_PARSE_FOR_FILE: dict[str, Any] = {
    "pyproject.toml": _extract_toml_deps,
    "requirements.txt": _extract_requirements_txt,
    "Pipfile": _extract_toml_deps,
    "package.json": _extract_package_json,
    "Cargo.toml": _extract_cargo_toml,
    "go.mod": _extract_go_mod,
}


def get_ecosystem(rel_path: str) -> str | None:
    name = Path(rel_path).name if "/" in rel_path or "\\" in rel_path else rel_path
    return ECOSYSTEM_FOR_FILE.get(name)


def parse_deps(source: str, rel_path: str) -> list[tuple[str, int]]:
    name = Path(rel_path).name if "/" in rel_path or "\\" in rel_path else rel_path
    parser = _PARSE_FOR_FILE.get(name)
    if parser:
        return parser(source)
    return []


# ---------------------------------------------------------------------------
# High-level check
# ---------------------------------------------------------------------------

def check_deps(source: str, rel_path: str, old_source: str = "") -> list[dict[str, Any]]:
    """Check a dependency file for typosquats and suspicious additions.
    
    Returns a list of violation dicts with keys:
      - category: "dependency"
      - description: human-readable explanation
      - line: line number
      - severity: "high" | "medium" | "low"
    """
    violations: list[dict[str, Any]] = []
    ecosystem = get_ecosystem(rel_path)
    if not ecosystem:
        return violations

    new_deps = parse_deps(source, rel_path)
    old_deps = parse_deps(old_source, rel_path) if old_source else []

    old_set = {d[0].lower() for d in old_deps}
    added = [(name, line) for name, line in new_deps if name.lower() not in old_set]

    for name, line in added:
        suspects = _check_typosquat(name, ecosystem)
        if suspects:
            violations.append({
                "category": "dependency",
                "description": f"Package '{name}' is a possible typosquat of: {', '.join(suspects[:3])}",
                "line": line,
                "severity": "high",
            })
        suspicious = _check_suspicious_name(name)
        for issue in suspicious:
            violations.append({
                "category": "dependency",
                "description": f"Package '{name}': {issue}",
                "line": line,
                "severity": "medium",
            })

    return violations
