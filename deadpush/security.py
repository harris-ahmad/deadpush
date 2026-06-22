"""
Security Boundary Map — tracks security-sensitive functions and their test coverage.

AI agents may introduce unsafe operations (eval, exec, raw SQL, crypto) without
corresponding tests. This module identifies those boundaries and flags untested ones.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    # (category, description, regex pattern for Python/JS source)
    ("code_exec", "Dynamic code execution", r"\b(exec|eval)\s*\("),
    ("command_injection", "Shell command execution", r"\b(subprocess\.(call|run|Popen|check_output|check_call)|os\.system|os\.popen|shlex)\s*\("),
    ("file_write", "File write operation", r"\bopen\s*\(.*[rwab]+\s*\)"),
    ("file_delete", "File deletion", r"\b(os\.remove|os\.unlink|shutil\.rmtree|Path\.unlink|Path\.rmdir)\s*\("),
    ("crypto", "Cryptographic operation", r"\b(hashlib|hmac|Cryptodome|Crypto|nacl|bcrypt|argon2|passlib)\b"),
    ("network", "Network I/O", r"\b(socket|requests\.(get|post|put|delete|patch)|urllib|aiohttp|httpx)\s*\("),
    ("sql_injection", "SQL query construction", r"\bexecute\s*\(\s*['\"](SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)"),
    ("pickle", "Unsafe deserialization", r"\b(pickle\.loads|pickle\.load|jsonpickle|yaml\.load(?!_safe)|shelve)\s*\("),
    ("insecure_import", "Insecure module import", r"\bimport\s+(pickle|shelve|marshal|subprocess|ctypes)\b"),
    ("temp_file", "Temporary file", r"\b(tempfile|NamedTemporaryFile|mkstemp|mkdtemp)\b"),
    ("permission", "Permission/chmod operation", r"\b(os\.chmod|os\.chown|os\.setuid|os\.setgid)\s*\("),
    ("path_traversal", "Path traversal risk", r"\b(Path|os\.path\.join)\s*\(.*\+\s*"),
]


SENSITIVE_FUNCTION_NAMES: set[str] = {
    # Python
    "exec", "eval", "compile",
    # Shell
    "system", "popen",
    # File
    "remove", "unlink", "rmtree",
    # Serialization
    "loads", "load",
    # Permissions
    "chmod", "chown",
}


@dataclass
class SecurityBoundary:
    """A security-sensitive operation found in source code."""
    file: str
    line: int
    category: str
    description: str
    matched_text: str
    has_test: bool = False
    test_file: str = ""


@dataclass
class SecurityReport:
    """Full security boundary scan result."""
    boundaries: list[SecurityBoundary] = field(default_factory=list)
    untested: list[SecurityBoundary] = field(default_factory=list)
    tested: list[SecurityBoundary] = field(default_factory=list)


class SecurityScanner:
    """Scans source files for security-sensitive operations and checks test coverage."""

    def __init__(self, repo_root: Path | None = None):
        self.repo_root = repo_root or Path.cwd()

    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

    def scan_file(self, file_path: Path) -> list[SecurityBoundary]:
        """Find security-sensitive operations in a single file."""
        boundaries: list[SecurityBoundary] = []
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return boundaries
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return boundaries

        rel_path = _relative(file_path, self.repo_root)

        for category, desc, pattern in SENSITIVE_PATTERNS:
            for m in re.finditer(pattern, source, re.IGNORECASE):
                line_num = source[:m.start()].count("\n") + 1
                # Determine context: extract the line
                lines = source.splitlines()
                context_line = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                boundaries.append(SecurityBoundary(
                    file=rel_path,
                    line=line_num,
                    category=category,
                    description=desc,
                    matched_text=context_line[:80],
                ))
        return boundaries

    def find_test_files(self) -> list[Path]:
        """Find test files in the repository."""
        test_files: list[Path] = []
        for pattern in ("**/test_*.py", "**/*_test.py", "**/tests/**/*.py", "**/test_*.js", "**/*.test.js", "**/*.spec.js", "**/__tests__/**", "**/*.test.ts", "**/*.spec.ts"):
            matches = list(self.repo_root.glob(pattern))
            test_files.extend(matches)
        # Deduplicate
        seen: set[Path] = set()
        deduped: list[Path] = []
        for p in test_files:
            resolved = p.resolve()
            if resolved not in seen:
                seen.add(resolved)
                deduped.append(p)
        return deduped

    def find_calls_in_tests(self, target_name: str, test_files: list[Path]) -> list[tuple[Path, int]]:
        """Find calls to a specific function name in test files."""
        results: list[tuple[Path, int]] = []
        try:
            name_lower = target_name.lower()
        except Exception:
            return results

        for tf in test_files:
            try:
                source = tf.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(rf'\b{re.escape(target_name)}\s*\(', source):
                    line_num = source[:m.start()].count("\n") + 1
                    results.append((tf, line_num))
            except Exception:
                pass
        return results

    def check_test_coverage(self, boundaries: list[SecurityBoundary]) -> SecurityReport:
        """Check each boundary for test coverage."""
        test_files = self.find_test_files()
        report = SecurityReport()

        for b in boundaries:
            # Try to infer the function name from the matched text
            func_name = _extract_func_name(b.matched_text)
            if func_name:
                calls = self.find_calls_in_tests(func_name, test_files)
                if calls:
                    b.has_test = True
                    b.test_file = str(calls[0][0])
                    report.tested.append(b)
                else:
                    report.untested.append(b)
            else:
                report.untested.append(b)

            report.boundaries.append(b)

        return report

    def scan_and_report(self, files: list[Any]) -> SecurityReport:
        """Scan a batch of files and check test coverage."""
        all_boundaries: list[SecurityBoundary] = []
        for f in files:
            path = getattr(f, "path", None)
            if path is None:
                continue
            all_boundaries.extend(self.scan_file(Path(path)))
        return self.check_test_coverage(all_boundaries)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _extract_func_name(text: str) -> str | None:
    """Extract the function/method name from matched source text."""
    m = re.match(r'^.*?\b([\w.]+)\s*\(', text)
    if m:
        name = m.group(1)
        # Remove module prefix for the last component
        if "." in name:
            name = name.rsplit(".", 1)[-1]
        return name
    return None
