"""
Post-write test verification.

Discovers and runs the most relevant test file for a given source file.
Used by the MCP verify_write tool so agents can verify their changes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config


TEST_RESULTS_DIR = ".deadpush/test_results"


@dataclass
class TestResult:
    passed: bool
    test_file: str
    command: str
    stdout: str
    stderr: str
    exit_code: int
    timestamp: str
    source_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "test_file": self.test_file,
            "command": self.command,
            "stdout": self.stdout[-2000:] if len(self.stdout) > 2000 else self.stdout,
            "stderr": self.stderr[-2000:] if len(self.stderr) > 2000 else self.stderr,
            "exit_code": self.exit_code,
            "timestamp": self.timestamp,
            "source_path": self.source_path,
        }


class TestVerifier:
    """Discover and run tests for a given source file."""

    def __init__(self, config: Config):
        self.config = config
        self.repo_root = config.repo_root

    def find_test_for(self, source_path: str) -> Path | None:
        """Find the most relevant test file for a source path.

        Convention: deadpush/x.py → tests/test_x.py
                    src/foo/bar.py → tests/test_foo/bar.py, tests/test_bar.py, etc.
        """
        rel = Path(source_path)
        stem = rel.stem
        parent = rel.parent

        candidates = [
            self.repo_root / "tests" / f"test_{stem}{rel.suffix}",
            self.repo_root / "tests" / f"test_{parent.name}_{stem}{rel.suffix}",
            self.repo_root / "tests" / parent.name / f"test_{stem}{rel.suffix}",
            self.repo_root / "tests" / parent.name / f"test_{parent.name}{rel.suffix}",
            self.repo_root / f"test_{rel}",
        ]

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()

        return None

    def find_or_create_results_dir(self) -> Path:
        results_dir = self.repo_root / TEST_RESULTS_DIR
        results_dir.mkdir(parents=True, exist_ok=True)
        return results_dir

    def run_test(self, test_file: Path) -> TestResult:
        """Run a test file and return structured results."""
        cmd_config = self.config.test
        test_path = str(test_file.resolve())
        command = cmd_config.command.format(test_file=test_path) if "{test_file}" in cmd_config.command else f"{cmd_config.command} {test_path}"
        timeout = cmd_config.timeout_seconds

        try:
            proc = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.repo_root),
            )
            exit_code = proc.returncode
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
        except subprocess.TimeoutExpired:
            exit_code = -1
            stdout = ""
            stderr = f"Test timed out after {timeout}s"
        except FileNotFoundError:
            exit_code = -2
            stdout = ""
            stderr = f"Test command not found: {cmd_config.command}"
        except Exception as e:
            exit_code = -3
            stdout = ""
            stderr = str(e)

        return TestResult(
            passed=exit_code == 0,
            test_file=str(test_file),
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def verify_write(self, path: str, content: str) -> dict[str, Any]:
        """Full verification flow: find test → run test → return result.

        Called from the MCP verify_write tool handler.
        """
        source_path = Path(path)

        # Find test file
        test_file = self.find_test_for(str(source_path))
        if not test_file:
            return {
                "verifiable": False,
                "reason": "No test file found for this source path.",
                "test_result": None,
            }

        # Run the test
        result = self.run_test(test_file)

        # Store result for get_test_results
        results_dir = self.find_or_create_results_dir()
        safe_name = source_path.name.replace("/", "__").replace("\\", "__")
        result_path = results_dir / f"{safe_name}.json"
        result.source_path = str(source_path)
        result_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")

        return {
            "verifiable": True,
            "reason": None,
            "test_result": result.to_dict(),
        }


def load_recent_results(config: Config, limit: int = 10) -> list[dict[str, Any]]:
    """Load recent test verification results for get_test_results MCP tool."""
    results_dir = config.repo_root / TEST_RESULTS_DIR
    entries = []
    if results_dir.exists():
        for f in sorted(results_dir.glob("*.json"), reverse=True)[:limit]:
            try:
                entries.append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass
    return entries
