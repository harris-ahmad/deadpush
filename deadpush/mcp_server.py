"""
Model Context Protocol (MCP) server for deadpush guardrails.

Any MCP-compatible agent (Cursor, Claude Desktop, Claude Code, etc.) can
connect and call deadpush's capabilities as native tools.

All tools return structured JSON so agents can parse results programmatically.
Transport: stdio (newline-delimited JSON-RPC 2.0)
"""

from __future__ import annotations

import difflib
import json
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .intercept import InterceptDaemon, GuardrailResult, Violation
from .intercept import _run_guardrails, _check_sensitive_write, _check_destructive_changes, STAGING_DIR, FEEDBACK_DIR
from .config import load_config
from .guard import _scoped_suspend_file
from .rules import RuntimeConfig


MCP_PROTOCOL_VERSION = "2024-11-05"


def _ok(data: Any = None, summary: str = "") -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps({
            "success": True,
            "summary": summary,
            "data": data,
        }, indent=2, default=str)}],
    }


def _err(message: str) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [{"type": "text", "text": json.dumps({
            "success": False,
            "error": message,
            "data": None,
        }, indent=2)}],
    }


def _text(text: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
    }


class McpServer:
    """MCP server exposing all deadpush capabilities as agent-native tools."""

    def __init__(self, repo_root: str | Path | None = None, danger_mode: bool = False):
        self.repo_root = Path(repo_root).resolve() if repo_root else Path.cwd().resolve()
        self.config = load_config(explicit_root=self.repo_root)
        self.runtime = RuntimeConfig(self.repo_root)
        self.daemon = InterceptDaemon(self.repo_root, self.config)
        self.daemon.runtime = self.runtime
        self._stdio_broken = False
        self.danger_mode = danger_mode
        self.suspend_file: Path | None = None
        self.suspended = False

    def _start_suspension_watch(self):
        if self.suspend_file is None:
            return
        def _watch():
            while not self.suspended:
                try:
                    if self.suspend_file and self.suspend_file.exists():
                        self.suspended = True
                        if not self._stdio_broken:
                            print("Suspension file detected — shutting down MCP server.",
                                  file=sys.stderr)
                        break
                except Exception:
                    pass
                time.sleep(10)
        t = threading.Thread(target=_watch, daemon=True, name="mcp-suspension-watch")
        t.start()

    # -----------------------------------------------------------------------
    # Feedback helpers
    # -----------------------------------------------------------------------
    def _count_unacknowledged_feedback(self) -> int:
        feedback_dir = self.repo_root / FEEDBACK_DIR
        count = 0
        if feedback_dir.exists():
            for f in feedback_dir.glob("*.json"):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if not data.get("acknowledged", False):
                        count += 1
                except Exception:
                    pass
        return count

    def _safe_call(self, handler: Callable[[dict[str, Any]], dict[str, Any]], args: dict[str, Any]) -> dict[str, Any]:
        try:
            return handler(args)
        except Exception as e:
            return _err(str(e))

    def _send_error(self, msg_id: Any, code: int, message: str):
        if self._stdio_broken:
            return
        response = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
        try:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            self._stdio_broken = True

    # -----------------------------------------------------------------------
    # Tool definitions
    # -----------------------------------------------------------------------
    def _tools_list(self) -> list[dict[str, Any]]:
        return [
            # --- Write / Check ---
            {
                "name": "write_file",
                "description": "Write a file through deadpush guardrails. Checks security, prompt injection, secrets, layer violations. Safe files are written; dangerous files are blocked with feedback. Returns structured JSON with violations if any.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path (e.g. src/api.py)"},
                        "content": {"type": "string", "description": "File content"},
                    },
                    "required": ["path", "content"],
                },
            },
            {
                "name": "check_file",
                "description": "Preview whether file content would pass guardrails. Returns violations without writing anything.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                },
            },
            # --- Scan ---
            {
                "name": "scan",
                "description": "Run full deadpush analysis. Returns dead symbols, debris, test issues, stale docs, layer violations, security boundaries, and complexity alerts as structured JSON.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "get_dead_symbols",
                "description": "Get all unreachable/dead code symbols detected by reachability analysis.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_debris",
                "description": "Get all debris items (AI artifacts, temp files, context dumps, chat exports).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_test_issues",
                "description": "Get test quality issues (no-assertion tests, tautologies, empty tests).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_stale_docs",
                "description": "Get stale/mismatched documentation (docstring params that don't match signatures).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_layer_violations",
                "description": "Get architecture layer import violations.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_security_boundaries",
                "description": "Get untested security-sensitive operations (eval, subprocess, crypto, SQL, etc.).",
                "inputSchema": {"type": "object", "properties": {
                    "min_severity": {"type": "string", "description": "Minimum severity: low, medium, high, critical"},
                }},
            },
            {
                "name": "get_complexity_alerts",
                "description": "Get files with significant complexity increases from baseline.",
                "inputSchema": {"type": "object", "properties": {
                    "min_pct": {"type": "number", "description": "Minimum percentage increase to report (default 20)"},
                }},
            },
            # --- Clean ---
            {
                "name": "clean",
                "description": "Clean dead code and debris. By default uses safe mode (archives with explanations). Returns list of items cleaned.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "description": "cleanup mode: safe (archive, default), dry_run (preview), force (delete)"},
                    },
                },
            },
            # --- Quarantine ---
            {
                "name": "quarantine_list",
                "description": "List quarantined files with reasons and original paths.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Max entries (default 20)"},
                    },
                },
            },
            {
                "name": "quarantine_restore",
                "description": "Restore a quarantined file to its original location.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Quarantined filename (from quarantine_list)"},
                    },
                    "required": ["name"],
                },
            },
            # --- Feedback ---
            {
                "name": "get_feedback",
                "description": "Read recent guardrail feedback entries. Shows what was blocked and why.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Max entries (default 5)"},
                    },
                },
            },
            {
                "name": "get_recent_feedback",
                "description": "Read unacknowledged guardrail feedback entries. Filtered to show only feedback the agent has not yet acknowledged.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Max entries (default 10)"},
                    },
                },
            },
            {
                "name": "acknowledge_feedback",
                "description": "Mark a feedback entry as acknowledged. The agent calls this after reading and addressing the feedback. Use the safe_name from get_recent_feedback (e.g. 'src__bad.py').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Feedback filename (safe_name, e.g. src__bad.py)"},
                    },
                    "required": ["name"],
                },
            },
            {
                "name": "retry_write",
                "description": "Submit corrected content for a previously blocked file. Runs guardrails on the new content. If it passes, writes to the real path and acknowledges the previous feedback. If it still fails, quarantines and writes new feedback.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path (e.g. src/api.py)"},
                        "content": {"type": "string", "description": "Corrected file content"},
                    },
                    "required": ["path", "content"],
                },
            },
            # --- Status ---
            {
                "name": "get_status",
                "description": "Get current guardrail configuration, available tools, and directory paths.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_safety_score",
                "description": "Get latest Safety Score from the background AI Agent Guardian.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            # --- Configuration tools (agent self-service) ---
            {
                "name": "get_runtime_config",
                "description": "View the current runtime configuration: allowed patterns, ignored paths, guardrail levels, and all settings.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "add_allowed_pattern",
                "description": "Add a regex pattern to the allowlist. When a guardrail match falls under an allowed pattern, it is skipped. Use this to whitelist known-safe code patterns.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Regex pattern to allow (e.g. r'safe_eval_data')"},
                        "description": {"type": "string", "description": "Why this pattern is safe (optional)"},
                    },
                    "required": ["pattern"],
                },
            },
            {
                "name": "remove_allowed_pattern",
                "description": "Remove a pattern from the allowlist by its regex string.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Regex pattern to remove"},
                    },
                    "required": ["pattern"],
                },
            },
            {
                "name": "ignore_path",
                "description": "Add a file path to the ignore list. Guardrails will skip this file entirely.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path to ignore (e.g. tests/fixtures/generated.py)"},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "set_guardrail_level",
                "description": "Change the severity level for a guardrail category. Valid levels: off, warn, block.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Guardrail category: prompt_injection, secret, security, layer, debris"},
                        "level": {"type": "string", "description": "Level: off (disable), warn (report only), block (prevent write)"},
                    },
                    "required": ["category", "level"],
                },
            },
            {
                "name": "reset_runtime_config",
                "description": "Reset all runtime config to defaults. Clears all allowed patterns, ignored paths, and guardrail level overrides.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            # --- Diff / Sensitive write tools ---
            {
                "name": "get_write_diff",
                "description": "Preview the diff and guardrail violations for a proposed write. Returns unified diff + would_block + violations. No file is written.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path (e.g. src/api.py)"},
                        "content": {"type": "string", "description": "Proposed file content"},
                    },
                    "required": ["path", "content"],
                },
            },
            {
                "name": "allow_sensitive_write",
                "description": "Explicitly opt in to writing a sensitive config file (CI/CD, deployment, Docker, etc.). Adds the path to the runtime allowlist so the next write passes the sensitive file guardrail.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path to allow (e.g. .github/workflows/deploy.yml)"},
                    },
                    "required": ["path"],
                },
            },
            # --- Agent-as-Adjudicator ---
            {
                "name": "adjudicate_finding",
                "description": "Adjudicate a guardrail finding. Presents the finding with structured uncertainty for the agent to adjudicate. Returns a scoring rubric. Call learn_false_positive if the agent determines the finding is a false positive.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Category: security, secret, prompt_injection, layer, debris, sensitive, destructive, dependency"},
                        "description": {"type": "string", "description": "The full violation description text"},
                        "file_path": {"type": "string", "description": "Relative path of the flagged file"},
                        "line": {"type": "number", "description": "Line number of the violation"},
                        "severity": {"type": "string", "description": "Severity: low, medium, high, critical"},
                        "uncertainty": {"type": "string", "description": "Why this flag might be wrong (contextual notes)"},
                    },
                    "required": ["category", "description", "file_path"],
                },
            },
            {
                "name": "learn_false_positive",
                "description": "Teach deadpush that a pattern is a false positive. After verifying a finding manually, call this to persist the pattern so it is auto-suppressed in future guardrail checks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Guardrail category"},
                        "pattern": {"type": "string", "description": "The violation description text (or pattern) to suppress"},
                        "reason": {"type": "string", "description": "Why this is a false positive (for future reference)"},
                    },
                    "required": ["category", "pattern", "reason"],
                },
            },
            # --- Test Verification ---
            {
                "name": "verify_write",
                "description": "Write a file through guardrails AND run the relevant test file. If tests pass, the file is written. If tests fail, the file is NOT written and the agent receives structured test output. Use this when you want to verify your change doesn't break existing tests.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path (e.g. src/api.py)"},
                        "content": {"type": "string", "description": "File content"},
                    },
                    "required": ["path", "content"],
                },
            },
            {
                "name": "get_test_results",
                "description": "Get recent test verification results. Returns structured test output from the last N verify_write calls.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Max entries (default 10)"},
                    },
                },
            },
        ]

    # -----------------------------------------------------------------------
    # Tool handlers — all return structured JSON
    # -----------------------------------------------------------------------
    def _run_analysis(self) -> dict[str, Any]:
        """Run full analysis and return structured results."""
        from .cli import _run_full_analysis
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run_full_analysis, self.config)
            try:
                return future.result(timeout=60)
            except TimeoutError:
                return _err("Analysis timed out after 60s")
            except Exception as e:
                return _err(f"Analysis failed: {e}")

    def _tool_write_file(self, args: dict[str, Any]) -> dict[str, Any]:
        path = args.get("path", "")
        content = args.get("content", "")
        if not path:
            return _err("path is required")
        result = self.daemon.write_file(path, content)
        if result.allowed:
            return _ok({"path": path, "status": "allowed", "violations": []}, "File approved.")
        return _ok({
            "path": path,
            "status": "blocked",
            "violations": [{"category": v.category, "description": v.description, "line": v.line, "severity": v.severity} for v in result.violations],
        }, f"File blocked: {len(result.violations)} violation(s).")

    def _tool_verify_write(self, args: dict[str, Any]) -> dict[str, Any]:
        path = args.get("path", "")
        content = args.get("content", "")
        if not path:
            return _err("path is required")
        if not content:
            return _err("content is required")

        # Step 1: Run guardrails
        result = self.daemon.write_file(path, content)
        if not result.allowed:
            return _ok({
                "path": path,
                "status": "blocked_by_guardrails",
                "violations": [{"category": v.category, "description": v.description, "line": v.line, "severity": v.severity} for v in result.violations],
                "test_result": None,
            }, f"File blocked by guardrails: {len(result.violations)} violation(s).")

        # Step 2: Run test verification
        from .verifier import TestVerifier
        verifier = TestVerifier(self.config)
        verification = verifier.verify_write(path, content)

        if not verification["verifiable"]:
            # No test file found — file is already written, just report it
            return _ok({
                "path": path,
                "status": "allowed",
                "violations": [],
                "test_result": None,
                "note": verification["reason"],
            }, "File written (no test file found for verification).")

        test_result = verification["test_result"]
        if test_result["passed"]:
            return _ok({
                "path": path,
                "status": "allowed",
                "violations": [],
                "test_result": test_result,
            }, f"Tests passed ({test_result['test_file']}). File written.")

        # Tests failed — quarantine the written file + restore from git
        self._quarantine_and_restore(path, result)
        return _ok({
            "path": path,
            "status": "test_failure",
            "violations": [{"category": "test_failure", "description": f"Tests failed: {test_result['test_file']}", "line": 0, "severity": "high"}],
            "test_result": test_result,
        }, f"Tests FAILED ({test_result['test_file']}). File quarantined and restored.")

    def _quarantine_and_restore(self, rel_path: str, guardrail_result: GuardrailResult):
        """Quarantine a written file and restore it from git."""
        from .intercept import QUARANTINE_DIR, FEEDBACK_DIR, _write_feedback
        dest = self.repo_root / rel_path
        if not dest.exists():
            return

        # Move to quarantine
        quarantine_dir = self.repo_root / QUARANTINE_DIR
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        safe_name = rel_path.replace("/", "__").replace("\\", "__")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantined = quarantine_dir / f"{timestamp}__{safe_name}"
        try:
            import shutil
            shutil.move(str(dest), str(quarantined))
        except Exception:
            return

        # Write feedback
        feedback_result = GuardrailResult()
        for v in guardrail_result.violations:
            feedback_result.reject(v)
        feedback_result.reject(Violation("test_failure", f"Tests failed, file quarantined to {quarantined.name}", 0, "high"))
        _write_feedback(self.repo_root / FEEDBACK_DIR, rel_path, feedback_result)

        # Restore from git
        try:
            import subprocess
            git_show = subprocess.run(
                ["git", "show", f"HEAD:{rel_path}"],
                capture_output=True, text=True,
                cwd=str(self.repo_root),
            )
            if git_show.returncode == 0 and git_show.stdout:
                dest.write_text(git_show.stdout, encoding="utf-8")
        except Exception:
            pass

    def _tool_get_test_results(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            limit = int(args.get("limit", 10))
        except (ValueError, TypeError):
            return _err("limit must be a number")
        from .verifier import load_recent_results
        entries = load_recent_results(self.config, limit=limit)
        return _ok({"count": len(entries), "results": entries}, f"{len(entries)} test result(s).")

    def _tool_check_file(self, args: dict[str, Any]) -> dict[str, Any]:
        path = args.get("path", "")
        content = args.get("content", "")
        if not path:
            return _err("path is required")
        staging_dir = self.daemon.staging_dir
        try:
            staging_path = (staging_dir / path).resolve()
            staging_path.parent.mkdir(parents=True, exist_ok=True)
            staging_path.write_text(content, encoding="utf-8")
            result = _run_guardrails(staging_path, staging_dir, self.config, self.runtime)
            staging_path.unlink(missing_ok=True)
        except Exception:
            staging_path.unlink(missing_ok=True)
            return _err("Could not process file")
        violations = [{"category": v.category, "description": v.description, "line": v.line, "severity": v.severity} for v in result.violations]
        return _ok({"path": path, "would_block": len(violations) > 0, "violations": violations},
                    f"{'Would be blocked' if violations else 'Would be approved'} ({len(violations)} violation(s)).")

    def _tool_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._run_analysis()
        return _ok({
            "files_scanned": len(result.get("files", [])),
            "dead_symbols_count": len(result.get("dead_symbols", [])),
            "debris_count": len(result.get("debris", [])),
            "test_issues_count": len(result.get("test_issues", [])),
            "stale_docs_count": len(result.get("stale_docs", [])),
            "layer_violations_count": len(result.get("layer_violations", [])),
            "complexity_alerts_count": len(result.get("complexity_alerts", [])),
            "security_untested_count": len(getattr(result.get("security_report"), "untested", [])),
        }, "Scan complete.")

    def _tool_get_dead_symbols(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._run_analysis()
        dead = result.get("dead_symbols", [])
        symbols = []
        for d in dead:
            s = d.symbol if hasattr(d, "symbol") else d
            symbols.append({
                "name": getattr(s, "name", str(s)),
                "file": getattr(s, "path", getattr(d, "path", "")),
                "confidence": getattr(d, "confidence", 1.0),
                "reason": getattr(d, "reason", ""),
            })
        return _ok({"count": len(symbols), "symbols": symbols}, f"{len(symbols)} dead symbols found.")

    def _tool_get_debris(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._run_analysis()
        items = [{"file": d.path, "category": d.category, "description": d.description, "block_push": getattr(d, "block_push", False)}
                 for d in result.get("debris", [])]
        return _ok({"count": len(items), "items": items}, f"{len(items)} debris items found.")

    def _tool_get_test_issues(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._run_analysis()
        issues = [{"file": t.file, "line": t.line, "issue_type": t.issue_type, "description": t.description}
                  for t in result.get("test_issues", [])]
        return _ok({"count": len(issues), "issues": issues}, f"{len(issues)} test quality issues found.")

    def _tool_get_stale_docs(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._run_analysis()
        docs = [{"file": d.file, "line": d.line, "issue_type": d.issue_type, "description": d.description}
                for d in result.get("stale_docs", [])]
        return _ok({"count": len(docs), "issues": docs}, f"{len(docs)} stale documentation issues found.")

    def _tool_get_layer_violations(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._run_analysis()
        violations = [{"file": v.file, "line": v.line, "description": v.description} for v in result.get("layer_violations", [])]
        return _ok({"count": len(violations), "violations": violations}, f"{len(violations)} layer violations found.")

    def _tool_get_security_boundaries(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._run_analysis()
        sec = result.get("security_report")
        if not sec:
            return _ok({"count": 0, "boundaries": []}, "No security data.")
        untested = [{"file": s.file, "line": s.line, "category": s.category, "description": s.description}
                    for s in sec.untested]
        tested = [{"file": s.file, "line": s.line, "category": s.category, "description": s.description}
                  for s in sec.tested]
        return _ok({"count_untested": len(untested), "count_tested": len(tested), "untested": untested, "tested": tested},
                   f"{len(untested)} untested security boundaries.")

    def _tool_get_complexity_alerts(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            min_pct = float(args.get("min_pct", 20))
        except (ValueError, TypeError):
            return _err("min_pct must be a number")
        result = self._run_analysis()
        alerts = [a for a in result.get("complexity_alerts", []) if a.get("pct_increase", 0) >= min_pct]
        return _ok({"count": len(alerts), "alerts": alerts}, f"{len(alerts)} complexity alerts.")

    def _tool_clean(self, args: dict[str, Any]) -> dict[str, Any]:
        mode = args.get("mode", "safe")
        result = self._run_analysis()
        debris = result.get("debris", [])
        dead = result.get("dead_symbols", [])
        all_issues = debris + [d for d in dead]
        if not all_issues:
            return _ok({"cleaned": 0, "items": []}, "Nothing to clean.")

        if mode == "dry_run":
            return _ok({"would_clean": len(all_issues), "would_archive": len(all_issues) if mode != "force" else 0}, f"Would clean {len(all_issues)} items.")

        import shutil
        from datetime import datetime
        archive_dir = self.repo_root / ".deadpush-archive" / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_dir.mkdir(parents=True, exist_ok=True)
        moved = []
        for item in all_issues:
            item_path = getattr(item, "path", None) or getattr(getattr(item, "symbol", None), "path", None)
            if not item_path:
                continue
            path = Path(item_path)
            if path.exists():
                dest = archive_dir / path.name
                shutil.move(str(path), str(dest))
                moved.append(str(path))
        return _ok({"cleaned": len(moved), "archive_dir": str(archive_dir), "items": moved},
                   f"Cleaned {len(moved)} items to {archive_dir}.")

    def _tool_quarantine_list(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            limit = int(args.get("limit", 20))
        except (ValueError, TypeError):
            return _err("limit must be a number")
        try:
            from .guard import QuarantineManager
            qm = QuarantineManager(self.repo_root)
            entries = qm.list_quarantined()[:limit]
            return _ok({"count": len(entries), "entries": entries}, f"{len(entries)} quarantined files.")
        except Exception as e:
            return _err(str(e))

    def _tool_quarantine_restore(self, args: dict[str, Any]) -> dict[str, Any]:
        err = self._check_danger("restore a quarantined file")
        if err:
            return err
        name = args.get("name", "")
        if not name:
            return _err("name is required")
        try:
            from .guard import QuarantineManager
            qm = QuarantineManager(self.repo_root)
            restored = qm.restore(name)
            if restored:
                return _ok({"restored": str(restored)}, f"Restored to {restored}.")
            return _err(f"Could not restore '{name}'. Check quarantine_list for valid names.")
        except Exception as e:
            return _err(str(e))

    def _tool_get_feedback(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            limit = int(args.get("limit", 5))
        except (ValueError, TypeError):
            return _err("limit must be a number")
        feedback_dir = self.repo_root / FEEDBACK_DIR
        entries = []
        if feedback_dir.exists():
            files = sorted(feedback_dir.glob("*.json"), reverse=True)[:limit]
            for f in files:
                try:
                    entries.append(json.loads(f.read_text(encoding="utf-8")))
                except Exception:
                    pass
        return _ok({"count": len(entries), "entries": entries}, f"{len(entries)} feedback entries.")

    def _tool_get_recent_feedback(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            limit = int(args.get("limit", 10))
        except (ValueError, TypeError):
            return _err("limit must be a number")
        feedback_dir = self.repo_root / FEEDBACK_DIR
        entries = []
        if feedback_dir.exists():
            for f in sorted(feedback_dir.glob("*.json"), reverse=True):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if not data.get("acknowledged", False):
                        entries.append(data)
                        if len(entries) >= limit:
                            break
                except Exception:
                    pass
        return _ok({"count": len(entries), "entries": entries}, f"{len(entries)} unacknowledged feedback entries.")

    def _tool_acknowledge_feedback(self, args: dict[str, Any]) -> dict[str, Any]:
        name = args.get("name", "")
        if not name:
            return _err("name is required")
        if not isinstance(name, str):
            return _err("name must be a string")
        feedback_dir = self.repo_root / FEEDBACK_DIR
        path = feedback_dir / name
        if not path.exists():
            path = feedback_dir / f"{name}.json"
        if not path.exists():
            return _err(f"Feedback entry '{name}' not found.")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["acknowledged"] = True
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return _ok({"name": name, "file": data.get("file", "")}, f"Feedback '{name}' acknowledged.")
        except Exception as e:
            return _err(f"Could not acknowledge feedback: {e}")

    def _tool_retry_write(self, args: dict[str, Any]) -> dict[str, Any]:
        path = args.get("path", "")
        content = args.get("content", "")
        if not path:
            return _err("path is required")
        if not content:
            return _err("content is required")
        # Write to staging through the daemon's pipeline
        result = self.daemon.write_file(path, content)
        # Acknowledge any previous feedback for this file
        safe_name = path.replace("/", "__").replace("\\", "__")
        feedback_dir = self.repo_root / FEEDBACK_DIR
        prev_path = feedback_dir / f"{safe_name}.json"
        if prev_path.exists():
            try:
                prev = json.loads(prev_path.read_text(encoding="utf-8"))
                prev["acknowledged"] = True
                prev_path.write_text(json.dumps(prev, indent=2), encoding="utf-8")
            except Exception:
                pass
        if result.allowed:
            return _ok({
                "path": path,
                "status": "allowed",
                "violations": [],
            }, "Retry approved. File written successfully.")
        return _ok({
            "path": path,
            "status": "blocked",
            "violations": [{"category": v.category, "description": v.description, "line": v.line, "severity": v.severity} for v in result.violations],
        }, f"Retry blocked: {len(result.violations)} violation(s) still present.")

    def _tool_get_status(self, args: dict[str, Any]) -> dict[str, Any]:
        agent_md = self.repo_root / "AGENT.md"
        return _ok({
            "repo_root": str(self.repo_root),
            "staging_dir": str(self.repo_root / STAGING_DIR),
            "feedback_dir": str(self.repo_root / FEEDBACK_DIR),
            "agent_onboarding": str(agent_md) if agent_md.exists() else None,
            "tools": [t["name"] for t in self._tools_list()],
        }, "Server running.")

    def _tool_get_safety_score(self, args: dict[str, Any]) -> dict[str, Any]:
        # Check default and hardened log locations
        candidates = [
            Path.home() / ".deadpush" / "guardian.log",
            Path("/var/db/deadpush/guardian.log"),
        ]
        score = "No background guardian running (start with deadpush protect --daemon)"
        for log in candidates:
            if log.exists():
                try:
                    lines = log.read_text(errors="ignore").strip().splitlines()[-20:]
                    for ln in reversed(lines):
                        if "Safety" in ln or "Score:" in ln or "Status:" in ln:
                            score = ln.strip()
                            break
                except Exception:
                    pass
                break
        return _ok({"safety_score": score}, "Safety score retrieved.")

    def _tool_get_runtime_config(self, args: dict[str, Any]) -> dict[str, Any]:
        return _ok(self.runtime.to_dict(), "Runtime configuration.")

    def _check_danger(self, action: str) -> dict[str, Any] | None:
        """Require danger mode for guardrail-softening actions. Returns error dict or None."""
        if not self.danger_mode:
            return _err(
                f"Cannot {action} in normal mode — this weakens security.\n"
                f"If you really need this, ask your user to run:\n"
                f"  deadpush mcp --danger\n"
                f"Then retry."
            )
        return None

    def _tool_add_allowed_pattern(self, args: dict[str, Any]) -> dict[str, Any]:
        err = self._check_danger("add an allowed pattern")
        if err:
            return err
        pattern = args.get("pattern", "")
        desc = args.get("description", "")
        if not pattern:
            return _err("pattern is required")
        try:
            self.runtime.add_allowed_pattern(pattern, desc)
            return _ok({"pattern": pattern}, f"Pattern added: {pattern}")
        except re.error as e:
            return _err(f"Invalid regex: {e}")

    def _tool_remove_allowed_pattern(self, args: dict[str, Any]) -> dict[str, Any]:
        err = self._check_danger("remove an allowed pattern")
        if err:
            return err
        pattern = args.get("pattern", "")
        if not pattern:
            return _err("pattern is required")
        if self.runtime.remove_allowed_pattern(pattern):
            return _ok({"pattern": pattern}, f"Pattern removed: {pattern}")
        return _err(f"Pattern not found: {pattern}")

    def _tool_ignore_path(self, args: dict[str, Any]) -> dict[str, Any]:
        err = self._check_danger("ignore a path")
        if err:
            return err
        path = args.get("path", "")
        if not path:
            return _err("path is required")
        self.runtime.ignore_path(path)
        return _ok({"path": path}, f"Ignored path: {path}")

    def _tool_set_guardrail_level(self, args: dict[str, Any]) -> dict[str, Any]:
        category = args.get("category", "")
        level = args.get("level", "")
        if not category or not level:
            return _err("category and level are required")
        if level in ("off", "warn") and not self.danger_mode:
            return _err(
                f"Cannot set guardrail '{category}' to '{level}' in normal mode — this weakens security.\n"
                f"Only hardening (warn → block, off → warn/block) is allowed.\n"
                f"To soften, ask your user to run:\n"
                f"  deadpush mcp --danger\n"
                f"Then retry."
            )
        try:
            self.runtime.set_guardrail_level(category, level)
            return _ok({"category": category, "level": level}, f"Guardrail '{category}' set to '{level}'.")
        except ValueError as e:
            return _err(str(e))

    def _tool_reset_runtime_config(self, args: dict[str, Any]) -> dict[str, Any]:
        err = self._check_danger("reset runtime config")
        if err:
            return err
        self.runtime.reset()
        return _ok({}, "Runtime config reset to defaults.")

    def _tool_get_write_diff(self, args: dict[str, Any]) -> dict[str, Any]:
        path = args.get("path", "")
        content = args.get("content", "")
        if not path:
            return _err("path is required")
        staging_dir = self.daemon.staging_dir
        staging_path = (staging_dir / path).resolve()
        staging_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            staging_path.write_text(content, encoding="utf-8")
            result = _run_guardrails(staging_path, staging_dir, self.config, self.runtime)
            staging_path.unlink(missing_ok=True)
        except Exception:
            staging_path.unlink(missing_ok=True)
            return _err("Could not process file")

        # Compute diff against existing file
        dest = (self.repo_root / path).resolve()
        diff_text = ""
        if dest.exists():
            try:
                old = dest.read_text(encoding="utf-8", errors="ignore")
                diff = difflib.unified_diff(
                    old.splitlines(keepends=True),
                    content.splitlines(keepends=True),
                    fromfile=str(dest),
                    tofile=str(dest),
                )
                diff_text = "".join(diff)
            except Exception:
                diff_text = "(could not read existing file)"

        violations = [{"category": v.category, "description": v.description, "line": v.line, "severity": v.severity} for v in result.violations]
        return _ok({
            "path": path,
            "would_block": not result.allowed,
            "file_exists": dest.exists(),
            "violations": violations,
            "diff": diff_text,
        }, f"{'Would be blocked' if not result.allowed else 'Would be approved'} ({len(violations)} violation(s)).")

    def _tool_allow_sensitive_write(self, args: dict[str, Any]) -> dict[str, Any]:
        path = args.get("path", "")
        if not path:
            return _err("path is required")
        import re
        self.runtime.add_allowed_pattern(re.escape(path) + "\\Z", f"Sensitive write bypass for {path}")
        return _ok({"path": path}, f"Sensitive write for '{path}' allowed. Added to allowlist.")
        # Note: allow_sensitive_write is intentionally NOT danger-gated — it only
        # allows writing to specific sensitive config paths, it doesn't disable
        # security categories. The agent can opt into writing deploy.yml etc.

    def _tool_adjudicate_finding(self, args: dict[str, Any]) -> dict[str, Any]:
        category = args.get("category", "")
        description = args.get("description", "")
        file_path = args.get("file_path", "")
        line = args.get("line", 0)
        severity = args.get("severity", "")
        uncertainty = args.get("uncertainty", "")

        if not category or not description or not file_path:
            return _err("category, description, and file_path are required")

        return _ok({
            "finding": {
                "category": category,
                "description": description,
                "file_path": file_path,
                "line": line,
                "severity": severity,
                "uncertainty": uncertainty,
            },
            "adjudication_prompt": (
                f"Review this {category} finding in {file_path}:{line}.\n"
                f"  Description: {description}\n"
                f"  Severity: {severity}\n"
                f"  Uncertainty: {uncertainty or 'None provided'}\n\n"
                "Is this a TRUE POSITIVE (actual issue) or FALSE POSITIVE (safe code)?\n"
                "- If TRUE POSITIVE: fix the issue and retry.\n"
                "- If FALSE POSITIVE: call learn_false_positive with category, the description pattern, and your reason."
            ),
            "scoring": {
                "certainty_levels": {
                    "certain": "No doubt — pattern is definitely a violation",
                    "likely": "Probably a violation but edge case possible",
                    "ambiguous": "Could go either way — context needed",
                    "likely_fp": "Probably a false positive — low risk pattern",
                    "certain_fp": "Definitely not a violation — safe code pattern",
                }
            }
        }, f"Finding presented for adjudication ({category}: {description[:60]}).")

    def _tool_learn_false_positive(self, args: dict[str, Any]) -> dict[str, Any]:
        err = self._check_danger("teach a false positive pattern")
        if err:
            return err
        category = args.get("category", "")
        pattern = args.get("pattern", "")
        reason = args.get("reason", "")
        if not category or not pattern or not reason:
            return _err("category, pattern, and reason are required")
        from .intercept import _learn_false_positive
        _learn_false_positive(category, pattern, reason, self.repo_root)
        return _ok({
            "category": category,
            "pattern": pattern,
            "reason": reason,
        }, f"Learned false positive pattern for '{category}': {pattern[:60]}")

    # -----------------------------------------------------------------------
    # MCP lifecycle
    # -----------------------------------------------------------------------
    def _inject_feedback_summary(self, response: dict[str, Any]) -> dict[str, Any]:
        try:
            content = response.get("content", [])
            for c in content:
                if c.get("type") == "text":
                    parsed = json.loads(c["text"])
                    parsed["feedback_summary"] = {
                        "unacknowledged": self._count_unacknowledged_feedback()
                    }
                    c["text"] = json.dumps(parsed, indent=2, default=str)
        except Exception as e:
            print(f"[deadpush] _inject_feedback_summary failed: {e}", file=sys.stderr, flush=True)
        return response

    def _handle_request(self, method: str, params: dict[str, Any] | None) -> dict[str, Any] | None:
        if method == "tools/list":
            return {"tools": self._tools_list()}
        elif method == "tools/call":
            name = (params or {}).get("name", "")
            arguments = (params or {}).get("arguments", {})
            tool_map: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
                "write_file": self._tool_write_file,
                "check_file": self._tool_check_file,
                "scan": self._tool_scan,
                "get_dead_symbols": self._tool_get_dead_symbols,
                "get_debris": self._tool_get_debris,
                "get_test_issues": self._tool_get_test_issues,
                "get_stale_docs": self._tool_get_stale_docs,
                "get_layer_violations": self._tool_get_layer_violations,
                "get_security_boundaries": self._tool_get_security_boundaries,
                "get_complexity_alerts": self._tool_get_complexity_alerts,
                "clean": self._tool_clean,
                "quarantine_list": self._tool_quarantine_list,
                "quarantine_restore": self._tool_quarantine_restore,
                "get_feedback": self._tool_get_feedback,
                "get_recent_feedback": self._tool_get_recent_feedback,
                "acknowledge_feedback": self._tool_acknowledge_feedback,
                "retry_write": self._tool_retry_write,
                "get_status": self._tool_get_status,
                "get_safety_score": self._tool_get_safety_score,
                "get_runtime_config": self._tool_get_runtime_config,
                "add_allowed_pattern": self._tool_add_allowed_pattern,
                "remove_allowed_pattern": self._tool_remove_allowed_pattern,
                "ignore_path": self._tool_ignore_path,
                "set_guardrail_level": self._tool_set_guardrail_level,
                "reset_runtime_config": self._tool_reset_runtime_config,
                "get_write_diff": self._tool_get_write_diff,
                "allow_sensitive_write": self._tool_allow_sensitive_write,
                "adjudicate_finding": self._tool_adjudicate_finding,
                "learn_false_positive": self._tool_learn_false_positive,
                "verify_write": self._tool_verify_write,
                "get_test_results": self._tool_get_test_results,
            }
            handler = tool_map.get(name)
            if not handler:
                return _err(f"Unknown tool: {name}")
            return self._safe_call(handler, arguments)
        return None

    def run(self):
        """Read JSON-RPC requests from stdin and respond on stdout."""
        self.daemon.start(http=False)

        for line in sys.stdin:
            if self._stdio_broken:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._send_error(None, -32700, "Parse error")
                continue

            msg_id = msg.get("id")
            method = msg.get("method")
            params = msg.get("params")

            if method == "initialize":
                self._send(msg_id, {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "deadpush", "version": "0.2.0"},
                })
                continue

            if method in ("notifications/initialized", "notifications/cancelled"):
                continue

            if method == "shutdown":
                self._send(msg_id, None)
                break

            if self.suspended:
                break

            if method:
                result = self._handle_request(method, params)
                if result is not None:
                    result = self._inject_feedback_summary(result)
                    self._send(msg_id, result)
                else:
                    self._send_error(msg_id, -32601, f"Method not found: {method}")

    def _send(self, msg_id: Any, result: Any):
        if self._stdio_broken:
            return
        response = {"jsonrpc": "2.0", "id": msg_id, "result": result}
        try:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            self._stdio_broken = True


def run_mcp(danger_mode: bool = False, hardened: bool = False):
    """Entry point for the MCP server (deadpush mcp)."""
    config = load_config()

    # Detect hardened guardian: if the shared port file exists under the repo,
    # the guardian is running as _deadpush and state lives in /var/db/deadpush/.
    # The --hardened flag can also be passed explicitly.
    if hardened or (config.repo_root / ".guardian" / "guardian.control.port").exists():
        hardened = True

    # Check for suspension flag (set by guardian when score ≤ 5).
    # In normal mode, refuse to start. Danger mode overrides.
    suspend_file = _scoped_suspend_file(config.repo_root, hardened)
    if suspend_file.exists() and not danger_mode:
        reason = suspend_file.read_text(encoding="utf-8").strip()
        print(f"❌ deadpush MCP is suspended.\n\n{reason}\n\n"
              f"Your AI agent was blocked from weakening guardrails repeatedly.\n"
              f"To re-enable MCP access, run:\n\n    deadpush mcp --danger\n\n"
              f"This allows the agent to use MCP tools again.\n",
              file=sys.stderr)
        return
    server = McpServer(config.repo_root, danger_mode=danger_mode)
    server.suspend_file = suspend_file
    server._start_suspension_watch()
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        server.daemon.stop()
