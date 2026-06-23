# Changelog

## 0.2.0 (2026-06-22)

- Initial public release.
- MCP server with 20+ tools for AI coding agents.
- 7-category guardrail pipeline: security, secrets, prompt injection, debris, layer violations, destructive changes, sensitive writes.
- Multi-factor dead code detection using 8 signals (call graph, registration, imports, reachability, git freshness, etc.).
- Real-time filesystem guardian daemon (`deadpush protect --daemon`).
- Staging-based write interception with quarantine + structured feedback.
- Agent-as-adjudicator learning loop (adjudicate findings, learn false positives).
- Path-aware severity lowering for test/mock files.
- Runtime config system with per-category guardrail levels.
- CLI: scan, clean, verify, quarantine, status, hooks, deps, init.
- JSON-RPC 2.0 protocol compliance.
- 300+ tests across 11 test files.
