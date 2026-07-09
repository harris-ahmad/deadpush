"""Minimal MCP server for mcp-proxy E2E tests — echoes tools/call to a marker file."""

from __future__ import annotations

import json
import os
import sys

MARKER = os.environ.get("MOCK_MCP_MARKER", "")


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            _reply(msg_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "mock", "version": "1"},
            })
        elif method == "tools/list":
            _reply(msg_id, {"tools": []})
        elif method == "tools/call":
            if MARKER:
                Path = __import__("pathlib").Path
                Path(MARKER).write_text(json.dumps(msg), encoding="utf-8")
            _reply(msg_id, {"content": [{"type": "text", "text": "ok"}]})
        elif method == "notifications/initialized":
            pass
        elif msg_id is not None:
            _reply(msg_id, {})


def _reply(msg_id, result: dict) -> None:
    print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}), flush=True)


if __name__ == "__main__":
    main()
