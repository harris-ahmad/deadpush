# Agent integration with Guardian Push Channel (GPC)

GPC delivers **push notifications** from the deadpush guardian to your agent runtime —
outside MCP stdio. Use it when the agent should react immediately to quarantines,
lockdowns, or session pauses without polling tools.

## Quick start (CLI)

```bash
deadpush protect --daemon   # guardian + GPC server
deadpush gpc-listen         # debug: print events
```

After `deadpush configure all`, a Cursor rule snippet is written to
`.cursor/rules/deadpush-gpc.mdc` with copy-paste examples.

## Python (in-process)

```python
from pathlib import Path
from deadpush.gpc import GpcClient, GpcMessage

REPO = Path("/path/to/your/repo")

def on_gpc(msg: GpcMessage) -> None:
    if msg.type == "INCIDENT":
        # Surface to user; do NOT retry the blocked write
        raise RuntimeError(f"Guardian blocked: {msg.payload}")
    if msg.type == "LOCKDOWN":
        raise RuntimeError(f"Repo lockdown: {msg.payload.get('reason')}")
    if msg.type == "SESSION_PAUSE":
        print("MCP paused:", msg.payload.get("reason"))
    if msg.type == "INSTRUCTION":
        print("Policy instruction:", msg.payload.get("text"))

client = GpcClient(REPO)
client.connect_and_listen()  # background thread; auto-ACK by default

# ... run your agent loop ...
client.stop()
```

## TypeScript / Node

Install the reference client (monorepo package):

```bash
cd packages/deadpush-gpc-client && npm install
```

```typescript
import { connectGpc } from "@deadpush/gpc-client";

const client = connectGpc("/path/to/repo", (msg) => {
  if (msg.type === "INCIDENT") {
    console.error("Guardian incident:", msg.payload);
  }
});
// client.close() on shutdown
```

Or implement manually: newline-delimited JSON on Unix socket
`~/.deadpush/gpc.<repo-id>.sock` (see [gpc-protocol.md](gpc-protocol.md)).

## Message types to handle

| Type | Agent action |
|------|----------------|
| `INCIDENT` | Stop current write path; show violation to user |
| `LOCKDOWN` | Halt all repo mutations (score 0) |
| `SESSION_PAUSE` | MCP suspended — do not rely on MCP tools |
| `INSTRUCTION` | Follow policy text (repeated violations) |
| `POLICY_UPDATE` | Refresh local understanding of allowlist/rules |

## Audit trail

Guardian and MCP proxy events are also recorded in a hash-chained audit log:

```bash
deadpush verify-audit
deadpush export-sarif -o results.sarif
```

Upload SARIF to GitHub Advanced Security or attach to CI artifacts.

## Optional: macOS T2-max (Endpoint Security)

Organizations with Apple ES entitlements can deploy `deadpush-es` (separate package).
See [macos-t2-max-es.md](macos-t2-max-es.md). OSS users should use T2 Seatbelt +
T3 GitHub scan.

## Protocol reference

Full schema: [gpc-protocol.md](gpc-protocol.md)
