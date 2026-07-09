# Guardian Push Channel (GPC)

Bidirectional push protocol **outside** MCP stdio. Agents subscribe to receive guardian
events without polling MCP tools.

## Transport

- Unix domain socket: `~/.deadpush/gpc.<repo-id>.sock` (soft) or `/var/db/deadpush/gpc.<repo-id>.sock` (hardened)
- Framing: newline-delimited JSON (one message per line)
- Protocol version: `1.0`
- Max message size: 65536 bytes

## Guardian → client messages

| type | payload fields | meaning |
|------|----------------|---------|
| `INCIDENT` | `category`, `description`, `file` | Guardrail block / quarantine |
| `LOCKDOWN` | `reason` | Safety score at 0; all writes quarantined |
| `INSTRUCTION` | `text` | Human/policy instruction for agent |
| `POLICY_UPDATE` | `rules` | Runtime policy changed |
| `SESSION_PAUSE` | `reason`, `until` | Scoped pause (CRITICAL still fires) |

## Client → guardian messages

| type | payload | meaning |
|------|---------|---------|
| `ACK` | `message_id` | Client received a message |
| `HEARTBEAT` | — | Keep-alive |
| `REQUEST_OVERRIDE` | `reason`, `message_id` | Human-gated override request (v0: received only) |

## Example message

```json
{"type": "INCIDENT", "repo_id": "a1b2c3d4e5f6", "timestamp": "2026-07-05T12:00:00+00:00", "message_id": "inc-123", "payload": {"category": "secret", "description": "Hardcoded API key", "file": ".env"}}
```

## CLI

```bash
# Debug: print events from running guardian
deadpush gpc-listen

# Guardian starts GPC automatically with `deadpush protect --daemon`
```

## Integration for agent authors

```python
from deadpush.gpc import GpcClient, GpcMessage

def on_msg(msg: GpcMessage):
    if msg.type == "INCIDENT":
        # surface to agent context
        ...

client = GpcClient(repo_root, on_message=on_msg)
client.connect_and_listen()  # background thread
```

GPC complements MCP — it does not replace filesystem/git enforcement. See [guarantees.md](guarantees.md).
