# @deadpush/gpc-client

Minimal TypeScript/Node client for the [deadpush](https://github.com/harris-ahmad/deadpush)
Guardian Push Channel (GPC).

```typescript
import { connectGpc } from "@deadpush/gpc-client";

connectGpc(process.cwd(), (msg) => {
  if (msg.type === "INCIDENT") console.error(msg.payload);
});
```

See [docs/agent-gpc-integration.md](../../docs/agent-gpc-integration.md) for the full protocol.
