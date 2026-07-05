# deadpush vs other agent guardrails

Honest comparison as of deadpush 0.3.0. deadpush owns **repo integrity**; MCP proxies
own **tool invocation** filtering. They complement each other.

## At a glance

| Capability | deadpush | Aperion Shield | JAK Shield | MCPKernel | OpenParallax |
|------------|:--------:|:--------------:|:----------:|:---------:|:------------:|
| Repo filesystem guardian | ✅ | ❌ | ❌ | partial | partial |
| Git hook enforcement | ✅ | ❌ | ❌ | ❌ | partial |
| Server-side ship gate (T3) | ✅ | ❌ | ❌ | ❌ | ❌ |
| MCP tool-call proxy | ✅ (`mcp-proxy`) | ✅ | ✅ | ✅ | ✅ |
| LLM debris / context files | ✅ | ❌ | ❌ | ❌ | ❌ |
| Hardened same-UID boundary | ✅ | ❌ | ❌ | ❌ | ✅ (process sep.) |
| OS sandbox (T2) | ✅ Seatbelt/fanotify | ❌ | ❌ | ✅ Docker/WASM | ✅ |
| Published guarantee catalog | ✅ | ❌ | partial | partial | partial |
| Plugin SDK on shared kernel | ✅ | ❌ | ❌ | partial | ❌ |

## What deadpush does that MCP-only tools do not

1. **Guards what lands in git** — not just what tools are called. Agents bypass MCP
   proxies by writing via shell, editor, or native APIs. deadpush's watchdog + hooks
   + server scan cover those paths.

2. **Debris detection** — `.cursorrules`, `CLAUDE.md`, scratchpads, and LLM context
   pollution are first-class guardrail categories.

3. **Provable tier model** — T0–T3 with documented guarantees ([guarantees.md](guarantees.md))
   and QA harness (`scripts/hardened_qa.sh`). Most competitors over-promise.

4. **Single enforcement kernel** — `enforce_content()` is shared by MCP, guardian,
   hooks, proxy, and scan. No policy drift between layers.

## What MCP-only tools do that deadpush does not (by design)

- **Database/git/filesystem MCP tool rules** at fine granularity (Shield's 45+ rules
  across SQL, k8s, AWS, etc.) — use Shield or MCPKernel alongside deadpush for tool
  surfaces deadpush does not cover.
- **Taint tracking / DLP across tool hops** — MCPKernel's specialty.
- **MicroVM isolation** — E2B, Blaxel, MCPKernel sandbox tiers.

## Recommended stacks

| Risk profile | Stack |
|--------------|-------|
| Solo dev, low risk | deadpush T0 + T3 (GitHub Action) |
| Unattended local agents | deadpush T1 (`--hardened`) + T3 |
| High-risk / compliance | deadpush T2 (`run --sandbox`) + T3 + Shield for MCP tools |
| CI/cloud agents | deadpush T3 + MCPKernel or E2B sandbox |

## Coexistence with MCP proxies

Route MCP through both layers:

```
Agent → deadpush mcp-proxy → Aperion Shield → postgres/github MCP servers
                ↓
         enforce_content() on repo writes
```

Configure Cursor/Claude to use `deadpush mcp-proxy` as the outer wrapper. See
[guarantees.md](guarantees.md) for what each layer guarantees.

## macOS Endpoint Security (T2-max)

True pre-write syscall deny on macOS requires Apple's System Extension entitlement.
deadpush T2 on macOS uses **Seatbelt** (partial — wrapped subprocess only). Orgs needing
full ES should track the optional `deadpush-es` extension (documented in
[guarantees.md](guarantees.md#g-10-pre-write-syscall-deny-linux-t2-max)).
