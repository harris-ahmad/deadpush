# deadpush-es (optional — org distribution)

**Status:** Placeholder for organizations with Apple Endpoint Security entitlements.

This is **not** part of the pip-installable `deadpush` package. Apple requires a
notarized System Extension with the
`com.apple.developer.endpoint-security.system-extension` entitlement.

## What it will provide

- macOS **T2-max**: kernel-level pre-write deny via Endpoint Security
- Coverage for writes that Seatbelt cannot confine (e.g. some IDE-internal paths)
- Integration with deadpush guardian audit trail and GPC

## What to use today (OSS)

| Tier | Command |
|------|---------|
| T0 + T3 | `deadpush protect` + GitHub required check |
| T1 | `deadpush protect --hardened` |
| T2 | `deadpush run --sandbox -- …` (Seatbelt) |
| MCP | `deadpush configure all` + `mcp-proxy` |

See [docs/macos-t2-max-es.md](../../docs/macos-t2-max-es.md) for the entitlement process.

## Building (future)

When implemented, this package will contain:

- Swift ES client + XPC helper
- Notarized `.pkg` installer
- Registration hook for guardian `deadpush doctor`

Contact the maintainer for early access if your org already holds ES entitlements.
