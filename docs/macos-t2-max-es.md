# macOS T2-max: Endpoint Security (optional)

deadpush **T2** on macOS uses Seatbelt (`sandbox-exec`) to confine wrapped agent
subprocesses. This is pip-installable and works today via `deadpush run --sandbox`.

**T2-max** — true kernel-level pre-write deny — requires Apple's **Endpoint Security**
framework via a **System Extension**. This cannot be shipped inside the pip package.

## Why ES is separate

- Apple requires the `com.apple.developer.endpoint-security.system-extension` entitlement
- System Extensions must be notarized and user-approved in System Settings
- ES clients run in kernel callback path — higher bar for OSS distribution

## When you need T2-max

- Compliance requirements for syscall-level write denial (not just subprocess confinement)
- Agents that cannot be wrapped in `deadpush run --sandbox` (e.g. IDE-internal writes)
- Paranoid environments where Seatbelt's subprocess scope is insufficient

## What T2 (Seatbelt) already covers

- Agent subprocesses launched via `deadpush run --sandbox`
- Git operations through the deadpush-git PATH wrapper
- MCP tool writes through `deadpush mcp-proxy`
- IDE native editor writes → watchdog quarantine (reactive, same as Linux T2 without fanotify)

## Entitlement process (orgs)

1. Enroll in Apple Developer Program
2. Request Endpoint Security entitlement from Apple
3. Build `deadpush-es` System Extension (future optional component)
4. Distribute via notarized pkg; users approve in System Settings → Privacy & Security

## Linux equivalent

On Linux, T2-max uses fanotify `FAN_DENY` (see `deadpush/backends/linux.py`), validated
in ubuntu CI via `tests/test_fanotify_deny.py`.

## Recommendation for OSS users

Use **T0 + T3** (local guardian + GitHub required check) as default. Add **T1**
(`--hardened`) for unattended agents. Add **T2** (`run --sandbox`) when the agent
process can be wrapped. Reserve T2-max/ES for orgs with Apple entitlements.

See [guarantees.md](guarantees.md) for the full guarantee catalog.
