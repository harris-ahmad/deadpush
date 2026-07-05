"""Detect git configuration escapes that bypass hooks in sandbox sessions."""

from __future__ import annotations

# Git -c / --config keys that bypass deadpush hook enforcement.
_BLOCKED_CONFIG_KEYS = (
    "core.hookspath",
    "init.templatedir",
)


def detect_git_config_escape(args: list[str]) -> str | None:
    """Return a human-readable reason if *args* attempt a hook bypass, else None."""
    if not args:
        return None

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-c", "--config") and i + 1 < len(args):
            reason = _blocked_config_value(args[i + 1])
            if reason:
                return reason
            i += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            reason = _blocked_config_value(arg[2:])
            if reason:
                return reason
        lowered = arg.lower()
        for key in _BLOCKED_CONFIG_KEYS:
            if key in lowered.replace("_", ""):
                return f"blocked git config escape: {arg}"
        i += 1
    return None


def _blocked_config_value(value: str) -> str | None:
    key = value.split("=", 1)[0].strip().lower()
    for blocked in _BLOCKED_CONFIG_KEYS:
        if key == blocked or key.replace("_", "") == blocked.replace("_", ""):
            return f"blocked git config escape: {value}"
    return None
