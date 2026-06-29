"""Minimal terminal output helpers for the guardian CLI."""

from __future__ import annotations

import sys


def is_rich_available() -> bool:
    try:
        import rich  # noqa: F401
        return True
    except ImportError:
        return False


def print_header(title: str, subtitle: str = "") -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    if subtitle:
        print(f"  {subtitle}")
    print(f"{'=' * 60}")


def print_success(msg: str) -> None:
    print(f"✅ {msg}")


def print_warning(msg: str) -> None:
    print(f"⚠️  {msg}", file=sys.stderr)


def print_error(msg: str) -> None:
    print(f"❌ {msg}", file=sys.stderr)


def print_info(msg: str) -> None:
    print(f"ℹ️  {msg}")
