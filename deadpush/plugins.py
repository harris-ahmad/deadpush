"""
Guardrail plugin SDK — extend enforce_content() without forking deadpush.

Register plugins via pyproject.toml entry point group ``deadpush.guardrails``:

    [project.entry-points."deadpush.guardrails"]
    my_rules = "my_package.guardrails:MyPlugin"
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .config import Config as DeadpushConfig
from .intercept import Violation
from .rules import RuntimeConfig


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Context passed to guardrail plugins during enforcement."""

    repo_root: Path
    config: DeadpushConfig
    runtime: RuntimeConfig | None


@runtime_checkable
class GuardrailPlugin(Protocol):
    """Protocol for third-party guardrail plugins."""

    name: str
    category: str

    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        """Return violations found in *source* for *rel_path* (may be empty)."""
        ...


_PLUGINS: list[GuardrailPlugin] | None = None


def _load_entry_point_plugins() -> list[GuardrailPlugin]:
    plugins: list[GuardrailPlugin] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return plugins

    try:
        eps = entry_points(group="deadpush.guardrails")
    except TypeError:
        # Python 3.11 fallback
        eps = entry_points().get("deadpush.guardrails", [])

    for ep in eps:
        try:
            obj = ep.load()
            if isinstance(obj, type):
                inst = obj()
            else:
                inst = obj
            if isinstance(inst, GuardrailPlugin) or (
                hasattr(inst, "name") and hasattr(inst, "category") and callable(getattr(inst, "check", None))
            ):
                plugins.append(inst)  # type: ignore[arg-type]
        except Exception:
            continue
    return plugins


def load_plugins(*, reload: bool = False) -> list[GuardrailPlugin]:
    """Return cached guardrail plugins (entry-point registered)."""
    global _PLUGINS
    if _PLUGINS is None or reload:
        _PLUGINS = _load_entry_point_plugins()
    return _PLUGINS


def run_plugins(
    rel_path: str,
    source: str,
    config: DeadpushConfig,
    runtime: RuntimeConfig | None,
) -> list[Violation]:
    """Run all registered plugins and collect violations."""
    ctx = CheckContext(repo_root=config.repo_root, config=config, runtime=runtime)
    violations: list[Violation] = []
    for plugin in load_plugins():
        level = runtime.get_guardrail_level(plugin.category) if runtime else "block"
        if level == "off":
            continue
        try:
            found = plugin.check(rel_path, source, ctx)
            violations.extend(found)
        except Exception:
            continue
    return violations


def register_plugin(plugin: GuardrailPlugin) -> None:
    """Register a plugin at runtime (primarily for tests)."""
    global _PLUGINS
    if _PLUGINS is None:
        _PLUGINS = _load_entry_point_plugins()
    _PLUGINS = list(_PLUGINS) + [plugin]
