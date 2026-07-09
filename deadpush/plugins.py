"""
Guardrail plugin SDK — extend enforce_content() without forking deadpush.

Register plugins via pyproject.toml entry point group ``deadpush.guardrails``:

    [project.entry-points."deadpush.guardrails"]
    my_rules = "my_package.guardrails:MyPlugin"

Or subclass ``BaseGuardrailPlugin`` and implement ``check()``.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from .config import Config as DeadpushConfig
from .intercept import Violation
from .rules import RuntimeConfig

logger = logging.getLogger("deadpush.plugins")


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Context passed to guardrail plugins during enforcement."""

    repo_root: Path
    config: DeadpushConfig
    runtime: RuntimeConfig | None


@dataclass
class PluginRunReport:
    """Summary of a plugin execution pass."""

    plugin_name: str
    violations: list[Violation] = field(default_factory=list)
    error: str | None = None


class BaseGuardrailPlugin(ABC):
    """Base class for guardrail plugins — subclass and implement ``check()``."""

    name: str
    category: str

    def __init__(self, name: str | None = None, category: str | None = None):
        self.name = name or getattr(self, "name", self.__class__.__name__)
        self.category = category or getattr(self, "category", "plugin")
        err = validate_plugin(self)
        if err:
            raise ValueError(err)

    @abstractmethod
    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        """Inspect *source* at *rel_path* and return violations (may be empty)."""
        raise NotImplementedError


@runtime_checkable
class GuardrailPlugin(Protocol):
    """Structural protocol for guardrail plugins (duck-typing compatible)."""

    name: str
    category: str

    def check(self, rel_path: str, source: str, ctx: CheckContext) -> list[Violation]:
        """Return violations found in *source* for *rel_path* (may be empty)."""
        ...


_PLUGINS: list[GuardrailPlugin] | None = None
_PLUGIN_ERRORS: list[str] = []


def validate_plugin(plugin: GuardrailPlugin) -> str | None:
    """Return an error string if *plugin* is misconfigured, else None."""
    name = getattr(plugin, "name", None)
    category = getattr(plugin, "category", None)
    check = getattr(plugin, "check", None)
    if not name or not isinstance(name, str):
        return "plugin missing non-empty name"
    if not category or not isinstance(category, str):
        return f"plugin {name!r} missing non-empty category"
    if not callable(check):
        return f"plugin {name!r} missing callable check()"
    return None


def _normalize_plugin(obj: object) -> GuardrailPlugin | None:
    if isinstance(obj, type) and issubclass(obj, BaseGuardrailPlugin):
        inst = obj()
    elif isinstance(obj, type):
        inst = obj()
    else:
        inst = obj
    err = validate_plugin(inst)  # type: ignore[arg-type]
    if err:
        _PLUGIN_ERRORS.append(err)
        logger.warning("Skipping invalid guardrail plugin: %s", err)
        return None
    return inst  # type: ignore[return-value]


def _load_entry_point_plugins() -> list[GuardrailPlugin]:
    global _PLUGIN_ERRORS
    _PLUGIN_ERRORS = []
    plugins: list[GuardrailPlugin] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return plugins

    try:
        eps = entry_points(group="deadpush.guardrails")
    except TypeError:
        eps = entry_points().get("deadpush.guardrails", [])

    for ep in eps:
        try:
            loaded = _normalize_plugin(ep.load())
            if loaded is not None:
                plugins.append(loaded)
        except Exception as e:
            msg = f"failed to load plugin {ep.name!r}: {e}"
            _PLUGIN_ERRORS.append(msg)
            logger.warning(msg)
    return plugins


def load_plugins(*, reload: bool = False) -> list[GuardrailPlugin]:
    """Return cached guardrail plugins (entry-point registered)."""
    global _PLUGINS
    if _PLUGINS is None or reload:
        _PLUGINS = _load_entry_point_plugins()
    return list(_PLUGINS)


def plugin_load_errors() -> list[str]:
    """Errors encountered loading entry-point plugins (for diagnostics)."""
    if _PLUGINS is None:
        load_plugins()
    return list(_PLUGIN_ERRORS)


def clear_plugins() -> None:
    """Reset plugin registry (primarily for tests)."""
    global _PLUGINS, _PLUGIN_ERRORS
    _PLUGINS = []
    _PLUGIN_ERRORS = []


def run_plugin(
    plugin: GuardrailPlugin,
    rel_path: str,
    source: str,
    ctx: CheckContext,
) -> PluginRunReport:
    """Run a single plugin with fault isolation."""
    report = PluginRunReport(plugin_name=plugin.name)
    try:
        found = plugin.check(rel_path, source, ctx)
        if not isinstance(found, list):
            report.error = f"plugin {plugin.name!r} check() must return list, got {type(found).__name__}"
            logger.warning(report.error)
            return report
        for v in found:
            if isinstance(v, Violation):
                report.violations.append(v)
            else:
                logger.warning("plugin %r returned non-Violation item: %r", plugin.name, v)
    except Exception as e:
        report.error = str(e)
        logger.exception("plugin %r raised during check()", plugin.name)
    return report


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
        report = run_plugin(plugin, rel_path, source, ctx)
        violations.extend(report.violations)
    return violations


def register_plugin(plugin: GuardrailPlugin) -> None:
    """Register a plugin at runtime (primarily for tests)."""
    err = validate_plugin(plugin)
    if err:
        raise ValueError(err)
    global _PLUGINS
    if _PLUGINS is None:
        _PLUGINS = _load_entry_point_plugins()
    _PLUGINS = list(_PLUGINS) + [plugin]
