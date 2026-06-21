"""
deadpush language plugin registry.

This central module makes adding + integrating new languages seamless:

- All plugins are registered here (lazily imported to keep startup fast and
  avoid requiring every tree-sitter-foo even if lang disabled).
- get_enabled_plugins(config) returns only the active ones for the run.
- Helpers for extensions, names, etc. are used by crawler, watch, ui etc.
- To add a new language:
    1. pip add the tree-sitter-xxx dep + update pyproject.toml
    2. Implement xxx.py following the LanguagePlugin protocol (see base.py)
    3. Add to LANGUAGE_REGISTRY below
    4. (optional) update default list in config.py

Plugins are structural (no inheritance required) but should implement the
methods in base.LanguagePlugin .
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from .base import Import, CallSite, LanguagePlugin

if TYPE_CHECKING:
    from ..config import Config

# ----------------------------------------------------------------------------
# Registry: name -> (import_path, class_name)
# Keep sorted for determinism. Lazy to support partial installs.
# ----------------------------------------------------------------------------
LANGUAGE_REGISTRY: dict[str, tuple[str, str]] = {
    "python": (".python_", "PythonPlugin"),
    "typescript": (".typescript", "TypeScriptPlugin"),
    "javascript": (".javascript", "JavaScriptPlugin"),
    "go": (".go_", "GoPlugin"),
    "rust": (".rust", "RustPlugin"),
    "cpp": (".cpp", "CppPlugin"),
    "java": (".java", "JavaPlugin"),
}

# Common aliases users / config may use
LANGUAGE_ALIASES: dict[str, str] = {
    "py": "python",
    "ts": "typescript",
    "tsx": "typescript",
    "js": "javascript",
    "jsx": "javascript",
    "c++": "cpp",
    "cxx": "cpp",
    "cc": "cpp",
    "c": "cpp",  # treat C as cpp plugin for simplicity (overlapping extensions)
}


def _load_plugin_class(module_rel: str, class_name: str):
    """Import and return the plugin class (lazy)."""
    from importlib import import_module
    mod = import_module(module_rel, package=__name__)
    return getattr(mod, class_name)


def get_plugin(name: str) -> LanguagePlugin | None:
    """Return an instantiated plugin for a canonical language name, or None."""
    canonical = LANGUAGE_ALIASES.get(name.lower(), name.lower())
    if canonical not in LANGUAGE_REGISTRY:
        return None
    mod_rel, cls_name = LANGUAGE_REGISTRY[canonical]
    try:
        cls = _load_plugin_class(mod_rel, cls_name)
        return cls()
    except Exception as e:
        # Fail gracefully so one bad language parser doesn't kill the run
        import warnings
        warnings.warn(f"Failed to load language plugin {name!r}: {e}")
        return None


def get_enabled_plugins(config: "Config") -> dict[str, LanguagePlugin]:
    """Return {lang_name: plugin_instance, ...} for languages enabled in config."""
    plugins: dict[str, LanguagePlugin] = {}
    for name in config.languages:
        canonical = LANGUAGE_ALIASES.get(name.lower(), name.lower())
        if canonical in plugins:
            continue
        plug = get_plugin(canonical)
        if plug:
            plugins[canonical] = plug
    # Also respect aliases that map into enabled set
    for alias, canon in LANGUAGE_ALIASES.items():
        if config.is_language_enabled(alias) and canon not in plugins:
            plug = get_plugin(canon)
            if plug:
                plugins[canon] = plug
    return plugins


def get_all_plugins() -> dict[str, LanguagePlugin]:
    """Return all known plugins (best effort; some may fail to import if deps missing)."""
    plugins = {}
    for name in list(LANGUAGE_REGISTRY.keys()):
        p = get_plugin(name)
        if p:
            plugins[name] = p
    return plugins


def get_all_extensions() -> set[str]:
    """Union of all file extensions known to any plugin (for filtering etc)."""
    exts: set[str] = set()
    for name in LANGUAGE_REGISTRY:
        try:
            p = get_plugin(name)
            if p and hasattr(p, "extensions"):
                exts.update(p.extensions)
        except Exception:
            pass
    return exts


def get_language_for_file(path: str | Path, plugins: dict[str, LanguagePlugin] | None = None) -> tuple[str, LanguagePlugin] | None:
    """Given a path, return (lang_name, plugin) that claims its suffix, or None."""
    suffix = Path(path).suffix.lower()
    plugs = plugins or get_all_plugins()
    for lang, plug in plugs.items():
        if hasattr(plug, "extensions") and suffix in plug.extensions:
            return lang, plug
    return None


# Re-export for convenience
__all__ = [
    "Import",
    "CallSite",
    "LanguagePlugin",
    "LANGUAGE_REGISTRY",
    "get_plugin",
    "get_enabled_plugins",
    "get_all_plugins",
    "get_all_extensions",
    "get_language_for_file",
]
