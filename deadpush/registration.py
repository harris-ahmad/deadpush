"""Registration pattern detection for dead code analysis.

Scans source files for common framework registration patterns that would
make a symbol "alive" even if not directly called in the call graph:
- Decorator registrations (@register, @route, @app.get, etc.)
- Dict/list registrations (plugin registries, handler maps)
- String references that match symbol names in registry contexts
- Framework-specific registries (Django urlpatterns, Flask routes, Click groups)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

_KNOWN_FRAMEWORK_OBJECTS: set[str] = {
    "app", "application", "router", "bp", "blueprint", "api",
    "route", "routes", "site", "server", "web",
}

_DECORATOR_PATTERNS: dict[str, float] = {
    "register": 0.9,
    "route": 0.8,
    "command": 0.8,
    "group": 0.8,
    "click_command": 0.8,
    "click_group": 0.8,
    "app_route": 0.9,
    "router_route": 0.8,
    "bp_route": 0.8,
    "get": 0.7,
    "post": 0.7,
    "put": 0.7,
    "delete": 0.7,
    "patch": 0.7,
    "hookimpl": 0.8,
    "hookspec": 0.7,
    "signal": 0.7,
    "receiver": 0.7,
    "listen": 0.7,
    "on_event": 0.7,
    "task": 0.6,
    "periodic_task": 0.7,
    "background_task": 0.7,
    "entrypoint": 0.8,
    "console_script": 0.8,
    "setuptools_entry": 0.8,
    "expose": 0.7,
    "action": 0.7,
    "filter": 0.6,
    "template_filter": 0.7,
    "context_processor": 0.7,
    "extension": 0.6,
    "middleware": 0.6,
    "errorhandler": 0.7,
    "before_request": 0.6,
    "after_request": 0.6,
    "teardown_request": 0.6,
    "on_message": 0.7,
    "subscribe": 0.7,
    "publish": 0.6,
    "event_handler": 0.7,
    "model": 0.5,
    "table": 0.5,
    "collection": 0.5,
    "resource": 0.5,
    "service": 0.5,
    "provider": 0.5,
    "factory": 0.5,
    "component": 0.5,
    "inject": 0.6,
    "implement": 0.6,
    "override": 0.5,
    "implements": 0.6,
    "dataclass": 0.3,
}

_REGISTRY_VARIABLE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:handlers|routes|urls|urlpatterns|views|controllers|actions|commands|tasks|workers|plugins|extensions|providers|services|maps|mappings|registry|registries|middlewares|filters|signals|events|listeners|consumers|producers|sinks|sources|adapters|ports|drivers|brokers|queues|schedules|jobs|crons|blueprints|modules|resources|endpoints|patterns)"),
    re.compile(r".*_registry$"),
    re.compile(r".*_handlers$"),
    re.compile(r".*_routes$"),
    re.compile(r".*_commands$"),
    re.compile(r".*_tasks$"),
    re.compile(r".*_listeners$"),
    re.compile(r".*_events$"),
    re.compile(r".*_plugins$"),
    re.compile(r".*_services$"),
]

_ENTRY_POINT_FILE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:main|app|server|cli|cmd|entry|index|wsgi|asgi|manage|setup|run|launch|start|boot|bootstrap|kernel|router|routes|urls|views|api|graphql|rest|grpc|consumer|worker|scheduler)\.py$", re.IGNORECASE),
    re.compile(r"(?:manage|setup|wsgi|asgi|cli)\.py$", re.IGNORECASE),
    re.compile(r"__main__\.py$"),
    re.compile(r"conftest\.py$"),
    re.compile(r"__init__\.py$"),
]


class RegistrationDetector:
    """Detect symbols registered via decorators, dict entries, or string refs.

    Scans all source files once and caches results.
    """

    def __init__(self, file_paths: list[Path], repo_root: Path):
        self.repo_root = repo_root
        self._registered: set[str] = set()
        self._scores: dict[str, float] = {}
        self._entry_point_files: set[str] = set()
        self._string_refs: dict[str, list[str]] = {}
        self._custom_patterns: list[str] = []
        self._scan(file_paths)

    def add_custom_pattern(self, pattern: str) -> None:
        self._custom_patterns.append(pattern)

    def _scan(self, file_paths: list[Path]) -> None:
        for fp in file_paths:
            rel = self._rel_path(fp)
            if rel in self._entry_point_files:
                continue
            for pat in _ENTRY_POINT_FILE_PATTERNS:
                if pat.search(fp.name):
                    self._entry_point_files.add(rel)
                    break
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            self._scan_decorators(text, rel)
            self._scan_dict_registrations(text, rel)
            self._scan_string_refs(text, rel)

        for custom in self._custom_patterns:
            try:
                cre = re.compile(custom)
                for fp in file_paths:
                    rel = self._rel_path(fp)
                    try:
                        text = fp.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    for m in cre.finditer(text):
                        name = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                        sym_id = f"{rel}::{name}"
                        self._registered.add(sym_id)
                        self._scores[sym_id] = max(self._scores.get(sym_id, 0), 0.5)
            except re.error:
                pass

    def _rel_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.repo_root))
        except ValueError:
            return str(path)

    def _scan_decorators(self, text: str, rel: str) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for dec in node.decorator_list:
                weight = self._decorator_weight(dec)
                if weight > 0:
                    sym_id = f"{rel}::{node.name}"
                    self._registered.add(sym_id)
                    self._scores[sym_id] = max(self._scores.get(sym_id, 0), weight)

    @staticmethod
    def _namespace_for_attr(dec: ast.expr) -> str | None:
        """Extract the leftmost name from an attribute chain (e.g. app.get → 'app')."""
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
            return RegistrationDetector._namespace_for_attr(dec.func)
        if isinstance(dec, ast.Attribute):
            if isinstance(dec.value, ast.Name):
                return dec.value.id.lower()
            if isinstance(dec.value, ast.Attribute):
                return RegistrationDetector._namespace_for_attr(dec.value)
        return None

    def _decorator_weight(self, dec: ast.expr) -> float:
        if isinstance(dec, (ast.Call, ast.Attribute)):
            if isinstance(dec, ast.Call):
                func = dec.func
            else:
                func = dec
            if isinstance(func, ast.Attribute):
                attr_name = func.attr.lower()
                weight = _DECORATOR_PATTERNS.get(attr_name, 0.0)
                namespace = self._namespace_for_attr(dec)
                if weight > 0 and namespace and namespace not in _KNOWN_FRAMEWORK_OBJECTS:
                    weight *= 0.3
                return weight
            if isinstance(func, ast.Name):
                return _DECORATOR_PATTERNS.get(func.id.lower(), 0.0)
            return 0.0
        if isinstance(dec, ast.Name):
            return _DECORATOR_PATTERNS.get(dec.id.lower(), 0.0)
        return 0.0

    def _scan_dict_registrations(self, text: str, rel: str) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return

        def _var_matches(name: str) -> bool:
            return any(p.search(name) for p in _REGISTRY_VARIABLE_PATTERNS)

        def _scan_value(val: ast.expr) -> None:
            if isinstance(val, ast.Dict):
                for v in val.values:
                    self._check_registry_value(v, rel)
            elif isinstance(val, ast.List):
                for elt in val.elts:
                    self._check_registry_value(elt, rel)
            elif isinstance(val, ast.Call):
                for kw in val.keywords:
                    self._check_registry_value(kw.value, rel)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    var_name = None
                    if isinstance(target, ast.Name):
                        var_name = target.id
                    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        var_name = target.value.id
                    if var_name and _var_matches(var_name):
                        _scan_value(node.value)
                        break
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and _var_matches(node.target.id):
                    _scan_value(node.value)

    def _check_registry_value(self, val: ast.expr, rel: str) -> None:
        if isinstance(val, ast.Name):
            weight = 0.3
            sym_id = f"{rel}::{val.id}"
            self._registered.add(sym_id)
            self._scores[sym_id] = max(self._scores.get(sym_id, 0), weight)
        elif isinstance(val, ast.Attribute):
            weight = 0.25
            sym_id = f"{rel}::{val.attr}"
            self._registered.add(sym_id)
            self._scores[sym_id] = max(self._scores.get(sym_id, 0), weight)
        elif isinstance(val, ast.Constant) and isinstance(val.value, str):
            weight = 0.2
            sym_id = f"{rel}::{val.value}"
            self._registered.add(sym_id)
            self._scores[sym_id] = max(self._scores.get(sym_id, 0), weight)

    def _scan_string_refs(self, text: str, rel: str) -> None:
        for m in re.finditer(r'["\'](\w+)["\']\s*[:=]\s*["\'](\w+)["\']', text):
            key, val = m.group(1), m.group(2)
            for name in (key, val):
                sym_id = f"{rel}::{name}"
                self._registered.add(sym_id)
                current = self._scores.get(sym_id, 0)
                self._scores[sym_id] = max(current, 0.15)

    def score(self, sym_id: str) -> float:
        return self._scores.get(sym_id, 0.0)

    def is_registered(self, sym_id: str) -> bool:
        return sym_id in self._registered

    def is_entry_point_file(self, path: str) -> bool:
        return path in self._entry_point_files

    def get_all_registered(self) -> set[str]:
        return self._registered.copy()
