"""
Architecture Layer Enforcer — validates import dependencies between layers.

AI agents frequently bypass architectural boundaries, creating direct coupling
between layers that should remain separate (e.g., views importing models directly).
This module enforces user-defined layer rules during scans.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


@dataclass
class LayerRule:
    """A single architectural layer definition."""
    name: str
    paths: list[str]
    allowed_imports: list[str]
    disallowed_imports: list[str] = field(default_factory=list)


@dataclass
class LayerViolation:
    """An import that violates architecture layer rules."""
    file: str
    line: int
    layer: str
    imported_module: str
    rule_type: str  # "disallowed" | "outside_layer"
    description: str
    confidence: float = 0.95


# Default layer rules for common architectures
DEFAULT_LAYERS: list[LayerRule] = [
    LayerRule(
        name="views/presentation",
        paths=["**/views/**", "**/templates/**", "**/pages/**", "**/components/**"],
        allowed_imports=["controllers", "services", "utils", "helpers"],
        disallowed_imports=["models", "db", "database", "repositories"],
    ),
    LayerRule(
        name="controllers/handlers",
        paths=["**/controllers/**", "**/handlers/**", "**/routes/**"],
        allowed_imports=["services", "models", "utils"],
        disallowed_imports=[],
    ),
    LayerRule(
        name="services",
        paths=["**/services/**", "**/use_cases/**", "**/domain/**"],
        allowed_imports=["models", "repositories", "utils", "infrastructure"],
        disallowed_imports=["views", "templates", "ui"],
    ),
    LayerRule(
        name="models/entities",
        paths=["**/models/**", "**/entities/**"],
        allowed_imports=["utils"],
        disallowed_imports=["views", "controllers", "services", "ui"],
    ),
]


class LayerEnforcer:
    """Enforces architectural layer import rules."""

    def __init__(self, layers: list[LayerRule] | None = None):
        self.layers = layers or DEFAULT_LAYERS

    def _get_layer_for_file(self, rel_path: str) -> LayerRule | None:
        """Find which layer a file belongs to based on its path."""
        rp = rel_path.replace("\\", "/")
        for layer in self.layers:
            for pat in layer.paths:
                if fnmatch(rp, pat) or fnmatch(rp, "**/" + pat):
                    return layer
        return None

    def _is_import_allowed(self, import_module: str, layer: LayerRule) -> bool:
        """Check if an import is allowed from the given layer."""
        imp = import_module.lower().replace("_", "").replace("-", "").replace(".", "/")

        # Check explicit disallow list
        for disallowed in layer.disallowed_imports:
            d = disallowed.lower().replace("_", "").replace("-", "")
            if d in imp:
                return False

        # Check allow list — if empty, everything is allowed (catch-all layer)
        if not layer.allowed_imports:
            return True

        for allowed in layer.allowed_imports:
            a = allowed.lower().replace("_", "").replace("-", "")
            if a in imp:
                return True

        # Relative imports from same layer are allowed
        return False

    def analyze_imports(
        self,
        rel_path: str,
        imports: list[tuple[str, int]],  # (module_name, line_number)
    ) -> list[LayerViolation]:
        """Check a file's imports against layer rules."""
        violations: list[LayerViolation] = []
        layer = self._get_layer_for_file(rel_path)
        if layer is None:
            return violations

        for module, line in imports:
            # Skip relative imports
            if module.startswith(".") or module.startswith(".."):
                continue

            if not self._is_import_allowed(module, layer):
                violations.append(LayerViolation(
                    file=rel_path,
                    line=line,
                    layer=layer.name,
                    imported_module=module,
                    rule_type="disallowed",
                    description=f"'{rel_path}' ({layer.name}) imports '{module}' which is outside its allowed dependencies",
                ))

        return violations

    def analyze_batch(self, files: list[Any]) -> list[LayerViolation]:
        """Analyze all source files for layer violations.

        Uses regex import extraction on each file, then checks against layer rules.
        """
        violations: list[LayerViolation] = []

        for f in files:
            if not getattr(f, "is_text", True):
                continue
            rel_path = str(getattr(f, "rel_path", f.path))
            try:
                source = f.path.read_text(encoding="utf-8", errors="ignore")
                imports_list = self.extract_imports_regex(source, f.path.suffix)
                if imports_list:
                    violations.extend(self.analyze_imports(rel_path, imports_list))
            except Exception:
                pass

        return violations

    def extract_imports_regex(self, source: str, suffix: str) -> list[tuple[str, int]]:
        """Extract import statements from source text using regex."""
        imports: list[tuple[str, int]] = []
        lines = source.splitlines()

        if suffix == ".py":
            for i, line in enumerate(lines, 1):
                m = re.match(r'^\s*import\s+(\S+)', line)
                if m:
                    imports.append((m.group(1).split(".")[0], i))
                m = re.match(r'^\s*from\s+(\S+)\s+import', line)
                if m:
                    imports.append((m.group(1).split(".")[0], i))
        elif suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"):
            for i, line in enumerate(lines, 1):
                m = re.match(r'^\s*import\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)\s+from\s+[\'"]([^\'"]+)[\'"]', line)
                if m:
                    mod = m.group(1).split("/")[0]
                    if mod.startswith("."):
                        continue
                    imports.append((mod, i))
                m = re.match(r'^\s*(?:const|let|var)\s+\w+\s*=\s*require\s*\([\'"]([^\'"]+)[\'"]', line)
                if m:
                    mod = m.group(1).split("/")[0]
                    if mod.startswith("."):
                        continue
                    imports.append((mod, i))
        elif suffix == ".go":
            for i, line in enumerate(lines, 1):
                m = re.match(r'^\s*import\s+[\'"]', line)
                if m:
                    continue  # handled by next lines
                m = re.match(r'^\s*[\'"](\S+)[\'"]', line)
                if m:
                    mod = m.group(1).split("/")[0]
                    imports.append((mod, i))
        elif suffix == ".rs":
            for i, line in enumerate(lines, 1):
                m = re.match(r'^\s*use\s+(\S+)', line)
                if m:
                    mod = m.group(1).split("::")[0]
                    imports.append((mod, i))

        return imports
