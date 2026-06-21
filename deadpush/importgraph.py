"""Cross-file import analysis for dead code detection.

Builds an import map across all Python source files and provides
efficient queries for import counts and string references.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


class ImportAnalyzer:
    """Analyze cross-file imports and string references for dead code scoring."""

    def __init__(self, file_paths: list[Path], repo_root: Path):
        self.repo_root = repo_root
        self._imports: dict[str, list[str]] = defaultdict(
            list
        )  # imported_name -> [file_paths]
        self._string_refs: dict[str, dict[str, list[int]]] = defaultdict(
            lambda: defaultdict(list)
        )  # name -> file_path -> [line_numbers]
        self._exclude_files: set[str] = set()
        self._build(file_paths)

    def _rel(self, path: Path | str) -> str:
        p = Path(path) if isinstance(path, str) else path
        try:
            return str(p.relative_to(self.repo_root))
        except ValueError:
            return str(p)

    def _build(self, file_paths: list[Path]) -> None:
        for fp in file_paths:
            if fp.suffix != ".py":
                continue
            rel = self._rel(fp)
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            self._extract_imports(text, rel)
            self._extract_string_refs(text, rel, fp)

    def _extract_imports(self, text: str, rel: str) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self._imports[name].append(rel)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self._imports[name].append(rel)

    def _extract_string_refs(self, text: str, rel: str, fp: Path) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.strip()
                if val.isidentifier() and len(val) > 1:
                    self._string_refs[val][rel].append(node.lineno)

    def count_external_imports(self, name: str, exclude_path: str) -> int:
        """Count files (excluding the definition file) that import this name."""
        exclude_rel = self._rel(exclude_path)
        files = self._imports.get(name, [])
        return len([f for f in files if f != exclude_rel])

    def count_string_references(self, name: str, exclude_path: str) -> int:
        """Count string literal occurrences of name outside its own file."""
        exclude_rel = self._rel(exclude_path)
        total = 0
        for file_path, line_nums in self._string_refs.get(name, {}).items():
            if file_path != exclude_rel:
                total += len(line_nums)
        return total

    def get_importing_files(self, name: str) -> list[str]:
        """Get list of files (relative paths) that import the given name."""
        return list(self._imports.get(name, []))

    def get_all_imported_names(self) -> set[str]:
        return set(self._imports.keys())
