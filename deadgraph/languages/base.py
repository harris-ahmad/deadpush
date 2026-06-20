"""
Base types and protocol for deadpush language plugins.

Defines the common Import representation and LanguagePlugin structural interface
used by all language backends (rust, cpp, python, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class Import:
    """Normalized representation of an import/use statement.

    - module: the module/package being imported (e.g. "std::io" or "crate")
    - names: imported names or ["*"] for glob
    - level: 0 for absolute, >0 indicates relative import depth (Python style)
    """
    module: str
    names: list[str]
    level: int = 0


@dataclass(frozen=True, slots=True)
class CallSite:
    """Structured representation of a function/method call site.

    This enables much better call-graph construction than raw text matching.
    """
    caller_id: str          # symbol id of the containing function/method
    callee: str             # best-effort name of the callee (e.g. "findOne", "db.findOne")
    line: int
    column: int = 0
    is_method: bool = False
    receiver: str | None = None   # e.g. "db", "this", "Model" for method calls
    raw_callee_text: str = ""     # original text for fallback


@runtime_checkable
class LanguagePlugin(Protocol):
    """Structural protocol for language plugins.

    Plugins are not required to inherit; they only need to provide the attributes
    and methods with matching signatures. This enables static checking and
    optional runtime isinstance checks.
    """

    extensions: list[str]
    language: Any  # tree_sitter.Language

    def get_parser(self) -> Any: ...

    def parse(self, source: bytes, path: str) -> Any: ...

    def extract_symbols(self, tree: Any, path: str) -> list[Any]: ...

    def extract_call_sites(self, tree: Any, path: str) -> list[CallSite]: ...

    def extract_imports(self, tree: Any, path: str) -> list[Import]: ...

    def detect_entry_points(
        self, tree: Any, path: str, config_dynamic_patterns: list[str]
    ) -> list[str]: ...

    def classify_dynamic_risk(self, tree: Any, path: str) -> float: ...

    def supports_suppression_comment(self, line_text: str) -> bool: ...
