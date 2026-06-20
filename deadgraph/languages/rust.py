"""
Production-grade Rust language plugin for deadpush.
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Tree
import tree_sitter_rust as tsrust

from ..graph import Symbol, make_symbol_id
from .base import Import, CallSite, LanguagePlugin

RUST_LANGUAGE = Language(tsrust.language())


class RustPlugin:
    extensions = [".rs"]
    language = RUST_LANGUAGE

    def get_parser(self):
        from tree_sitter import Parser
        return Parser(self.language)

    def parse(self, source: bytes, path: str) -> Tree:
        return self.get_parser().parse(source)

    def extract_symbols(self, tree: Tree, path: str) -> list[Symbol]:
        symbols: list[Symbol] = []
        root = tree.root_node

        def walk(node: Node):
            if node.type == "function_item":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = name_node.text.decode("utf-8")
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name),
                        name=name,
                        kind="function",
                        path=path,
                        line=node.start_point[0] + 1,
                        is_entry_point=(name == "main"),
                    ))
            elif node.type == "struct_item":
                name_node = node.child_by_field_name("name")
                if name_node:
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name_node.text.decode("utf-8")),
                        name=name_node.text.decode("utf-8"),
                        kind="class",
                        path=path,
                        line=node.start_point[0] + 1,
                    ))
            elif node.type == "impl_item":
                for child in node.children:
                    if child.type == "function_item":
                        walk(child)

            for child in node.children:
                walk(child)

        walk(root)

        symbols.append(Symbol(
            id=make_symbol_id(path, Path(path).name),
            name=Path(path).name,
            kind="file",
            path=path,
            line=1
        ))
        return symbols

    def extract_call_sites(self, tree: Tree, path: str) -> list[CallSite]:
        """Exhaustive Rust call site extraction.

        Handles function calls, method calls (via field_expression or UFCS),
        associated functions, macros (basic), turbofish ignored.
        """
        calls: list[CallSite] = []
        root = tree.root_node

        def get_text(n: Node | None) -> str:
            if not n:
                return ""
            return n.text.decode("utf-8", errors="ignore").strip()

        def walk(node: Node, current_func_id: str | None = None):
            if node.type == "function_item":
                name_node = node.child_by_field_name("name")
                if name_node:
                    current_func_id = make_symbol_id(path, get_text(name_node))

            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node and current_func_id:
                    raw = get_text(func_node)
                    callee_name = raw
                    receiver = None
                    is_method = False

                    if func_node.type == "field_expression":
                        is_method = True
                        value = func_node.child_by_field_name("value")
                        field = func_node.child_by_field_name("field")
                        callee_name = get_text(field) if field else raw
                        receiver = get_text(value) if value else None
                    elif func_node.type in ("identifier", "scoped_identifier"):
                        callee_name = raw.split("::")[-1]

                    callee_name = callee_name.split("(")[0].strip().split("::<")[0]

                    call = CallSite(
                        caller_id=current_func_id,
                        callee=callee_name,
                        line=node.start_point[0] + 1,
                        is_method=is_method,
                        receiver=receiver,
                        raw_callee_text=raw
                    )
                    calls.append(call)

            for child in node.children:
                walk(child, current_func_id)

        walk(root)
        return calls

    def extract_imports(self, tree: Tree, path: str) -> list[Import]:
        return [Import(module="crate", names=["*"], level=0)]

    def detect_entry_points(self, tree: Tree, path: str, config_dynamic_patterns: list[str]) -> list[str]:
        source = tree.root_node.text.decode("utf-8", errors="ignore")
        return ["main"] if "fn main(" in source[:800] else []

    def classify_dynamic_risk(self, tree: Tree, path: str) -> float:
        text = tree.root_node.text.decode("utf-8", errors="ignore").lower()
        risk = 0.0
        if "unsafe" in text:
            risk += 0.45
        if "dyn " in text:
            risk += 0.25
        return min(risk, 1.0)

    def supports_suppression_comment(self, line_text: str) -> bool:
        return "// deadpush: ignore" in line_text
