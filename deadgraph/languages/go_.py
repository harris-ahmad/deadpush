"""
Production-grade Go language plugin for deadpush.
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Tree
import tree_sitter_go as tsgo

from ..graph import Symbol, make_symbol_id
from .base import Import, CallSite, LanguagePlugin

GO_LANGUAGE = Language(tsgo.language())


class GoPlugin:
    extensions = [".go"]
    language = GO_LANGUAGE

    def get_parser(self):
        from tree_sitter import Parser
        return Parser(self.language)

    def parse(self, source: bytes, path: str) -> Tree:
        return self.get_parser().parse(source)

    def extract_symbols(self, tree: Tree, path: str) -> list[Symbol]:
        symbols: list[Symbol] = []
        root = tree.root_node

        def walk(node: Node):
            if node.type == "function_declaration":
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
            elif node.type == "method_declaration":
                # receiver + name
                name_node = node.child_by_field_name("name")
                recv = node.child_by_field_name("receiver")
                if name_node:
                    name = name_node.text.decode("utf-8")
                    # include receiver type in name for uniqueness e.g. (*Foo).Bar
                    recv_text = ""
                    if recv:
                        for c in recv.children:
                            if c.type in ("type_identifier", "pointer_type"):
                                recv_text = c.text.decode("utf-8", "ignore").strip("*() ")
                                break
                    full = f"{recv_text}.{name}" if recv_text else name
                    symbols.append(Symbol(
                        id=make_symbol_id(path, full),
                        name=full,
                        kind="method",
                        path=path,
                        line=node.start_point[0] + 1,
                    ))
            elif node.type == "type_spec":
                # struct or interface
                name_node = node.child_by_field_name("name")
                if name_node:
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name_node.text.decode("utf-8")),
                        name=name_node.text.decode("utf-8"),
                        kind="class",
                        path=path,
                        line=node.start_point[0] + 1,
                    ))

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
        """Exhaustive Go call extraction.

        Handles function calls, method calls on receivers (value/pointer),
        qualified identifiers (pkg.Func), etc.
        """
        calls: list[CallSite] = []
        root = tree.root_node

        def get_text(n: Node | None) -> str:
            if not n:
                return ""
            return n.text.decode("utf-8", errors="ignore").strip()

        def walk(node: Node, current_func_id: str | None = None):
            if node.type in ("function_declaration", "method_declaration"):
                name_node = node.child_by_field_name("name")
                func_name = get_text(name_node) if name_node else None
                if func_name:
                    current_func_id = make_symbol_id(path, func_name)

            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node and current_func_id:
                    raw = get_text(func_node)
                    callee_name = raw
                    receiver = None
                    is_method = False

                    if func_node.type == "selector_expression":
                        is_method = True
                        sel = func_node.child_by_field_name("field")
                        x = func_node.child_by_field_name("operand")
                        callee_name = get_text(sel) if sel else raw
                        receiver = get_text(x) if x else None
                    elif func_node.type == "identifier":
                        callee_name = raw

                    callee_name = callee_name.split("(")[0].strip()

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
        imports: list[Import] = []
        root = tree.root_node
        for node in root.children:
            if node.type == "import_declaration":
                for spec in node.children:
                    if spec.type == "import_spec":
                        path_node = spec.child_by_field_name("path") or spec
                        mod = path_node.text.decode("utf-8").strip('"')
                        imports.append(Import(module=mod, names=["*"], level=0))
        return imports or [Import(module="main", names=["*"], level=0)]

    def detect_entry_points(self, tree: Tree, path: str, config_dynamic_patterns: list[str]) -> list[str]:
        src = tree.root_node.text.decode("utf-8", errors="ignore")
        if 'package main' in src and 'func main()' in src:
            return ["main"]
        return ["main"] if "func main(" in src[:400] else []

    def classify_dynamic_risk(self, tree: Tree, path: str) -> float:
        text = tree.root_node.text.decode("utf-8", errors="ignore").lower()
        risk = 0.0
        if "unsafe" in text or "reflect." in text:
            risk += 0.35
        if "go " in text and "func" in text:  # goroutines
            risk += 0.15
        return min(risk, 1.0)

    def supports_suppression_comment(self, line_text: str) -> bool:
        return "// deadpush: ignore" in line_text
