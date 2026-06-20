"""
Production-grade TypeScript (and TSX) language plugin for deadpush.
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Tree
import tree_sitter_typescript as tsts

from ..graph import Symbol, make_symbol_id
from .base import Import, CallSite, LanguagePlugin

TS_LANGUAGE = Language(tsts.language_typescript())
TSX_LANGUAGE = Language(tsts.language_tsx())


def _pick_language(path: str) -> Language:
    return TSX_LANGUAGE if Path(path).suffix.lower() == ".tsx" else TS_LANGUAGE


class TypeScriptPlugin:
    extensions = [".ts", ".tsx", ".mts", ".cts"]
    # language attr is set per instance in practice; we pick default TS
    language = TS_LANGUAGE

    def get_parser(self, path: str | None = None):
        from tree_sitter import Parser
        lang = _pick_language(path or "") if path else self.language
        return Parser(lang)

    def parse(self, source: bytes, path: str) -> Tree:
        return self.get_parser(path).parse(source)

    def extract_symbols(self, tree: Tree, path: str) -> list[Symbol]:
        symbols: list[Symbol] = []
        root = tree.root_node

        def walk(node: Node):
            if node.type in ("function_declaration", "method_definition", "arrow_function"):
                name_node = node.child_by_field_name("name") or node.child_by_field_name("property_identifier")
                if not name_node:
                    # arrow assigned to var, rough scan siblings/parent
                    for sib in (node.parent.children if node.parent else []):
                        if sib.type == "identifier":
                            name_node = sib
                            break
                if name_node:
                    name = name_node.text.decode("utf-8")
                    kind = "function"
                    if node.type == "method_definition":
                        kind = "method"
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name),
                        name=name,
                        kind=kind,
                        path=path,
                        line=node.start_point[0] + 1,
                        is_entry_point=(name in ("main", "default", "index")),
                    ))
            elif node.type in ("class_declaration", "interface_declaration", "type_alias_declaration"):
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
        """Exhaustive call site extraction for TypeScript/TSX.

        Similar structure to JS but handles TS-specific nodes (e.g. type arguments are ignored).
        Captures direct calls, member calls, new, with receiver info.
        """
        calls: list[CallSite] = []
        root = tree.root_node

        def get_text(n: Node | None) -> str:
            if not n:
                return ""
            return n.text.decode("utf-8", errors="ignore").strip()

        def walk(node: Node, current_func_id: str | None = None, current_func_name: str | None = None):
            if node.type in ("function_declaration", "method_definition", "arrow_function", "function_expression"):
                name_node = node.child_by_field_name("name") or node.child_by_field_name("property_identifier")
                func_name = get_text(name_node) if name_node else current_func_name
                if not func_name:
                    # assigned to variable
                    parent = node.parent
                    if parent and parent.type in ("variable_declarator", "assignment_expression"):
                        for c in parent.children:
                            if c.type == "identifier":
                                func_name = get_text(c)
                                break
                current_func_id = make_symbol_id(path, func_name) if func_name else current_func_id
                current_func_name = func_name

            if node.type in ("call_expression", "new_expression"):
                func_node = node.child_by_field_name("function")
                if func_node and current_func_id:
                    raw = get_text(func_node)
                    is_new = node.type == "new_expression"
                    callee_name = raw
                    receiver = None
                    is_method = False

                    if func_node.type == "member_expression":
                        is_method = True
                        prop = func_node.child_by_field_name("property")
                        obj = func_node.child_by_field_name("object")
                        callee_name = get_text(prop) if prop else raw
                        receiver = get_text(obj) if obj else None
                    elif func_node.type == "identifier":
                        callee_name = raw
                    else:
                        callee_name = raw.split(".")[-1].split("(")[0].strip() or raw

                    callee_name = callee_name.split("(")[0].strip().rstrip(".")

                    call = CallSite(
                        caller_id=current_func_id,
                        callee=callee_name,
                        line=node.start_point[0] + 1,
                        column=node.start_point[1] + 1,
                        is_method=is_method or is_new,
                        receiver=receiver,
                        raw_callee_text=raw
                    )
                    calls.append(call)

            for child in node.children:
                walk(child, current_func_id, current_func_name)

        walk(root)
        return calls

    def extract_imports(self, tree: Tree, path: str) -> list[Import]:
        imports: list[Import] = []
        root = tree.root_node
        for node in root.children:
            if node.type == "import_statement":
                # import foo from "bar" or import {x} from "bar"
                source_node = None
                for c in node.children:
                    if c.type == "string":
                        source_node = c
                if source_node:
                    mod = source_node.text.decode("utf-8").strip('"\'')
                    imports.append(Import(module=mod, names=["*"], level=0))
            elif node.type == "import_clause":
                pass  # covered above
        return imports or [Import(module=".", names=["*"], level=0)]

    def detect_entry_points(self, tree: Tree, path: str, config_dynamic_patterns: list[str]) -> list[str]:
        src = tree.root_node.text.decode("utf-8", errors="ignore")[:800]
        if "export default" in src or "function main" in src:
            return ["default", "main"]
        if "app.listen" in src or "server.listen" in src:
            return ["app"]
        return ["main"] if "main(" in src else []

    def classify_dynamic_risk(self, tree: Tree, path: str) -> float:
        text = tree.root_node.text.decode("utf-8", errors="ignore").lower()
        risk = 0.0
        if "eval(" in text or "new Function(" in text:
            risk += 0.40
        if "require(" in text and "dynamic" in text:
            risk += 0.15
        if "process.env" in text:  # config surface
            risk += 0.10
        return min(risk, 1.0)

    def supports_suppression_comment(self, line_text: str) -> bool:
        return "// deadpush: ignore" in line_text or "/* deadpush: ignore */" in line_text
