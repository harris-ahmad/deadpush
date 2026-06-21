"""
JavaScript (and JSX) language plugin for deadpush.

Covers .js .jsx .mjs .cjs .vue script sections etc via extension match.
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Tree
import tree_sitter_javascript as tsjs

from ..graph import Symbol, make_symbol_id
from .base import Import, CallSite, LanguagePlugin

JS_LANGUAGE = Language(tsjs.language())


class JavaScriptPlugin:
    extensions = [".js", ".jsx", ".mjs", ".cjs", ".es6"]
    language = JS_LANGUAGE

    def get_parser(self):
        from tree_sitter import Parser
        return Parser(self.language)

    def parse(self, source: bytes, path: str) -> Tree:
        return self.get_parser().parse(source)

    def extract_symbols(self, tree: Tree, path: str) -> list[Symbol]:
        symbols: list[Symbol] = []
        root = tree.root_node

        def walk(node: Node):
            if node.type in ("function_declaration", "method_definition", "generator_function_declaration"):
                name_node = node.child_by_field_name("name") or node.child_by_field_name("property_identifier")
                if name_node:
                    name = name_node.text.decode("utf-8")
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name),
                        name=name,
                        kind="function" if "method" not in node.type else "method",
                        path=path,
                        line=node.start_point[0] + 1,
                        is_entry_point=name in ("main", "index", "default"),
                    ))
            elif node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name_node.text.decode("utf-8")),
                        name=name_node.text.decode("utf-8"),
                        kind="class",
                        path=path,
                        line=node.start_point[0] + 1,
                    ))
            elif node.type == "variable_declarator":
                # catch const foo = () => {} or function expr assigned
                name_node = node.child_by_field_name("name")
                val = node.child_by_field_name("value")
                if name_node and val and val.type in ("arrow_function", "function_expression"):
                    name = name_node.text.decode("utf-8")
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name),
                        name=name,
                        kind="function",
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
        """Exhaustive call site extraction for JavaScript/JSX.

        Captures:
        - Direct calls: foo()
        - Method calls: obj.method(), this.foo(), Model.find()
        - Arrow functions, methods, constructors, IIFE, etc.
        - Basic receiver tracking for resolution.
        Returns structured CallSite objects for high-quality call graph.
        """
        calls: list[CallSite] = []
        root = tree.root_node

        def get_text(n: Node | None) -> str:
            if not n:
                return ""
            return n.text.decode("utf-8", errors="ignore").strip()

        def walk(node: Node, current_func_id: str | None = None, current_func_name: str | None = None):
            # Track containing function for caller attribution
            if node.type in ("function_declaration", "method_definition", "arrow_function", "function_expression", "generator_function_declaration"):
                name_node = node.child_by_field_name("name") or node.child_by_field_name("property_identifier")
                func_name = get_text(name_node) if name_node else current_func_name
                if not func_name and node.parent and node.parent.type in ("variable_declarator", "assignment_expression"):
                    # e.g. const foo = () => {} or foo = function() {}
                    for sib in (node.parent.children if node.parent else []):
                        if sib.type in ("identifier", "property_identifier"):
                            func_name = get_text(sib)
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

                    # Analyze structure for better resolution
                    if func_node.type == "member_expression":
                        is_method = True
                        prop = func_node.child_by_field_name("property")
                        obj = func_node.child_by_field_name("object")
                        callee_name = get_text(prop) if prop else raw
                        receiver = get_text(obj) if obj else None
                        if receiver in ("this", "self"):
                            # Could resolve to current class if we tracked, for now keep receiver
                            pass
                    elif func_node.type == "identifier":
                        callee_name = raw
                    else:
                        # complex like (foo.bar)() or foo()() etc. - keep raw for fallback
                        callee_name = raw.split(".")[-1].split("(")[0].strip() or raw

                    # Clean common noise
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
                for c in node.children:
                    if c.type == "string":
                        mod = c.text.decode("utf-8").strip('"\'')
                        imports.append(Import(module=mod, names=["*"], level=0))
            elif node.type == "call_expression":
                # require("foo")
                fn = node.child_by_field_name("function")
                if fn and fn.text.decode("utf-8") == "require":
                    args = node.child_by_field_name("arguments")
                    if args:
                        for a in args.children:
                            if a.type == "string":
                                mod = a.text.decode("utf-8").strip('"\'')
                                imports.append(Import(module=mod, names=["*"], level=0))
        return imports or [Import(module=".", names=["*"], level=0)]

    def detect_entry_points(self, tree: Tree, path: str, config_dynamic_patterns: list[str]) -> list[str]:
        src = tree.root_node.text.decode("utf-8", errors="ignore")[:600]
        if "module.exports" in src or "export default" in src:
            return ["default"]
        if "function main" in src or ".listen(" in src:
            return ["main", "app"]
        return ["main"] if "main(" in src else []

    def classify_dynamic_risk(self, tree: Tree, path: str) -> float:
        text = tree.root_node.text.decode("utf-8", errors="ignore").lower()
        risk = 0.0
        if "eval(" in text or "new Function(" in text:
            risk += 0.35
        if "vm." in text or "child_process" in text:
            risk += 0.25
        return min(risk, 1.0)

    def supports_suppression_comment(self, line_text: str) -> bool:
        return "// deadpush: ignore" in line_text or "/* deadpush: ignore */" in line_text
