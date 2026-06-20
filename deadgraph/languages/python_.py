"""
Production-grade Python language plugin for deadpush.

Uses tree-sitter-python for accurate(ish) structural analysis:
- Functions, async functions, classes, methods
- Basic call site extraction (including attribute calls like obj.method)
- Import / from-import normalization
- Entry point heuristics + dynamic risk (exec/eval etc)
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Tree
import tree_sitter_python as tspython

from ..graph import Symbol, make_symbol_id
from .base import Import, CallSite, LanguagePlugin

PYTHON_LANGUAGE = Language(tspython.language())


class PythonPlugin:
    extensions = [".py", ".pyi", ".pyw"]
    language = PYTHON_LANGUAGE

    def get_parser(self):
        from tree_sitter import Parser
        return Parser(self.language)

    def parse(self, source: bytes, path: str) -> Tree:
        return self.get_parser().parse(source)

    def extract_symbols(self, tree: Tree, path: str) -> list[Symbol]:
        symbols: list[Symbol] = []
        root = tree.root_node
        current_class: str | None = None

        def walk(node: Node):
            nonlocal current_class
            if node.type == "function_definition" or node.type == "async_function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = name_node.text.decode("utf-8")
                    is_method = current_class is not None
                    kind = "method" if is_method else "function"
                    is_entry = name == "main" or (
                        # common patterns
                        "if __name__" in (node.text or b"").decode("utf-8", "ignore")[:200]
                    )
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name),
                        name=name,
                        kind=kind,
                        path=path,
                        line=node.start_point[0] + 1,
                        is_entry_point=is_entry,
                    ))
            elif node.type == "class_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    cname = name_node.text.decode("utf-8")
                    prev_class = current_class
                    current_class = cname
                    symbols.append(Symbol(
                        id=make_symbol_id(path, cname),
                        name=cname,
                        kind="class",
                        path=path,
                        line=node.start_point[0] + 1,
                    ))
                    # walk children with class context
                    for child in node.children:
                        walk(child)
                    current_class = prev_class
                    return  # already recursed

            for child in node.children:
                walk(child)

        walk(root)

        # file symbol (always)
        symbols.append(Symbol(
            id=make_symbol_id(path, Path(path).name),
            name=Path(path).name,
            kind="file",
            path=path,
            line=1
        ))
        return symbols

    def extract_call_sites(self, tree: Tree, path: str) -> list[CallSite]:
        """Exhaustive Python call site extraction.

        Handles:
        - Direct calls, attribute calls (obj.method, self.method, Class.method)
        - Decorated functions, async, nested, lambdas (best effort)
        - Captures receiver for potential resolution.
        Uses tree-sitter fields extensively.
        """
        calls: list[CallSite] = []
        root = tree.root_node

        def get_text(n: Node | None) -> str:
            if not n:
                return ""
            return n.text.decode("utf-8", errors="ignore").strip()

        def walk(node: Node, current_func_id: str | None = None, current_func_name: str | None = None):
            if node.type in ("function_definition", "async_function_definition"):
                name_node = node.child_by_field_name("name")
                func_name = get_text(name_node) if name_node else current_func_name
                current_func_id = make_symbol_id(path, func_name) if func_name else current_func_id
                current_func_name = func_name

            if node.type == "call":
                func_node = node.child_by_field_name("function")
                if func_node and current_func_id:
                    raw = get_text(func_node)
                    callee_name = raw
                    receiver = None
                    is_method = False

                    # attribute call: obj.attr()
                    if func_node.type == "attribute":
                        is_method = True
                        attr_node = func_node.child_by_field_name("attribute")
                        value_node = func_node.child_by_field_name("value")
                        callee_name = get_text(attr_node) if attr_node else raw
                        receiver = get_text(value_node) if value_node else None
                        if receiver in ("self", "cls"):
                            # intra-class, we can enhance later
                            pass
                    elif func_node.type == "identifier":
                        callee_name = raw
                    else:
                        # e.g. (lambda x: x)(1) or complex expr
                        callee_name = raw.split(".")[-1].split("(")[0].strip() or raw

                    callee_name = callee_name.split("(")[0].strip()

                    call = CallSite(
                        caller_id=current_func_id,
                        callee=callee_name,
                        line=node.start_point[0] + 1,
                        column=node.start_point[1] + 1,
                        is_method=is_method,
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
                # import foo, bar as b
                for child in node.children:
                    if child.type == "dotted_name":
                        mod = child.text.decode("utf-8")
                        imports.append(Import(module=mod, names=["*"], level=0))
                    elif child.type == "aliased_import":
                        name_node = child.child_by_field_name("name")
                        if name_node:
                            imports.append(Import(module=name_node.text.decode("utf-8"), names=["*"], level=0))
            elif node.type == "import_from_statement":
                level = 0
                module = ""
                names: list[str] = []
                for child in node.children:
                    if child.type == "dotted_name" or child.type == "identifier":
                        module = child.text.decode("utf-8")
                    elif child.type == "relative_import":
                        level = child.text.count(".")
                    elif child.type == "import_list":
                        for n in child.children:
                            if n.type in ("dotted_name", "identifier"):
                                names.append(n.text.decode("utf-8"))
                            elif n.type == "aliased_import":
                                nn = n.child_by_field_name("name")
                                if nn:
                                    names.append(nn.text.decode("utf-8"))
                if not names:
                    names = ["*"]
                imports.append(Import(module=module or "", names=names, level=level))

        if not imports:
            # implicit "from . import current package" not useful, default to file level
            imports.append(Import(module=Path(path).stem, names=["*"], level=0))
        return imports

    def detect_entry_points(self, tree: Tree, path: str, config_dynamic_patterns: list[str]) -> list[str]:
        source = tree.root_node.text.decode("utf-8", errors="ignore")[:2000]
        entries: list[str] = []
        if "if __name__ == '__main__'" in source or 'if __name__ == "__main__"' in source:
            entries.append("__main__")
        if "def main(" in source:
            entries.append("main")
        # app / cli common
        if any(pat in source for pat in ("app.run", "cli()", "fire.Fire", "Typer")):
            entries.append("app")
        # honor dynamic patterns from config if they look like func names
        for pat in config_dynamic_patterns:
            if "(" not in pat and pat.replace("\\b", "").strip().isidentifier():
                if f"def {pat}" in source or pat in source[:500]:
                    entries.append(pat)
        return list(dict.fromkeys(entries)) or (["main"] if "def main" in source else [])

    def classify_dynamic_risk(self, tree: Tree, path: str) -> float:
        text = tree.root_node.text.decode("utf-8", errors="ignore").lower()
        risk = 0.0
        dangerous = ["exec(", "eval(", "__import__(", "compile(", "globals()[", "locals()["]
        for d in dangerous:
            if d in text:
                risk += 0.30
        if "importlib" in text and "import" in text:
            risk += 0.15
        if "subprocess" in text or "os.system" in text:
            risk += 0.20
        return min(risk, 1.0)

    def supports_suppression_comment(self, line_text: str) -> bool:
        return "# deadpush: ignore" in line_text or "# noqa: deadpush" in line_text
