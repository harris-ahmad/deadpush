"""
Java language plugin for deadpush (added as extra language support).

Covers .java (and basic .kt for kotlin interop surface if needed, but focused on java).
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Tree
import tree_sitter_java as tsjava

from ..graph import Symbol, make_symbol_id
from .base import Import, CallSite, LanguagePlugin

JAVA_LANGUAGE = Language(tsjava.language())


class JavaPlugin:
    extensions = [".java"]
    language = JAVA_LANGUAGE

    def get_parser(self):
        from tree_sitter import Parser
        return Parser(self.language)

    def parse(self, source: bytes, path: str) -> Tree:
        return self.get_parser().parse(source)

    def extract_symbols(self, tree: Tree, path: str) -> list[Symbol]:
        symbols: list[Symbol] = []
        root = tree.root_node

        def walk(node: Node):
            if node.type == "method_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = name_node.text.decode("utf-8")
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name),
                        name=name,
                        kind="method",
                        path=path,
                        line=node.start_point[0] + 1,
                        is_entry_point=(name == "main"),
                    ))
            elif node.type == "class_declaration" or node.type == "interface_declaration" or node.type == "record_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name_node.text.decode("utf-8")),
                        name=name_node.text.decode("utf-8"),
                        kind="class",
                        path=path,
                        line=node.start_point[0] + 1,
                    ))
            elif node.type == "constructor_declaration":
                # treat ctors as special methods
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = name_node.text.decode("utf-8") + ".<init>"
                    symbols.append(Symbol(
                        id=make_symbol_id(path, name),
                        name=name,
                        kind="method",
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
        """Exhaustive Java call site extraction.

        Uses method_invocation, constructor calls (object_creation_expression),
        captures receivers for methods.
        """
        calls: list[CallSite] = []
        root = tree.root_node

        def get_text(n: Node | None) -> str:
            if not n:
                return ""
            return n.text.decode("utf-8", errors="ignore").strip()

        def walk(node: Node, current_func_id: str | None = None):
            if node.type == "method_declaration":
                nm = node.child_by_field_name("name")
                if nm:
                    current_func_id = make_symbol_id(path, get_text(nm))

            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                if name_node and current_func_id:
                    raw = get_text(name_node)
                    callee_name = raw
                    receiver = None
                    is_method = True

                    # Look for object/method pattern in parent or siblings
                    # In tree-sitter-java, method_invocation has 'object' field for receiver
                    obj = node.child_by_field_name("object")
                    if obj:
                        receiver = get_text(obj)
                        # name is the method name

                    callee_name = callee_name.split("(")[0]

                    call = CallSite(
                        caller_id=current_func_id,
                        callee=callee_name,
                        line=node.start_point[0] + 1,
                        is_method=is_method,
                        receiver=receiver,
                        raw_callee_text=raw
                    )
                    calls.append(call)

            # Also constructor calls
            if node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node and current_func_id:
                    raw = get_text(type_node)
                    call = CallSite(
                        caller_id=current_func_id,
                        callee=raw,
                        line=node.start_point[0] + 1,
                        is_method=True,  # kind of
                        receiver=None,
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
                # import com.foo.Bar; or import static ...
                for c in node.children:
                    if c.type == "scoped_identifier" or c.type == "identifier":
                        mod = c.text.decode("utf-8")
                        imports.append(Import(module=mod, names=["*"], level=0))
        return imports or [Import(module="current", names=["*"], level=0)]

    def detect_entry_points(self, tree: Tree, path: str, config_dynamic_patterns: list[str]) -> list[str]:
        src = tree.root_node.text.decode("utf-8", errors="ignore")
        if "public static void main(String" in src or "public static void main(String[]" in src:
            return ["main"]
        if "SpringApplication.run" in src or "@SpringBootApplication" in src:
            return ["SpringBoot"]
        return ["main"] if "void main" in src[:500] else []

    def classify_dynamic_risk(self, tree: Tree, path: str) -> float:
        text = tree.root_node.text.decode("utf-8", errors="ignore").lower()
        risk = 0.0
        if "reflection" in text or "class.forname" in text:
            risk += 0.30
        if "system." in text and ("exec" in text or "load" in text):
            risk += 0.25
        if "native " in text:
            risk += 0.15
        return min(risk, 1.0)

    def supports_suppression_comment(self, line_text: str) -> bool:
        return "// deadpush: ignore" in line_text or "/* deadpush: ignore */" in line_text
