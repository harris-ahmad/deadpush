"""Tests for the Architecture Layer Enforcer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush.layers import LayerEnforcer, LayerRule


class TestLayerEnforcer:
    def _make_enforcer(self):
        return LayerEnforcer([
            LayerRule("views", ["**/views/**", "**/pages/**"], ["services", "utils"], ["models"]),
            LayerRule("services", ["**/services/**"], ["models", "utils"], ["views"]),
            LayerRule("models", ["**/models/**"], ["utils"], ["views", "services"]),
        ])

    def test_get_layer_by_path(self):
        e = self._make_enforcer()
        assert e._get_layer_for_file("src/views/page.py").name == "views"
        assert e._get_layer_for_file("src/services/user.py").name == "services"
        assert e._get_layer_for_file("src/models/user.py").name == "models"

    def test_unmatched_file(self):
        e = self._make_enforcer()
        assert e._get_layer_for_file("src/utils/helper.py") is None

    def test_disallowed_import_detected(self):
        e = self._make_enforcer()
        vs = e.analyze_imports("src/views/page.py", [("models", 5)])
        assert len(vs) == 1
        assert vs[0].layer == "views"
        assert vs[0].imported_module == "models"
        assert vs[0].rule_type == "disallowed"

    def test_allowed_import(self):
        e = self._make_enforcer()
        vs = e.analyze_imports("src/views/page.py", [("services", 3)])
        assert len(vs) == 0

    def test_no_layer_no_violations(self):
        e = self._make_enforcer()
        vs = e.analyze_imports("src/utils/helper.py", [("models", 1)])
        assert len(vs) == 0

    def test_relative_import_skipped(self):
        e = self._make_enforcer()
        vs = e.analyze_imports("src/views/page.py", [(".models", 2), ("..core", 3)])
        assert len(vs) == 0

    def test_default_layers_exist(self):
        from deadpush.layers import DEFAULT_LAYERS
        assert len(DEFAULT_LAYERS) >= 4

    def test_extract_imports_python(self):
        e = self._make_enforcer()
        source = "import os\nimport django.db.models\nfrom flask import app\n"
        imports = e.extract_imports_regex(source, ".py")
        assert ("os", 1) in imports
        assert ("django", 2) in imports
        assert ("flask", 3) in imports

    def test_extract_imports_typescript(self):
        e = self._make_enforcer()
        source = 'import React from "react"\nimport { useState } from "react"\nimport * as lodash from "lodash"\n'
        imports = e.extract_imports_regex(source, ".tsx")
        assert ("react", 1) in imports
        assert ("lodash", 3) in imports

    def test_extract_imports_js_require(self):
        e = self._make_enforcer()
        source = 'const fs = require("fs")\n'
        imports = e.extract_imports_regex(source, ".js")
        assert ("fs", 1) in imports

    def test_extract_imports_go(self):
        e = self._make_enforcer()
        source = 'import (\n"fmt"\n"os"\n)\n'
        imports = e.extract_imports_regex(source, ".go")
        assert ("fmt", 2) in imports or ("os", 3) in imports

    def test_extract_imports_rust(self):
        e = self._make_enforcer()
        source = "use std::collections::HashMap;\nuse serde::{Deserialize};\n"
        imports = e.extract_imports_regex(source, ".rs")
        assert ("std", 1) in imports
        assert ("serde", 2) in imports
