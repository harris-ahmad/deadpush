from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import deadpush_bootstrap


def test_bootstrap_finds_editable_root_from_direct_url(tmp_path, monkeypatch):
    site_pkg = tmp_path / "site-packages"
    site_pkg.mkdir()
    dist = site_pkg / "deadpush-0.2.1.dist-info"
    dist.mkdir()
    repo = tmp_path / "repo"
    (repo / "deadpush").mkdir(parents=True)
    (repo / "deadpush" / "__init__.py").write_text("")
    (dist / "direct_url.json").write_text(
        json.dumps({"dir_info": {"editable": True}, "url": f"file://{repo}"})
    )

    for mod in list(sys.modules):
        if mod == "deadpush" or mod.startswith("deadpush."):
            monkeypatch.delitem(sys.modules, mod, raising=False)

    import builtins

    real_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "deadpush" or name.startswith("deadpush."):
            raise ModuleNotFoundError(name)
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    import site

    monkeypatch.setattr(site, "getsitepackages", lambda: [str(site_pkg)])
    sys.path[:] = [p for p in sys.path if str(repo) not in p]

    deadpush_bootstrap._bootstrap_editable_path()
    assert str(repo) in sys.path
