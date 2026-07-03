"""Console entry bootstrap.

Editable installs rely on a ``.pth`` file in site-packages. On macOS,
Python 3.12+ skips ``.pth`` files with the UF_HIDDEN flag (common under
~/Documents). This module is installed as a top-level module in
site-packages so the CLI can always locate the real ``deadpush`` package.
"""

from __future__ import annotations


def _bootstrap_editable_path() -> None:
    import json
    import sys
    from pathlib import Path

    try:
        import deadpush.cli  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    import site

    candidates: list[Path] = []
    for sp in site.getsitepackages():
        sp_path = Path(sp)
        for dist in sp_path.glob("deadpush-*.dist-info"):
            direct = dist / "direct_url.json"
            if not direct.exists():
                continue
            try:
                data = json.loads(direct.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            if data.get("dir_info", {}).get("editable"):
                url = data.get("url", "")
                if url.startswith("file://"):
                    candidates.append(Path(url[7:]))

        for pth in sp_path.glob("*deadpush*.pth"):
            try:
                for line in pth.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("import"):
                        candidates.append(Path(line))
            except OSError:
                continue

    for root in candidates:
        if (root / "deadpush").is_dir():
            root_s = str(root)
            if root_s not in sys.path:
                sys.path.insert(0, root_s)
            return


def main() -> None:
    _bootstrap_editable_path()
    from deadpush.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
