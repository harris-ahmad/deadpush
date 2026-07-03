#!/usr/bin/env bash
# Dev install for deadpush. Works around macOS UF_HIDDEN on .pth files (Python 3.12+
# skips them), which breaks editable installs under ~/Documents.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON="$ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  echo "error: python3 not found" >&2
  exit 1
fi

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  "$PYTHON" -m venv "$ROOT/.venv"
  PYTHON="$ROOT/.venv/bin/python"
fi

"$PYTHON" -m pip install -U pip
"$PYTHON" -m pip install -e "$ROOT[dev,rich]"

SITE="$("$PYTHON" -c "import site; print(site.getsitepackages()[0])")"

# Bootstrap module must be a real .py file in site-packages (not via skipped .pth).
cp "$ROOT/deadpush_bootstrap.py" "$SITE/deadpush_bootstrap.py"

# Self-contained CLI wrapper: survives hidden .pth even if entry-point script breaks.
{
  echo "#!$PYTHON"
  tail -n +2 "$ROOT/scripts/deadpush"
} > "$ROOT/.venv/bin/deadpush"
chmod +x "$ROOT/.venv/bin/deadpush"

# Stale wheel copies shadow the editable install (e.g. macOS "cli 2.py" duplicates).
for site_pkg in "$ROOT/.venv"/lib/python*/site-packages/deadpush; do
  if [[ -d "$site_pkg" && ! -f "$site_pkg/__init__.py" ]]; then
    rm -rf "$site_pkg"
  fi
done

if [[ "$(uname -s)" == Darwin ]]; then
  chflags -R nohidden "$ROOT/.venv" 2>/dev/null || true
fi

VERIFY_DIR="${TMPDIR:-/tmp}"
cd "$VERIFY_DIR"
"$ROOT/.venv/bin/deadpush" --version

echo "deadpush dev install OK"
echo "Run: source .venv/bin/activate"
