# Contributing

Thanks for your interest in deadpush.

## Getting Started

```bash
git clone https://github.com/harris-ahmad/deadpush
cd deadpush
./scripts/dev_install.sh
source .venv/bin/activate
```

Or manually:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,rich]"
```

### macOS: editable install silently broken?

On macOS, Python 3.12+ **skips `.pth` files marked hidden** (`UF_HIDDEN`). Files under `~/Documents` (and other iCloud-synced folders) often get this flag, so `pip install -e .` succeeds but `deadpush` only works when your cwd is the repo — from any other directory you get `ModuleNotFoundError`.

Fix:

```bash
./scripts/dev_install.sh
# or, if already installed:
chflags -R nohidden .venv
```

Do **not** run plain `pip install deadpush` in the dev venv; use `pip install -e .` so the editable hook points at your source tree.

## Running Tests

```bash
pytest
```

## Code Style

We use ruff. Run before committing:

```bash
ruff check .
```

## Pull Requests

- Keep changes focused. One PR = one concern.
- Add tests for new functionality.
- Run the full test suite before submitting.
- Update CHANGELOG.md if the change is user-facing.

## Questions?

Open an issue at https://github.com/harris-ahmad/deadpush/issues
