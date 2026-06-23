# Contributing

Thanks for your interest in deadpush.

## Getting Started

```bash
git clone https://github.com/harris-ahmad/deadpush
cd deadpush
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,watch,rich]"
```

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
