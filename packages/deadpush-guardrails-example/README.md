# deadpush-guardrails-example

Reference [deadpush](https://github.com/harris-ahmad/deadpush) guardrail plugin.

## Install

```bash
pip install deadpush-guardrails-example
```

## What it does

Blocks `TODO`, `FIXME`, and `HACK` markers in files under `src/` (category: `debris`).

## Author your own

Subclass `deadpush.plugins.BaseGuardrailPlugin` and register via:

```toml
[project.entry-points."deadpush.guardrails"]
my_rules = "my_package.plugin:MyPlugin"
```

See `deadpush_guardrails_example/plugin.py` for a minimal example.
