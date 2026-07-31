#!/usr/bin/env python3
"""Thin wrapper: python scripts/run_eval.py --out eval_out"""

from deadpush.eval.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
