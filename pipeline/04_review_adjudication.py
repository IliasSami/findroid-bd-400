#!/usr/bin/env python
"""PHASE (04_review_adjudication.py) - review adjudication."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, _ROOT.as_posix())
sys.path.insert(0, (_ROOT / "src").as_posix())

from pipeline._phase import run_phase  # noqa: E402

if __name__ == "__main__":
    run_phase("review_adjudication")
