"""findroid CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if _REPO_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, _REPO_ROOT.as_posix())
if (_REPO_ROOT / "src").as_posix() not in sys.path:
    sys.path.insert(0, (_REPO_ROOT / "src").as_posix())

from pipeline.run_pipeline import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
