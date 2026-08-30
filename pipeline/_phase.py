"""Shared runner for the numbered pipeline scripts.

Each ``NN_name.py`` executes a single phase against the default configuration.
Paths are resolved from the repository root regardless of the caller's cwd.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

from findroid.config import load_config  # noqa: E402
from pipeline.run_pipeline import Pipeline  # noqa: E402


def run_phase(name: str) -> None:
    cfg = load_config(REPO_ROOT)
    cfg.resolve_env_overrides()
    pipe = Pipeline(cfg)
    try:
        method = getattr(pipe, f"phase_{name}")
        print(f"== phase {name} ==")
        for line in method():
            print("  ", line)
    finally:
        pipe.close()
