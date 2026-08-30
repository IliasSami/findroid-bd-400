"""Shared fixtures for the findroid test-suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if REPO_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, REPO_ROOT.as_posix())
SRC = REPO_ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from findroid.config import load_config  # noqa: E402


@pytest.fixture()
def cfg(tmp_path: Path):
    """A config whose data/DB/vault point at a temp dir for isolation."""
    env = {
        "FINDROID_DATA_ROOT": str(tmp_path / "data"),
        "FINDROID_DB_PATH": str(tmp_path / "findroid.db"),
        "FINDROID_APK_VAULT": str(tmp_path / "samples"),
    }
    for k, v in env.items():
        import os

        os.environ[k] = v
    c = load_config(REPO_ROOT)
    c.resolve_env_overrides()
    yield c
    for k in env:
        import os

        os.environ.pop(k, None)
