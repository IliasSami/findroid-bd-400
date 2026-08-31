"""Named source adapters + registry.

Mock mode returns the deterministic simulation adapters. Real mode builds the
live adapters from environment credentials:

* ``malwarebazaar_real`` — primary malicious source (family signatures + live
  APK downloads via the ``Auth-Key`` header).
* ``malshare_real`` — supplementary download capacity (no family taxonomy).
* ``f_droid_real`` — engineering benign bytes (official open-source builds).
* ``play_benign`` — BD benign APKs imported on a residential network, backed by
  a live Google Play listing (the store front is reachable from any network).
* ``import_malware`` — manual malicious drops (filename-declared family), the
  hook for BD-only trojans (SikkahBot) and theZoo archives.
"""

from __future__ import annotations

import os

from ..config import PROJECT_ROOT
from .base import BaseSource, SourceError
from .f_droid import FDroidSource
from .import_malware import ImportMalwareSource
from .malshare_real import MalShareSource
from .malwarebazaar_real import MalwareBazaarSource
from .play_benign import ImportBenignSource


class AndroZooSource(BaseSource):
    kind = "androzoo"

    def __init__(self, api_key: str = ""):
        super().__init__("androzoo")
        self._api_key = api_key

    def credentials_ok(self) -> bool:
        return bool(self._api_key)

    def discover(self, *, limit: int | None = None):
        if not self.credentials_ok():
            raise SourceError("AndroZoo credentials missing (set ANDROZOO_API_KEY)")
        raise SourceError("AndroZoo real acquisition is out of scope for this build")


def build_source_registry(cfg) -> dict[str, BaseSource]:
    """Build the source registry from configuration.

    Mock mode returns only the deterministic mock adapters. Real mode keys off
    ``development.mock_sources`` and the environment; benign import sources are
    gated on ``development.allow_real_apks`` so that candidate discovery never
    touches the live channels unless explicitly enabled.
    """
    from ..config import AppConfig

    if not isinstance(cfg, AppConfig):
        raise TypeError("registry expects an AppConfig")
    if cfg.development.mock_sources:
        return {
            "mock_play": MockPlaySource(),
            "mock_malwarebazaar": MockMalwareSource(),
        }

    out: dict[str, BaseSource] = {}
    mb_key = os.environ.get("MALWAREBAZAAR_API_KEY", "").strip()
    if mb_key:
        out["malwarebazaar_real"] = MalwareBazaarSource(mb_key)
    ms_key = os.environ.get("MALSHARE_API_KEY", "").strip()
    if ms_key:
        out["malshare_real"] = MalShareSource(ms_key)

    if cfg.development.allow_real_apks:
        out["f_droid_real"] = FDroidSource.from_metadata(
            PROJECT_ROOT / "metadata" / "fdroid_fintech_ids.csv"
        )
        out["play_benign"] = ImportBenignSource()
        out["import_malware"] = ImportMalwareSource()

    if not out:
        raise SourceError(
            "real sources requested but nothing is configured: set MALWAREBAZAAR_API_KEY "
            "and/or FINDROID_ALLOW_REAL_APKS=1 (MALSHARE_API_KEY optional)"
        )
    return out


class MockPlaySource(BaseSource):
    kind = "mock_play"

    def __init__(self):
        super().__init__("mock_play")

    def credentials_ok(self) -> bool:
        return True

    def discover(self, *, limit: int | None = None):
        raise SourceError("use mock_candidates.generate_benign_candidates()")


class MockMalwareSource(BaseSource):
    kind = "mock_malwarebazaar"

    def __init__(self):
        super().__init__("mock_malwarebazaar")

    def credentials_ok(self) -> bool:
        return True

    def discover(self, *, limit: int | None = None):
        raise SourceError("use mock_candidates.generate_malicious_candidates()")


__all__ = [
    "AndroZooSource",
    "MalwareBazaarSource",
    "MalShareSource",
    "FDroidSource",
    "ImportBenignSource",
    "ImportMalwareSource",
    "MockPlaySource",
    "MockMalwareSource",
    "SourceError",
    "build_source_registry",
]
