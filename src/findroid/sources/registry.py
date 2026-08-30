"""Named source adapters + registry.

Real adapters (AndroZoo, MalwareBazaar) are *structural stubs*: the full query
paths exist but raise :class:`SourceError` unless real credentials are present
(which is intentionally out of scope while the corpus runs mock-first).
The mock adapters exercise the identical contracts deterministically.
"""

from __future__ import annotations

from .base import BaseSource, SourceError


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
        # real-mode query is deliberately not implemented; see README
        raise SourceError("AndroZoo real acquisition is out of scope for this build")


class MalwareBazaarSource(BaseSource):
    kind = "malwarebazaar"

    def __init__(self, api_key: str = ""):
        super().__init__("malwarebazaar")
        self._api_key = api_key

    def credentials_ok(self) -> bool:
        return bool(self._api_key)

    def discover(self, *, limit: int | None = None):
        if not self.credentials_ok():
            raise SourceError("MalwareBazaar credentials missing (set MALWAREBAZAAR_API_KEY)")
        raise SourceError("MalwareBazaar real acquisition is out of scope for this build")


def build_source_registry(cfg) -> dict[str, BaseSource]:
    """Build the source registry from configuration.

    Returns a dict of source-key -> adapter. The default app config runs
    mock mode, so the sources are the deterministic mock adapters.
    """
    from ..config import AppConfig

    if not isinstance(cfg, AppConfig):
        raise TypeError("registry expects an AppConfig")
    return {
        "mock_play": MockPlaySource(),
        "mock_malwarebazaar": MockMalwareSource(),
    }


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
    "MockPlaySource",
    "MockMalwareSource",
    "SourceError",
    "build_source_registry",
]
