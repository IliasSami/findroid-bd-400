"""Source adapter contracts.

Every source yields deterministic :class:`CandidateRecord` objects. Real
adapters (AndroZoo, MalwareBazaar) are stubbed: they raise when the required
API key is missing or when mock mode is off. The mock backends produce fully
deterministic, versioned, *simulated* candidates that exercise the entire
pipeline end to end without any external API.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable

from ..models import CandidateRecord


class SourceError(RuntimeError):
    """Raised when a source cannot satisfy a query."""


class BaseSource(abc.ABC):
    kind: str = "generic"

    def __init__(self, name: str):
        self.name = name

    @abc.abstractmethod
    def discover(self, *, limit: int | None = None) -> Iterable[CandidateRecord]:
        """Return candidate records from this source."""

    @abc.abstractmethod
    def credentials_ok(self) -> bool:
        """True when the source can issue real queries right now."""
