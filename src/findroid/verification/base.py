"""Verification framework.

A candidate is verified for both **fintech relevance** and **class evidence**
before it may become a sample. Every check returns a per-check dict; the caller
aggregates into a status + notes recorded in the ``verification`` table.

Design invariants:

* No guess as evidence. A check that depends on information we do not have
  returns ``unknown`` and the candidate goes to REVIEW_REQUIRED, never silently
  downstream.
* Collision handling. Brand collisions and package-name collisions are rejected
  by the fintech verifier before anything else.
* Origin is never lost. Simulated evidence is labelled SIMULATED in the notes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import VerificationStatus

Check = dict[str, Any]


@dataclass
class CheckResult:
    ok: bool
    status: str  # pass | warn | fail | unknown
    message: str
    detail: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class CheckError(RuntimeError):
    pass


def aggregate(checks: list[CheckResult]) -> VerificationStatus:
    """Combine per-check results into a single verification status.

    - any ``fail``      -> REJECTED
    - any ``unknown``   -> INSUFFICIENT_EVIDENCE (blocked)
    - any ``warn``      -> MANUAL_REVIEW
    - all ``pass``      -> VERIFIED
    """
    if not checks:
        return VerificationStatus.PENDING
    if any(c.status == "fail" for c in checks):
        return VerificationStatus.REJECTED
    if any(c.status == "unknown" for c in checks):
        return VerificationStatus.INSUFFICIENT_EVIDENCE
    if any(c.status == "warn" for c in checks):
        return VerificationStatus.MANUAL_REVIEW
    return VerificationStatus.VERIFIED


def compile_notes(checks: list[CheckResult]) -> str:
    return "; ".join(f"{c.status}:{c.message}" for c in checks)


def same_package_name(a: str, b: str) -> bool:
    return a.strip().lower() == b.strip().lower()
