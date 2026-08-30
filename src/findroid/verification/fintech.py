"""Fintech classification verification.

A sample belongs in a *fintech* corpus either because it **is** a fintech
application (benign candidates, verified against the controlled seed catalogue)
or because it **targets** fintech applications (malicious candidates, verified
against family + impersonation-target evidence). Anything that can't be
classified honestly is blocked (``unknown``), never guessed.
"""

from __future__ import annotations

from ..models import CandidateRecord, ClassLabel
from ..sources.mock_benign import SeedPackage, package_label
from .base import CheckResult

_KNOWN_FINTECH_SUBSECTORS = {
    "mfs_wallet",
    "mfs_agent",
    "bank_retail",
    "digital_banking",
    "psp_wallet",
    "merchant_pos",
    "sme_ledger",
    "interop_rail",
    "remittance",
    "neobank",
    "crypto_exchange",
    "crypto_wallet",
    "lending",
    "investment",
    "insurance",
    "microfinance",
    "fintech_utility",
}


def _check_package_syntax(rec: CandidateRecord) -> CheckResult:
    pkg = rec.package_name
    if not pkg or "." not in pkg or not all(c.isalnum() or c in "._" for c in pkg):
        return CheckResult(False, "fail", "package_name malformed")
    if len(pkg) > 180:
        return CheckResult(False, "fail", "package_name suspiciously long")
    return CheckResult(True, "pass", "package_name syntax ok")


def _check_targeting(rec: CandidateRecord) -> CheckResult:
    if not rec.targeting_basis:
        return CheckResult(
            False, "unknown", "malicious candidate has no impersonation target evidence"
        )
    # Fintech-relevance for a Trojan is that it impersonates a fintech app.
    # Brand specificity is judged by the class-evidence verifier, not here.
    return CheckResult(True, "pass", f"targets fintech: {rec.targeting_basis}")


def _check_benign_seed(rec: CandidateRecord, catalog: dict[str, SeedPackage]) -> CheckResult:
    if rec.fintech_category not in _KNOWN_FINTECH_SUBSECTORS:
        return CheckResult(
            False, "unknown", "fintech_category not in controlled catalogue; refusing to guess"
        )
    pkg = rec.package_name
    seed = catalog.get(pkg)
    if seed is None:
        return CheckResult(
            False,
            "unknown",
            f"package {pkg!r} not found in verified seed catalogue",
        )
    if seed.is_collision:
        return CheckResult(
            False,
            "fail",
            f"excluded: {pkg!r} is a documented brand collision / impostor (" + seed.evidence + ")",
        )
    if rec.fintech_category != seed.subsector:
        return CheckResult(
            False,
            "fail",
            f"subsector mismatch: catalog says {seed.subsector}, candidate says {rec.fintech_category}",
        )
    return CheckResult(
        True,
        "pass",
        f"matches seed catalogue entry {seed.app_name} ({package_label(seed)})",
    )


def _check_bd_anchor(rec: CandidateRecord) -> CheckResult:
    if rec.country == "BD":
        return CheckResult(True, "pass", "BD-anchored candidate")
    if rec.country:
        return CheckResult(True, "warn", f"non-BD but documented regional/global brand ({rec.country})")
    return CheckResult(False, "unknown", "no country/region anchor; refusing to guess")


def verify_fintech_class(rec: CandidateRecord, catalog: dict[str, SeedPackage]) -> list[CheckResult]:
    """Return per-check results. Aggregation happens in the orchestrator."""
    if rec.suspected_class == ClassLabel.MALICIOUS:
        return [
            _check_package_syntax(rec),
            _check_targeting(rec),
        ]
    return [
        _check_package_syntax(rec),
        _check_benign_seed(rec, catalog),
        _check_bd_anchor(rec),
    ]
