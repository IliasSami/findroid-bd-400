"""Verification: aggregate rules + fintech classification checks."""

from __future__ import annotations

from findroid.models import CandidateRecord, ClassLabel, VerificationStatus, utcnow
from findroid.sources.mock_benign import SeedPackage, package_label
from findroid.verification.base import CheckResult, aggregate
from findroid.verification.fintech import verify_fintech_class


def _benign_record(**kw) -> CandidateRecord:
    base = dict(
        candidate_id="c1",
        source="mock_play",
        sha256="a" * 64,
        package_name="com.example.bkash",
        app_name="bKash Example",
        version_code=1000,
        version_name="1.0",
        fintech_category="mfs_wallet",
        fintech_basis="seed catalogue entry",
        suspected_class=ClassLabel.BENIGN,
        country="BD",
    )
    base.update(kw)
    return CandidateRecord(created_at=utcnow(), updated_at=utcnow(), **base)


def _mal_record(**kw) -> CandidateRecord:
    base = dict(
        candidate_id="m1",
        source="mock_malwarebazaar",
        sha256="b" * 64,
        package_name="com.evil.trojan",
        app_name="Trojan",
        version_code=1,
        version_name="1",
        fintech_category="",
        fintech_basis="targets_bd_fintech",
        suspected_class=ClassLabel.MALICIOUS,
        suspected_family="SikkahBot",
        targeting_basis="impersonates bKash (BD)",
        country="",
    )
    base.update(kw)
    return CandidateRecord(created_at=utcnow(), updated_at=utcnow(), **base)


def _seed(**kw) -> SeedPackage:
    base = dict(
        package_id="com.example.bkash",
        app_name="bKash Example",
        organisation="Example Ltd",
        country="BD",
        tier=1,
        subsector="mfs_wallet",
        verification_status="confirmed",
        evidence="Play listing; widely documented",
    )
    base.update(kw)
    return SeedPackage(**base)


# ---------------------------------------------------------------- aggregation
def test_aggregate_all_pass_verified():
    checks = [CheckResult(True, "pass", "x"), CheckResult(True, "pass", "y")]
    assert aggregate(checks) == VerificationStatus.VERIFIED


def test_aggregate_any_fail_rejected():
    checks = [CheckResult(True, "pass", "x"), CheckResult(False, "fail", "bad")]
    assert aggregate(checks) == VerificationStatus.REJECTED


def test_aggregate_unknown_blocks():
    checks = [CheckResult(True, "pass", "x"), CheckResult(False, "unknown", "nope")]
    assert aggregate(checks) == VerificationStatus.INSUFFICIENT_EVIDENCE


def test_aggregate_warn_manual_review():
    checks = [CheckResult(True, "pass", "x"), CheckResult(True, "warn", "hmm")]
    assert aggregate(checks) == VerificationStatus.MANUAL_REVIEW


def test_aggregate_empty_pending():
    assert aggregate([]) == VerificationStatus.PENDING


# --------------------------------------------------------- fintech class checks
def test_fintech_benign_against_catalog():
    rec = _benign_record()
    checks = verify_fintech_class(rec, {"com.example.bkash": _seed()})
    assert aggregate(checks) == VerificationStatus.VERIFIED


def test_fintech_benign_collision_rejected():
    rec = _benign_record()
    seed = _seed(verification_status="collision", evidence="impostor store listing")
    checks = verify_fintech_class(rec, {"com.example.bkash": seed})
    assert aggregate(checks) == VerificationStatus.REJECTED


def test_fintech_benign_unknown_subsector_blocks():
    rec = _benign_record(fintech_category="games")
    checks = verify_fintech_class(rec, {"com.example.bkash": _seed()})
    assert aggregate(checks) == VerificationStatus.INSUFFICIENT_EVIDENCE


def test_fintech_benign_no_country_blocks_no_guess():
    rec = _benign_record(country="")
    checks = verify_fintech_class(rec, {"com.example.bkash": _seed()})
    assert aggregate(checks) == VerificationStatus.INSUFFICIENT_EVIDENCE


def test_fintech_malicious_requires_targeting():
    rec = _mal_record(targeting_basis="")
    checks = verify_fintech_class(rec, {})
    assert aggregate(checks) == VerificationStatus.INSUFFICIENT_EVIDENCE


def test_fintech_malicious_targeting_ok():
    checks = verify_fintech_class(_mal_record(), {})
    assert aggregate(checks) == VerificationStatus.VERIFIED


def test_package_label_maps_subsector():
    assert package_label(_seed()) == "mobile financial service wallet"
