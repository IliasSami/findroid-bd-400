"""Label evidence rules: confidence triage for malware + benign."""

from __future__ import annotations

from findroid.models import CandidateRecord, ClassLabel, Confidence, utcnow
from findroid.sources.mock_malware import ThreatFamily
from findroid.verification.labels import (
    confidence_from_checks,
    leading_confidence,
    verify_benign_evidence,
    verify_malware_evidence,
)

_FAMILIES = {
    "SikkahBot": ThreatFamily(
        family="SikkahBot",
        first_reported="2025",
        region_focus="Bangladesh",
        techniques="SMS interception; accessibility overlay",
        delivery_vector="smishing links",
        typical_vt_detection="low",
        provenance_note="Cyble CRIL documented",
    )
}


def _record(**kw) -> CandidateRecord:
    base = dict(
        candidate_id="m",
        source="mock_malwarebazaar",
        sha256="c" * 64,
        package_name="com.evil.sikkah",
        app_name="S",
        version_code=1,
        version_name="1",
        suspected_class=ClassLabel.MALICIOUS,
        suspected_family="SikkahBot",
        targeting_basis="impersonates bKash (BD)",
        vt_detection=2,
        play_verification_date="",
        evidence="",
        source_reference="ref",
    )
    base.update(kw)
    return CandidateRecord(created_at=utcnow(), updated_at=utcnow(), **base)


def test_malware_inband_low_vt_with_vendor_doc_is_A():
    rec = _record(vt_detection=2, evidence="vendor report: Cyble documented SIMULATED")
    checks = verify_malware_evidence(rec, _FAMILIES)
    assert leading_confidence(checks) == Confidence.A


def test_malware_inband_without_vendor_doc_is_B():
    rec = _record(vt_detection=2, evidence="bazaar listing SIMULATED")
    checks = verify_malware_evidence(rec, _FAMILIES)
    assert leading_confidence(checks) == Confidence.B


def test_malware_out_of_band_is_C():
    rec = _record(vt_detection=60, evidence="bazaar listing SIMULATED")
    checks = verify_malware_evidence(rec, _FAMILIES)
    assert leading_confidence(checks) == Confidence.C


def test_benign_clean_is_B():
    rec = _record(
        suspected_class=ClassLabel.BENIGN,
        vt_detection=0,
        play_verification_date="2026-01-01",
        evidence="Play listing SIMULATED",
    )
    checks = verify_benign_evidence(rec)
    assert confidence_from_checks(checks) is Confidence.B


def test_benign_dirty_vt_fails():
    rec = _record(
        suspected_class=ClassLabel.BENIGN,
        vt_detection=2,
        play_verification_date="2026-01-01",
    )
    checks = verify_benign_evidence(rec)
    assert checks[0].status == "fail"
