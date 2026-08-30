"""Verification orchestrator.

For every pending candidate:

1. Fintech-class checks (``fintech.py``).
2. Class-evidence checks (``labels.py``) -> leading confidence.
3. Aggregate to a status and persist to the ``verification`` table.
4. VERIFIED -> promote to a labeled sample (labels + label_evidence rows).
   MANUAL_REVIEW / INSUFFICIENT_EVIDENCE / REJECTED -> review queue or blocked.
"""

from __future__ import annotations

import uuid

from ..config import AppConfig
from ..models import (
    CandidateRecord,
    Confidence,
    LabelRecord,
    ReviewRecord,
    SampleRecord,
    VerificationStatus,
    utcnow,
)
from ..persistence import Database
from ..sources.mock_benign import SeedPackage
from ..sources.mock_malware import ThreatFamily
from .base import CheckResult, aggregate, compile_notes
from .fintech import verify_fintech_class
from .labels import (
    confidence_from_checks,
    leading_confidence,
    verify_benign_evidence,
    verify_malware_evidence,
)

VERIFIED = VerificationStatus.VERIFIED


def _make_id() -> str:
    return uuid.uuid4().hex[:16]


def verify_pending_candidates(
    db: Database,
    cfg: AppConfig,
    catalog: dict[str, SeedPackage],
    families: dict[str, ThreatFamily],
    *,
    limit: int | None = None,
) -> dict[str, int]:
    """Process candidates still in ``pending``, updating the database in place.

    Returns a tally of statuses assigned.
    """
    rows = db.fetchall("SELECT * FROM candidates WHERE verification_status='pending'")
    tally: dict[str, int] = {}
    processed = 0
    for row in rows:
        if limit and processed >= limit:
            break
        rec = CandidateRecord(**dict(row))
        status, checks, conf = _verify_one(rec, catalog, families)
        db.execute(
            "UPDATE candidates SET verification_status=?, verification_notes=? WHERE candidate_id=?",
            (status.value, compile_notes(checks), rec.candidate_id),
        )
        db.add_verification(
            {
                "verification_id": _make_id(),
                "candidate_id": rec.candidate_id,
                "sha256": rec.sha256,
                "status": status.value,
                "checks": [c.__dict__ for c in checks],
                "notes": compile_notes(checks),
                "checked_at": utcnow(),
            }
        )
        _promote_or_queue(db, rec, status, conf, checks)
        tally[status.value] = tally.get(status.value, 0) + 1
        processed += 1
    db.commit()
    return tally


def _verify_one(
    rec: CandidateRecord,
    catalog: dict[str, SeedPackage],
    families: dict[str, ThreatFamily],
) -> tuple[VerificationStatus, list[CheckResult], Confidence | None]:
    fintech_checks = verify_fintech_class(rec, catalog)
    if rec.suspected_class.value == "malicious":
        ev_checks = verify_malware_evidence(rec, families)
        conf = leading_confidence(ev_checks)
    else:
        ev_checks = verify_benign_evidence(rec)
        conf = confidence_from_checks(ev_checks)
    all_checks = list(fintech_checks) + list(ev_checks)
    status = aggregate(fintech_checks)
    return status, all_checks, conf


def _promote_or_queue(
    db: Database,
    rec: CandidateRecord,
    status: VerificationStatus,
    conf: Confidence | None,
    checks: list[CheckResult],
) -> None:
    if status == VERIFIED and conf is not None and conf != Confidence.C:
        _promote(db, rec, conf)
        return
    # Everything else lands in the review queue so the no-guess policy is
    # visible and actionable rather than silently dropping rows.
    _queue(db, rec, status, conf, checks)


def _promote(db: Database, rec: CandidateRecord, conf: Confidence) -> None:
    now = utcnow()
    label = LabelRecord(
        sample_id=rec.candidate_id,
        sha256=rec.sha256,
        class_label=rec.suspected_class,
        confidence=conf,
        family=rec.suspected_family,
        targeting_basis=rec.targeting_basis,
        vt_detection=rec.vt_detection,
        evidence_refs=[rec.source_reference, rec.evidence],
        source_note=rec.evidence,
        reviewed=True,
        reviewer="verify_orchestrator",
        review_timestamp=now,
        created_at=now,
        updated_at=now,
    )
    db.upsert_label(label)
    db.execute(
        "INSERT OR IGNORE INTO label_evidence (sample_id, sha256, kind, value, source, fetched_at) VALUES (?,?,?,?,?,?)",
        (rec.candidate_id, rec.sha256, "source_reference", rec.source_reference, rec.source, now),
    )
    db.execute(
        "INSERT OR IGNORE INTO label_evidence (sample_id, sha256, kind, value, source, fetched_at) VALUES (?,?,?,?,?,?)",
        (rec.candidate_id, rec.sha256, "evidence", rec.evidence, rec.source, now),
    )
    if conf == Confidence.A and rec.suspected_family:
        db.execute(
            "INSERT OR IGNORE INTO label_evidence (sample_id, sha256, kind, value, source, fetched_at) VALUES (?,?,?,?,?,?)",
            (
                rec.candidate_id,
                rec.sha256,
                "vendor_report",
                rec.evidence,
                rec.source,
                now,
            ),
        )

    sample = SampleRecord(
        sample_id=rec.candidate_id,
        sha256=rec.sha256,
        source=rec.source,
        class_label=rec.suspected_class,
        package_name=rec.package_name,
        app_name=rec.app_name,
        version_code=rec.version_code,
        version_name=rec.version_name,
        fintech_category=rec.fintech_category,
        fintech_basis=rec.fintech_basis,
        targeting_basis=rec.targeting_basis,
        label_confidence=conf,
        family=rec.suspected_family,
        family_confidence=conf if rec.suspected_family else None,
        label_evidence_reference=rec.evidence,
        market=rec.market,
        country=rec.country,
        dex_date=rec.dex_date,
        vt_detection=rec.vt_detection,
        created_at=now,
    )
    db.upsert_sample(sample)


def _queue(
    db: Database,
    rec: CandidateRecord,
    status: VerificationStatus,
    conf: Confidence | None,
    checks: list[CheckResult],
) -> None:
    reason = status.value
    evidence_lines = "\n".join(f"- {c.status}: {c.message}" for c in checks)
    db.add_review(
        ReviewRecord(
            sample_id=rec.candidate_id,
            candidate_label=rec.suspected_class.value,
            candidate_family=rec.suspected_family,
            confidence=conf if conf else Confidence.C,
            reason=reason,
            evidence=evidence_lines + "\n" + rec.evidence,
            review_required=True,
            review_status="REVIEW_REQUIRED",
        )
    )
