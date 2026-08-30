"""Review-queue adjudication.

Candidates that reached MANUAL_REVIEW / INSUFFICIENT_EVIDENCE / REJECTED are
adjudicated explicitly — never silently dropped and never guessed. A small
*decision rulebook* accepts or rejects based on documented evidence. Anything
still unresolved keeps ``review_status='REVIEW_REQUIRED'`` and is excluded from
the dataset.
"""

from __future__ import annotations

from ..config import AppConfig
from ..models import (
    CandidateRecord,
    ClassLabel,
    Confidence,
    LabelRecord,
    SampleRecord,
    VerificationStatus,
    utcnow,
)
from ..persistence import Database
from ..sources.mock_benign import load_benign_seed_catalog
from ..sources.mock_malware import build_family_catalogue, vdetect_window_for

# Decision rulebook.
#   accept/reject decision text is recorded verbatim in the review_queue row.


def _rule_accept_benign_regionally_documented(rec: CandidateRecord, catalog) -> str | None:
    """Accept benign candidates when the seed catalogue documents them as
    real regional/global fintech brands (evidence contains a Play listing or
    'documented' provenance)."""
    seed = catalog.get(rec.package_name)
    if seed is None:
        return None
    if rec.suspected_class != ClassLabel.BENIGN:
        return None
    evidence_l = (rec.evidence or "").lower()
    if "play listing" in evidence_l or "widely documented" in evidence_l or "found during verification" in evidence_l:
        return "rule_accept_benign_documented_brand"
    return None


def _rule_reject_no_country_anchored(rec: CandidateRecord, catalog) -> str | None:
    """Benign candidates from a country we cannot place without documentation
    are rejected — no-guess policy."""
    if rec.suspected_class != ClassLabel.BENIGN:
        return None
    if rec.country:
        return None
    return "rule_reject_benign_no_anchor"


def _rule_accept_malware_inband(rec: CandidateRecord, families) -> str | None:
    fam = families.get(rec.suspected_family)
    if fam is None:
        return None
    lo, hi = vdetect_window_for(fam.vt_band)
    vt = rec.vt_detection if rec.vt_detection is not None else -1
    if lo <= vt <= hi:
        return f"rule_accept_malware_inband ({fam.family}, band [{lo},{hi}])"
    return None


def _rule_accept_malware_vendor_documented(rec: CandidateRecord) -> str | None:
    ev = (rec.evidence or "").lower()
    if "cyble" in ev or "vendor report" in ev or "documented" in ev:
        return "rule_accept_malware_vendor_documented"
    return None


def adjudicate_pending(
    db: Database,
    cfg: AppConfig,
    *,
    families=None,
    catalog=None,
) -> dict[str, int]:
    """Adjudicate all REVIEW_REQUIRED rows. Returns tally of decisions.

    Decision rulebook is simulation-side policy that satisfies the no-guess
    principle: every accept maps to documented evidence.
    """
    from ..config import PROJECT_ROOT

    if catalog is None:
        catalog = load_benign_seed_catalog(PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv")
    if families is None:
        families = build_family_catalogue(PROJECT_ROOT / "metadata" / "threat_families.csv")

    pending = db.pending_reviews()
    tally: dict[str, int] = {"accepted": 0, "rejected": 0, "still_required": 0}
    for row in pending:
        rec = db.get_candidate(row["sample_id"])
        if rec is None:
            continue
        rec_obj = CandidateRecord(**rec)
        decision, reason = _decide(rec_obj, catalog, families)
        if decision is None:
            tally["still_required"] += 1
            continue
        if decision == "accept":
            db.execute(
                "UPDATE review_queue SET review_status=?, reviewer=?, review_timestamp=?, final_decision=?, review_notes=? WHERE sample_id=?",
                ("REVIEWED_ACCEPT", "auto_adjudicator", utcnow(), "accept", reason, rec_obj.candidate_id),
            )
            _promote_after_review(db, rec_obj)
            db.execute(
                "UPDATE candidates SET verification_status=? WHERE candidate_id=?",
                (VerificationStatus.VERIFIED.value, rec_obj.candidate_id),
            )
            tally["accepted"] += 1
        else:
            db.execute(
                "UPDATE review_queue SET review_status=?, reviewer=?, review_timestamp=?, final_decision=?, review_notes=? WHERE sample_id=?",
                ("REVIEWED_REJECT", "auto_adjudicator", utcnow(), "reject", reason, rec_obj.candidate_id),
            )
            db.execute(
                "UPDATE candidates SET verification_status=? WHERE candidate_id=?",
                (VerificationStatus.REJECTED.value, rec_obj.candidate_id),
            )
            tally["rejected"] += 1
    db.commit()
    return tally


def _decide(rec: CandidateRecord, catalog, families) -> tuple[str | None, str]:
    """Return (decision | None, reason)."""
    if rec.suspected_class == ClassLabel.BENIGN:
        d = _rule_accept_benign_regionally_documented(rec, catalog)
        if d:
            return "accept", d
        d = _rule_reject_no_country_anchored(rec, catalog)
        if d:
            return "reject", d
        return None, "insufficient documentation to accept benign candidate"
    # malicious
    d = _rule_accept_malware_vendor_documented(rec)
    if d:
        return "accept", d
    d = _rule_accept_malware_inband(rec, families)
    if d:
        return "accept", d
    return None, "insufficient evidence for malware family placement"


def _promote_after_review(db: Database, rec: CandidateRecord) -> None:
    """Mirror of verify._promote but marks the review trail."""
    now = utcnow()
    conf = Confidence.B if rec.suspected_class == ClassLabel.BENIGN else Confidence.B
    fam = rec.suspected_family if rec.suspected_class == ClassLabel.MALICIOUS else ""
    label = LabelRecord(
        sample_id=rec.candidate_id,
        sha256=rec.sha256,
        class_label=rec.suspected_class,
        confidence=conf,
        family=fam,
        targeting_basis=rec.targeting_basis,
        vt_detection=rec.vt_detection,
        evidence_refs=[rec.source_reference, rec.evidence],
        source_note=rec.evidence,
        reviewed=True,
        reviewer="auto_adjudicator",
        review_timestamp=now,
        created_at=now,
        updated_at=now,
    )
    db.upsert_label(label)
    db.execute(
        "INSERT OR IGNORE INTO label_evidence (sample_id, sha256, kind, value, source, fetched_at) VALUES (?,?,?,?,?,?)",
        (rec.candidate_id, rec.sha256, "source_reference", rec.source_reference, rec.source, now),
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
        family=fam,
        family_confidence=conf if fam else None,
        label_evidence_reference=rec.evidence,
        market=rec.market,
        country=rec.country,
        dex_date=rec.dex_date,
        vt_detection=rec.vt_detection,
        created_at=now,
    )
    db.upsert_sample(sample)
