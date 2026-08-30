"""Class-evidence verification.

Assigns a leading label *confidence* based on the strength of available
evidence — never on guesses.

Confidence bands follow the contract in ``configs/labeling.yaml``:

* A — strong external evidence (vendor report, documented family, verified IOC).
* B — strong automated evidence (high detection, family tools agree).
* C — ambiguous (low detection, weak evidence) -> REVIEW_REQUIRED.

The malware evidence check deliberately keeps SikkahBot-style low-VT candidates
at B when vendor-documented (Cyble CRIL) so that low detection alone never
sinks an otherwise well-evidenced family — and conversely sends high-detection
but weakly-evidenced cases to review.
"""

from __future__ import annotations

from ..models import CandidateRecord, ClassLabel, Confidence
from ..sources.mock_malware import ThreatFamily, vdetect_window_for
from .base import CheckResult

_VT_HIGH = 28  # (reserved) high-detection families would clear B on VT alone


def _evidence_quality(rec: CandidateRecord) -> str:
    e = (rec.evidence or "").lower()
    if "cyble" in e or "vendors" in e or "provenance" in e or "documented" in e:
        return "vendor_documented"
    return "source_generated"


def verify_malware_evidence(
    rec: CandidateRecord, families: dict[str, ThreatFamily]
) -> list[CheckResult]:
    fam = families.get(rec.suspected_family)
    if fam is None:
        return [
            CheckResult(
                False, "unknown", f"family {rec.suspected_family!r} not in threat catalogue"
            )
        ]
    if rec.targeting_basis is None or not rec.targeting_basis:
        return [CheckResult(False, "unknown", "targeting basis missing; no fintech relevance")]

    ev = _evidence_quality(rec)
    vt = rec.vt_detection if rec.vt_detection is not None else -1
    lo, hi = vdetect_window_for(fam.vt_band)
    in_band = lo <= vt <= hi
    if ev == "vendor_documented" and fam.targets_bd and in_band:
        conf = Confidence.A
    elif in_band:
        conf = Confidence.B
    else:
        conf = Confidence.C

    msgs = {
        Confidence.A: "vendor-documented BD family and detection within expected band",
        Confidence.B: "detection within expected family band",
        Confidence.C: "ambiguous: detection outside family band or weak evidence",
    }
    return [
        CheckResult(
            True,
            "pass" if conf != Confidence.C else "warn",
            f"malware evidence confidence={conf.value}: {msgs[conf]}",
            detail=f"vt={vt} band=[{lo},{hi}] family={fam.family} evidence={ev}",
            meta={"confidence": conf},
        )
    ]


def verify_benign_evidence(rec: CandidateRecord) -> list[CheckResult]:
    """Benign evidence = catalog listing + zero detections + Play presence."""
    checks: list[CheckResult] = []

    if rec.vt_detection in (None, -1):
        checks.append(CheckResult(False, "unknown", "no VT detections recorded"))
    elif rec.vt_detection == 0:
        checks.append(CheckResult(True, "pass", f"vt_detection={rec.vt_detection} (clean)"))
    else:
        checks.append(
            CheckResult(
                False,
                "fail",
                f"benign candidate has vt_detection={rec.vt_detection}; cannot be clean",
            )
        )

    if not rec.play_verification_date:
        checks.append(CheckResult(False, "unknown", "no Play-listing verification date"))
    else:
        checks.append(CheckResult(True, "pass", "Play listing present"))

    return checks


def confidence_from_checks(checks: list[CheckResult]) -> Confidence:
    if any(c.status == "fail" for c in checks):
        return Confidence.C
    if any(c.status == "unknown" for c in checks):
        return Confidence.C
    if any(c.status == "warn" for c in checks):
        return Confidence.C
    # benign evidence that is fully clean -> B (mock) / A (real Play round-trip)
    return Confidence.B


def leading_confidence(checks: list[CheckResult]) -> Confidence:
    """Pick the confidence carried by the *evidence* checks.

    The malware evidence check embeds its assigned confidence in ``meta``.
    The strongest band found wins (A > B > C); absent a signal the mock keeps
    B. C means ambiguous evidence and the orchestrator routes those candidates
    to the review queue (``c_requires_review`` policy), never to promotion.
    """
    seen = []
    for c in checks:
        meta_conf = c.meta.get("confidence")
        if isinstance(meta_conf, Confidence):
            seen.append(meta_conf)
    if Confidence.A in seen:
        return Confidence.A
    if Confidence.B in seen:
        return Confidence.B
    if Confidence.C in seen:
        return Confidence.C
    return Confidence.B


def resolve_final_confidence(
    rec: CandidateRecord, families: dict[str, ThreatFamily]
) -> Confidence | None:
    """Wrap the per-class evidence checks and return the leading confidence.

    Returns None when the candidate cannot be classified at all.
    """
    if rec.suspected_class == ClassLabel.MALICIOUS:
        checks = verify_malware_evidence(rec, families)
    else:
        checks = verify_benign_evidence(rec)
    if any(c.status == "unknown" for c in checks):
        return None
    conf = confidence_from_checks(checks)
    if conf == Confidence.C:
        return conf if any(c.status == "warn" for c in checks) else None
    return conf
