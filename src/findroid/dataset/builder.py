"""Dataset builder: selection, gating, versioning, export.

Selection implements the quota+diversity funnel (benign pool ~330-360 ->
validated ~280-300 -> final 240; malicious ~250 -> ~180-200 -> 160) using the
priorities from ``configs/selection.yaml``. Nothing is emitted until Gates 1-8
pass. Gates always inspect only the members of the active dataset version.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..config import AppConfig
from ..persistence import Database
from .gates import gates_passed, record_gates, run_gates


def _utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _select(samples: list[dict], target: int, max_ver: int) -> list[dict]:
    """Quota + diversity selection over a validated candidate pool.

    Ordering is deterministic and BD-first: samples anchored to BD sort ahead
    of documented regional/global fills, then by source, then by id. The version
    cap (default per config) bounds how many builds of one package may enter.
    """

    def order_key(s: dict):
        bd_boost = 0 if s["country"] == "BD" else 1
        return (bd_boost, s["source"], s["sample_id"])

    kept: list[dict] = []
    version_count: dict[str, int] = {}
    for s in sorted(samples, key=order_key):
        pkg = s["package_name"]
        if version_count.get(pkg, 0) >= max_ver:
            continue
        kept.append(s)
        version_count[pkg] = version_count.get(pkg, 0) + 1
        if len(kept) >= target:
            break
    return kept


def _next_version(db: Database) -> str:
    row = db.fetchone("SELECT COUNT(*) n FROM dataset_versions")
    n = int(row["n"]) if row else 0
    return f"v1.{n}.0"


def build_dataset(
    db: Database,
    cfg: AppConfig,
    *,
    version: str | None = None,
    run_hash: str = "",
) -> dict:
    """Run selection + gates + version registration for the corpus."""
    benign = green_samples(db, cfg, "benign")
    malicious = green_samples(db, cfg, "malicious")
    max_ver = int(cfg.selection.get("max_versions_per_package", 12))

    bp = _select(benign, cfg.dataset.benign, max_ver)
    mp = _select(malicious, cfg.dataset.malicious, max_ver)
    picks = bp + mp
    version = version or _next_version(db)

    db.execute("UPDATE samples SET dataset_version=''")
    for s in picks:
        db.execute(
            "UPDATE samples SET dataset_version=? WHERE sample_id=?",
            (version, s["sample_id"]),
        )
    db.commit()

    results = run_gates(db, cfg)
    record_gates(db, results, run_hash)
    passed = gates_passed(results)

    if passed:
        db.register_version(
            version,
            len(picks),
            len(bp),
            len(mp),
            cfg.config_hash(),
            notes="gates-ok",
        )
        db.commit()
    return {
        "benign_available": len(benign),
        "malicious_available": len(malicious),
        "benign_selected": len(bp),
        "malicious_selected": len(mp),
        "total_selected": len(picks),
        "gates_passed": passed,
        "gates": [g.model_dump() for g in results],
        "version": version if passed else None,
    }


def green_samples(db: Database, cfg: AppConfig, class_label: str) -> list[dict]:
    """Samples that passed verification, validation, and extraction, and that
    satisfy the label-evidence eligibility rule (malicious: VT >= min or A-grade
    evidence; benign: zero detections). This implements the top selection
    priority ``evidence_quality`` from configs/selection.yaml so weakly-evidenced
    candidates are never candidates for selection."""
    min_vt = int(cfg.labels.malicious_vt_min)
    if class_label == "malicious":
        eligibility = f"(samples.vt_detection >= {min_vt} OR labels.confidence = 'A')"
    else:
        eligibility = "(samples.vt_detection = 0)"
    rows = db.fetchall(
        f"""
        SELECT samples.*, labels.confidence AS label_confidence
        FROM samples JOIN labels ON labels.sample_id = samples.sample_id
        WHERE samples.class_label = ?
          AND samples.apk_validation_status='VALID'
          AND samples.feature_extraction_status='SUCCESS'
          AND {eligibility}
        """,
        (class_label,),
    )
    return [dict(r) for r in rows]
