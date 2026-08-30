"""Dataset quality gates.

Enforced by the dataset builder before any release is allowed. A gate that
fails with severity FAIL halts the build; WARNING notes are recorded but do not
block. The exact gate definitions below are the *contract* shipped in the
DATASHEET, matching the MASTER prompt Gates 1-8.
"""

from __future__ import annotations

from ..config import AppConfig
from ..models import GateResult
from ..persistence import Database

REQUIRED = 8


def run_gates(db: Database, cfg: AppConfig) -> list[GateResult]:
    """Run Gates 1-8 over the current samples table."""
    results: list[GateResult] = []
    benign = db.count_active_samples("benign")
    malicious = db.count_active_samples("malicious")
    total = benign + malicious

    # 1 -- row count
    ok = total == cfg.dataset.total
    results.append(
        GateResult(
            gate="G1_row_count",
            passed=ok,
            severity="FAIL" if not ok else "PASS",
            detail=f"expected {cfg.dataset.total}, found {total}",
        )
    )

    # 2 -- 60/40 balance
    ok = benign == cfg.dataset.benign and malicious == cfg.dataset.malicious
    results.append(
        GateResult(
            gate="G2_balance",
            passed=ok,
            severity="FAIL" if not ok else "PASS",
            detail=f"benign {benign}/{cfg.dataset.benign}, malicious {malicious}/{cfg.dataset.malicious}",
        )
    )

    # 3 -- Android validity
    n_invalid = int(
        db.scalar(
            "SELECT COUNT(*) FROM samples WHERE dataset_version != '' AND apk_validation_status != 'VALID'"
        )
    )
    results.append(
        GateResult(
            gate="G3_apk_validity",
            passed=n_invalid == 0,
            severity="FAIL" if n_invalid else "PASS",
            detail=f"{n_invalid} samples fail APK validation",
        )
    )

    # 4 -- fintech classification
    n_no_fintech = int(
        db.scalar(
            """
            SELECT COUNT(*) FROM samples
            WHERE dataset_version != '' AND (class_label='benign' AND (fintech_category='' OR fintech_basis=''))
               OR (class_label='malicious' AND (targeting_basis='' OR targeting_basis IS NULL))
            """
        )
    )
    results.append(
        GateResult(
            gate="G4_fintech_classification",
            passed=n_no_fintech == 0,
            severity="FAIL" if n_no_fintech else "PASS",
            detail=f"{n_no_fintech} samples lack fintech classification evidence",
        )
    )

    # 5 -- malware evidence (vt>=min OR strong external evidence override)
    min_vt = cfg.labels.malicious_vt_min
    n_weak_mal = int(
        db.scalar(
            """
            SELECT COUNT(*) FROM samples
            WHERE dataset_version != '' AND class_label='malicious'
              AND (vt_detection < ? OR vt_detection IS NULL)
              AND label_confidence != 'A'
            """,
            (min_vt,),
        )
    )
    results.append(
        GateResult(
            gate="G5_malware_evidence",
            passed=n_weak_mal == 0,
            severity="FAIL" if n_weak_mal else "PASS",
            detail=f"{n_weak_mal} malicious samples below VT={min_vt} without A-grade evidence",
        )
    )

    # 6 -- benign evidence
    n_dirty_benign = int(
        db.scalar("SELECT COUNT(*) FROM samples WHERE dataset_version != '' AND class_label='benign' AND vt_detection != 0")
    )
    results.append(
        GateResult(
            gate="G6_benign_evidence",
            passed=n_dirty_benign == 0,
            severity="FAIL" if n_dirty_benign else "PASS",
            detail=f"{n_dirty_benign} benign samples with vt_detection != 0",
        )
    )

    # 7 -- unique SHA-256
    n_dup_sha = int(
        db.scalar(
            "SELECT COUNT(*) FROM (SELECT sha256 FROM samples WHERE dataset_version != '' GROUP BY sha256 HAVING COUNT(*)>1)"
        )
    )
    results.append(
        GateResult(
            gate="G7_unique_sha256",
            passed=n_dup_sha == 0,
            severity="FAIL" if n_dup_sha else "PASS",
            detail=f"{n_dup_sha} duplicated SHA-256 values",
        )
    )

    # 8 -- package duplication (soft, bounded by version cap)
    max_ver = cfg.selection.get("max_versions_per_package", 12)
    over_ver = [
        dict(r)
        for r in db.fetchall(
            "SELECT package_name, COUNT(*) c FROM samples WHERE dataset_version != '' GROUP BY package_name HAVING c > ?",
            (max_ver,),
        )
    ]
    results.append(
        GateResult(
            gate="G8_package_dedup",
            passed=len(over_ver) == 0,
            severity="WARNING" if over_ver else "PASS",
            detail=(
                f"{len(over_ver)} package(s) exceed {max_ver} versions: "
                + ", ".join(f"{r['package_name']}({r['c']})" for r in over_ver)
                if over_ver
                else f"no package exceeds {max_ver} versions"
            ),
        )
    )
    return results


def gates_passed(results: list[GateResult]) -> bool:
    return all(r.passed or r.severity == "WARNING" for r in results)


def record_gates(db: Database, results: list[GateResult], run_hash: str) -> None:
    for r in results:
        db.add_gate(r, run_hash)
