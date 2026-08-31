"""Dataset export.

Writes the release files under ``data/releases/<version>/``:

* ``findroid_bd_<version>_dataset.csv``      (wide: rows x features)
* ``findroid_bd_<version>_dataset.parquet``  (same table, when output.parquet)
* ``findroid_bd_<version>_manifest.json``    (provenance + gates + version hash)
* ``findroid_bd_<version>_label.csv``        (label evidence per sample)
* ``findroid_bd_<version>_label.parquet``    (same, when output.parquet)
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC
from pathlib import Path

import pandas as pd

from ..config import AppConfig
from ..features.schema import FEATURE_GROUPS, ROW_CONTRACT, select_features
from ..persistence import Database


def _active_rows(db: Database) -> list[dict]:
    rows = db.fetchall(
        """
        SELECT samples.*, labels.confidence AS label_confidence,
               labels.family AS family, labels.confidence AS family_confidence,
               labels.evidence_refs AS evidence_refs
        FROM samples LEFT JOIN labels ON labels.sample_id = samples.sample_id
        WHERE samples.dataset_version != ''
        """
    )
    return [dict(r) for r in rows]


def _feature_rows(db: Database) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in db.fetchall(
        "SELECT sample_id, feature_name, value, dtype, [group] AS grp, extraction_status FROM features"
    ):
        out.setdefault(r["sample_id"], {})[f"{r['grp']}.{r['feature_name']}"] = r["value"]
    return out


def export_release(
    db: Database,
    cfg: AppConfig,
    version: str,
    reports_root: Path | None = None,
) -> dict[str, Path]:
    """Export the active version to CSV/JSON/parquet in data/releases."""
    out_dir = cfg.data_root / "releases" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = _active_rows(db)
    features = _feature_rows(db)

    # column schema: row contract + stable feature ordering
    feature_names: set[str] = set()
    for r in rows:
        feature_names.update(features.get(r["sample_id"], {}).keys())
    ordered_features = select_features(sorted(feature_names), FEATURE_GROUPS)
    columns = ROW_CONTRACT + ordered_features

    latest = db.scalar("SELECT MAX(check_id) - 8 FROM quality_checks") or 0
    gates = db.fetchall(
        "SELECT gate, passed, severity, detail FROM quality_checks "
        "WHERE check_id > ? ORDER BY check_id",
        (latest,),
    )
    manifest = {
        "dataset": cfg.dataset.model_dump(),
        "version": version,
        "config_hash": cfg.config_hash(),
        "gates": [dict(r) for r in gates],
        "generated_at": _now(),
        "build_mode": {
            "mock_sources": cfg.development.mock_sources,
            "mock_acquisition": cfg.development.mock_acquisition,
            "mock_extraction": cfg.development.mock_extraction,
            "note": "SIMULATED backend: artifact hashes are synthetic; real acquisition required for release",
        },
        "row_count": len(rows),
        "class_breakdown": {
            "benign": sum(1 for r in rows if r["class_label"] == "benign"),
            "malicious": sum(1 for r in rows if r["class_label"] == "malicious"),
        },
    }

    data_csv = out_dir / f"findroid_bd_{version}_dataset.csv"
    label_csv = out_dir / f"findroid_bd_{version}_label.csv"

    rows_out: list[dict] = []
    for r in rows:
        merged = dict(r)
        merged.update(features.get(r["sample_id"], {}))
        merged["label_confidence"] = r["label_confidence"]
        rows_out.append(merged)

    with data_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows_out)

    label_rows = [
        {
            "sample_id": r["sample_id"],
            "sha256": r["sha256"],
            "class_label": r["class_label"],
            "confidence": r["label_confidence"],
            "family": r["family"],
            "targeting_basis": r["targeting_basis"],
            "evidence_refs": r.get("evidence_refs", ""),
        }
        for r in rows
    ]
    with label_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=list(label_rows[0].keys()) if label_rows else []
        )
        writer.writeheader()
        writer.writerows(label_rows)

    written = {
        "dataset_csv": data_csv,
        "label_csv": label_csv,
    }
    hash_parts = [data_csv.read_bytes(), label_csv.read_bytes()]

    if cfg.output.parquet:
        data_pq = out_dir / f"findroid_bd_{version}_dataset.parquet"
        label_pq = out_dir / f"findroid_bd_{version}_label.parquet"
        pd.DataFrame(rows_out, columns=columns).to_parquet(data_pq, index=False)
        pd.DataFrame(label_rows).to_parquet(label_pq, index=False)
        written["dataset_parquet"] = data_pq
        written["label_parquet"] = label_pq
        hash_parts += [data_pq.read_bytes(), label_pq.read_bytes()]

    # manifest content hash for integrity verification
    content_hash = hashlib.sha256(b"".join(hash_parts)).hexdigest()
    manifest["content_sha256"] = content_hash
    manifest["files"] = sorted(p.name for p in written.values())
    manifest_path = out_dir / f"findroid_bd_{version}_manifest.json"

    with manifest_path.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)

    written["manifest_json"] = manifest_path
    return written


def _now() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat(timespec="seconds")
