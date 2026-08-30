"""Acquisition.

In mock mode a download writes a deterministic ``.mockapk.json`` descriptor into
the samples vault and records the artifact SHA-256 — never a real APK. In real
mode (out of scope) this module would stream the verified source artifact and
recomputing the hash from the downloaded bytes.
"""

from __future__ import annotations

import random
from pathlib import Path

from ..config import AppConfig
from ..models import (
    AcquisitionStatus,
    ErrorRecord,
    SampleRecord,
    ValidationStatus,
)
from ..persistence import Database
from ..sources.mock_apk import synth_manifest


def acquire_samples(
    db: Database,
    cfg: AppConfig,
    *,
    limit: int | None = None,
    force: bool = False,
) -> dict:
    """Acquire artifacts for samples pending acquisition. Returns a status tally."""
    sql = "SELECT * FROM samples WHERE acquisition_status='pending'"
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = db.fetchall(sql)
    tally: dict = {}
    mock = cfg.development.mock_acquisition
    for row in rows:
        sample = SampleRecord(**dict(row))
        try:
            if mock:
                _acquire_mock(db, cfg, sample)
                tally["mock_downloaded"] = tally.get("mock_downloaded", 0) + 1
            else:
                raise NotImplementedError("real acquisition is out of scope")
        except Exception as exc:  # noqa: BLE001
            db.log_error(
                ErrorRecord(
                    stage="acquisition",
                    sample_id=sample.sample_id,
                    sha256=sample.sha256,
                    error_code="ACQUIRE",
                    message=str(exc),
                )
            )
            tally["failed"] = tally.get("failed", 0) + 1
    db.commit()
    return tally


def _acquire_mock(db: Database, cfg: AppConfig, sample: SampleRecord) -> None:
    vault = cfg.samples_root
    rel = Path(sample.class_label.value) / sample.sha256[:2] / (sample.sha256 + ".mockapk.json")
    dest = vault / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int(sample.sha256[:8], 16))
    manifest = synth_manifest(sample, sample.sha256, rng).to_dict()
    import json

    payload = json.dumps(manifest, sort_keys=True, indent=2)
    if dest.exists() and dest.read_text() == payload:
        pass
    else:
        dest.write_text(payload, encoding="utf-8")
    db.execute(
        "UPDATE samples SET acquisition_status=?, apk_validation_status=?, apk_size=? WHERE sample_id=?",
        (
            AcquisitionStatus.SIMULATED.value,
            ValidationStatus.VALID.value,
            manifest["apk_size_bytes"],
            sample.sample_id,
        ),
    )
    # record artifact path + hash so provenance chain closes
    db.execute(
        "INSERT OR REPLACE INTO label_evidence (sample_id, sha256, kind, value, source, fetched_at) VALUES (?,?,?,?,?,?)",
        (sample.sample_id, sample.sha256, "artifact_path", str(rel), "mock_acquisition", None),
    )
