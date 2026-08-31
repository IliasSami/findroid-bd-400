"""Acquisition.

Mock mode writes a deterministic ``.mockapk.json`` descriptor and records the
simulated artifact SHA-256. Real mode (``mock_acquisition=false`` +
``allow_real_apks=true``) downloads or imports genuine APK bytes, recomputes the
hash from the bytes, verifies it equals the sample hash, and stores the artifact
under ``samples/<class>/<sha2>/<sha256>.apk``.

Channels per source:

* ``malwarebazaar_real`` / ``malshare_real`` — live download, hash re-verified.
* ``f_droid_real`` — live official build download, hash re-verified.
* ``play_benign`` — the APK must exist in ``samples/import/`` (residential
  fetch); the sample is skipped with an explicit error otherwise.
* ``import_malware`` — the APK must exist in ``samples/import_malicious/``.
"""

from __future__ import annotations

import hashlib
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
from ..sources.base import SourceError
from ..sources.mock_apk import synth_manifest


def acquire_samples(
    db: Database,
    cfg: AppConfig,
    *,
    limit: int | None = None,
    force: bool = False,
) -> dict:
    """Acquire artifacts for samples pending acquisition. Returns a status tally."""
    real = not cfg.development.mock_acquisition
    if real and not cfg.development.allow_real_apks:
        raise RuntimeError(
            "real acquisition requires mock_acquisition=false AND allow_real_apks=true "
            "(set FINDROID_ALLOW_REAL_APKS=1 and FINDROID_MOCK_ACQUISITION=0)"
        )
    sql = "SELECT * FROM samples WHERE acquisition_status='pending'"
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = db.fetchall(sql)
    tally: dict = {}
    registry: dict = {}
    if real:
        from ..sources.registry import build_source_registry

        registry = build_source_registry(cfg)
    for row in rows:
        sample = SampleRecord(**dict(row))
        try:
            if not real:
                _acquire_mock(db, cfg, sample)
                tally["mock_downloaded"] = tally.get("mock_downloaded", 0) + 1
            else:
                _acquire_real(db, cfg, sample, registry)
                tally["real_downloaded"] = tally.get("real_downloaded", 0) + 1
        except SourceError:
            db.log_error(
                ErrorRecord(
                    stage="acquisition",
                    sample_id=sample.sample_id,
                    sha256=sample.sha256,
                    error_code="SOURCE",
                    message=f"source unavailable: {sample.source}",
                )
            )
            tally["failed"] = tally.get("failed", 0) + 1
        except _ImportRequired as exc:
            db.execute(
                "UPDATE samples SET acquisition_status=? WHERE sample_id=?",
                (AcquisitionStatus.SKIPPED.value, sample.sample_id),
            )
            db.log_error(
                ErrorRecord(
                    stage="acquisition",
                    sample_id=sample.sample_id,
                    sha256=sample.sha256,
                    error_code="IMPORT_REQUIRED",
                    message=str(exc),
                )
            )
            tally["skipped"] = tally.get("skipped", 0) + 1
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


class _ImportRequired(Exception):
    """Raised when a sample needs a dropped import file that is not present."""


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
    db.execute(
        "INSERT OR REPLACE INTO label_evidence (sample_id, sha256, kind, value, source, fetched_at) VALUES (?,?,?,?,?,?)",
        (sample.sample_id, sample.sha256, "artifact_path", str(rel), "mock_acquisition", None),
    )


def _acquire_real(
    db: Database, cfg: AppConfig, sample: SampleRecord, registry: dict
) -> None:
    vault = cfg.samples_root
    rel = Path(sample.class_label.value) / sample.sha256[:2] / f"{sample.sha256}.apk"
    dest = vault / rel
    if dest.is_file():
        return  # already acquired; nothing to do
    dest.parent.mkdir(parents=True, exist_ok=True)

    apk_bytes = _real_bytes(sample, registry)
    actual = hashlib.sha256(apk_bytes).hexdigest()
    if actual != sample.sha256:
        raise ValueError(
            f"sha256 mismatch after acquisition: expected {sample.sha256}, got {actual}"
        )
    dest.write_bytes(apk_bytes)

    manifest = _manifest_of(dest)
    db.execute(
        "UPDATE samples SET "
        "acquisition_status=?, apk_validation_status=?, apk_size=?, "
        "package_name=?, app_name=?, version_code=?, version_name=? "
        "WHERE sample_id=?",
        (
            AcquisitionStatus.COMPLETED.value,
            ValidationStatus.VALID.value,
            manifest.get("size_bytes", len(apk_bytes)),
            manifest.get("package_name") or sample.package_name,
            manifest.get("app_name") or sample.app_name,
            manifest.get("version_code") or sample.version_code,
            manifest.get("version_name") or sample.version_name,
            sample.sample_id,
        ),
    )
    db.execute(
        "INSERT OR REPLACE INTO label_evidence (sample_id, sha256, kind, value, source, fetched_at) VALUES (?,?,?,?,?,?)",
        (sample.sample_id, sample.sha256, "artifact_path", str(rel), sample.source, None),
    )


def _real_bytes(sample: SampleRecord, registry: dict) -> bytes:
    source = registry.get(sample.source)
    if source is None:
        raise SourceError(f"no source registered for {sample.source!r}")

    if sample.source in {"malwarebazaar_real", "malshare_real"}:
        return source.download(sample.sha256)

    if sample.source == "f_droid_real":
        return source.download_apk(sample.package_name, sample.version_code)

    if sample.source == "play_benign":
        file = source.locate_import_file(sample.sha256)
        if file is None:
            raise _ImportRequired(
                f"play_benign requires the import APK for {sample.sha256[:16]} "
                "in samples/import/ (residential fetch); run `findroid fetch-benign`"
            )
        return file.read_bytes()

    if sample.source == "import_malware":
        file = source.locate_import_file(sample.sha256)
        if file is None:
            raise _ImportRequired(
                f"import_malware requires a samples/import_malicious/ APK for {sample.sha256[:16]}"
            )
        return file.read_bytes()

    raise SourceError(f"no acquisition route for source {sample.source!r}")


def _manifest_of(apk_path: Path) -> dict:
    from .manifest import ApkReadError, read_apk_manifest

    try:
        return read_apk_manifest(apk_path)
    except ApkReadError:
        return {}
