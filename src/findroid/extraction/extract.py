"""Deterministic simulated static extraction.

The mock extractor reads the simulated manifest descriptor a strategy mirror of
the real Androguard walk — permissions, strings, certificates, dex metrics —
and emits :class:`FeatureRecord` rows. Every feature documents its ``origin``
(measured/derived), the ``source_tool`` (``androgurd``), the mock
``extractor_version``, and SIMULATED markers so real acquisitions can be
distinguished from development runs in every downstream analysis.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Generator
from pathlib import Path

from ..config import AppConfig
from ..models import (
    ErrorRecord,
    ExtractionRunRecord,
    ExtractionStatus,
    FeatureRecord,
    SampleRecord,
)

EXTRACTOR_VERSION = "0.3.0-mock"
FEATURE_SCHEMA_VERSION = "1.0.0"


def extract_one(
    db,
    cfg: AppConfig,
    sample: SampleRecord,
    *,
    artifact: Path,
) -> Generator[FeatureRecord, None, None]:
    """Yield feature records for one sample's simulated artifact."""
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    sha_full = sample.sha256
    base_env = dict(
        origin="simulated",
        source_tool="androgurd",
        extractor_version=EXTRACTOR_VERSION,
    )

    # static_manifest.permissions (group static_manifest)
    perms = payload.get("permissions", [])
    for p in perms:
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sha_full,
            feature_name=f"perm.{p}",
            value=1,
            dtype="int",
            group="static_manifest",
            **base_env,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # static_manifest sdk / dex / apk metrics (derived aggregations)
    yields = [
        ("sdk.min", payload.get("min_sdk")),
        ("sdk.target", payload.get("target_sdk")),
        ("dex.classes", payload.get("dex", {}).get("classes_dx")),
        ("dex.methods", payload.get("dex", {}).get("methods_dx")),
        ("apk.size_bytes", payload.get("apk_size_bytes")),
        ("dex.date", payload.get("dex_date")),
    ]
    for name, value in yields:
        if value is None:
            continue
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sha_full,
            feature_name=name,
            value=value,
            dtype="int" if isinstance(value, int) else "str",
            group="static_manifest",
            **base_env,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # static_cert group: certificate identity + digest (schema-declared group)
    cert_items = [
        ("cert.cn", payload.get("cert", {}).get("subject_cn")),
        ("cert.org", payload.get("cert", {}).get("org")),
        ("cert.issuer_cn", payload.get("cert", {}).get("issuer_cn")),
        ("cert.digest", payload.get("cert", {}).get("digest")),
    ]
    for name, value in cert_items:
        if value is None:
            continue
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sha_full,
            feature_name=name,
            value=value,
            dtype="str",
            group="static_cert",
            **base_env,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # static_code.strings + indicator flags (derived from string catalogue)
    hit_flags = _indicator_flags(payload.get("dex", {}).get("strings_dx", []))
    for name, flag in hit_flags.items():
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sha_full,
            feature_name=name,
            value=int(flag),
            dtype="int",
            group="static_code",
            **base_env,
            extraction_status=ExtractionStatus.SUCCESS,
        )
    # string catalogue sizes
    strings = payload.get("dex", {}).get("strings_dx", [])
    yield FeatureRecord(
        sample_id=sample.sample_id,
        sha256=sha_full,
        feature_name="dex.string_count",
        value=len(strings),
        dtype="int",
        group="static_code",
        **base_env,
        extraction_status=ExtractionStatus.SUCCESS,
    )

    # derived class signal + fintech strings present
    yield FeatureRecord(
        sample_id=sample.sample_id,
        sha256=sha_full,
        feature_name="is_simulated",
        value=1 if payload.get("simulated") else 0,
        dtype="int",
        group="static_code",
        **base_env,
        extraction_status=ExtractionStatus.SUCCESS,
    )


def run_extraction_for_all(
    db,
    cfg: AppConfig,
    *,
    limit: int | None = None,
) -> dict:
    """Extract features for all samples in the current staging state.

    ``cfg.development.mock_extraction`` selects the simulated backend (reads the
    ``.mockapk.json`` descriptor) or the real backend (androguard on a genuine
    APK). The emission schema is identical for both.
    """
    from . import static_real

    real = not cfg.development.mock_extraction and static_real.available()
    version = static_real.REAL_EXTRACTOR_VERSION if real else EXTRACTOR_VERSION
    schema_version = static_real.FEATURE_SCHEMA_VERSION if real else FEATURE_SCHEMA_VERSION

    rows = db.fetchall(
        "SELECT * FROM samples WHERE feature_extraction_status IN ('NOT_RUN','FAILED')"
        + (" LIMIT " + str(int(limit)) if limit else "")
    )
    tally: dict = {"success": 0, "partial": 0, "failed": 0}
    for row in rows:
        sample = SampleRecord(**dict(row))
        artifact = _locate_artifact(cfg, sample, real=real)
        if artifact is None:
            status = ExtractionStatus.FAILED
            db.add_extraction_run(
                ExtractionRunRecord(
                    run_id=sample.sample_id + ":x",
                    sample_id=sample.sample_id,
                    sha256=sample.sha256,
                    status=status,
                    extractor_version=version,
                    feature_schema_version=schema_version,
                    error_code="NO_ARTIFACT",
                    error_message="artifact descriptor not found",
                    created_at="",
                )
            )
            db.log_error(
                ErrorRecord(
                    stage="extraction",
                    sample_id=sample.sample_id,
                    sha256=sample.sha256,
                    error_code="NO_ARTIFACT",
                    message="missing artifact descriptor" if not real else "missing APK in vault",
                )
            )
            tally["failed"] += 1
            continue

        try:
            count = 0
            if real:
                for fe in static_real.extract_real_one(sample, artifact):
                    db.add_feature(fe)
                    count += 1
            else:
                for fe in extract_one(db, cfg, sample, artifact=artifact):
                    db.add_feature(fe)
                    count += 1
            status = ExtractionStatus.SUCCESS if count > 0 else ExtractionStatus.PARTIAL
        except Exception as exc:  # noqa: BLE001
            status = ExtractionStatus.FAILED
            db.log_error(
                ErrorRecord(
                    stage="extraction",
                    sample_id=sample.sample_id,
                    sha256=sample.sha256,
                    error_code="EXTRACT",
                    message=str(exc),
                )
            )
            count = 0
        db.execute(
            "UPDATE samples SET feature_extraction_status=? WHERE sample_id=?",
            (status.value, sample.sample_id),
        )
        db.add_extraction_run(
            ExtractionRunRecord(
                run_id=f"{sample.sample_id}:{hashlib.sha256(sample.sha256.encode()).hexdigest()[:8]}",
                sample_id=sample.sample_id,
                sha256=sample.sha256,
                status=status,
                extractor_version=version,
                feature_schema_version=schema_version,
                feature_count=count,
                created_at="",
            )
        )
        tally["success"] += 1 if status == ExtractionStatus.SUCCESS else 0
        tally["partial"] += 1 if status == ExtractionStatus.PARTIAL else 0
        tally["failed"] += 1 if status == ExtractionStatus.FAILED else 0
    db.commit()
    return tally


def _locate_artifact(cfg: AppConfig, sample: SampleRecord, *, real: bool = False) -> Path | None:
    if not real:
        rel = Path(sample.class_label.value) / sample.sha256[:2] / (sample.sha256 + ".mockapk.json")
        p = cfg.samples_root / rel
        return p if p.exists() else None
    for suffix in (".apk", ".apk.zip"):
        rel = Path(sample.class_label.value) / sample.sha256[:2] / (sample.sha256 + suffix)
        p = cfg.samples_root / rel
        if p.exists():
            return p
    return None


_STRING_FLAG_GROUPS = {
    "otp": ["otp", "one time pass", "verification code"],
    "sms": ["sms", "message center"],
    "ussd": ["ussd"],
    "overlay": ["overlay", "screen overlay", "touch overlay"],
    "accessibility": ["accessibility", "nodeinfo"],
    "bank_brand": ["bkash", "nagad", "rocket", "bank", "banking"],
    "wallet": ["wallet", "mobile wallet", "purse", "e wallet"],
    "payment": ["payment", "transaction", "transfer", "merchant qr"],
    "credential": ["credential", "password", "pin", "login", "passcode", "seed phrase"],
}


def _indicator_flags(strings: list[str]) -> dict:
    flags: dict = {}
    hay = [s.lower() for s in strings]
    for group, needles in _STRING_FLAG_GROUPS.items():
        flags[f"str_ind.{group}"] = any(any(n in h for n in needles) for h in hay)
    return flags
