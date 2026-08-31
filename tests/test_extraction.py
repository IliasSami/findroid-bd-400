"""Feature-extraction group contract (static_cert vs static_manifest)."""

from __future__ import annotations

import json
from pathlib import Path

from findroid.config import load_config
from findroid.extraction.extract import FEATURE_SCHEMA_VERSION, extract_one
from findroid.models import ClassLabel, ExtractionStatus, SampleRecord


def _sample() -> SampleRecord:
    return SampleRecord(
        sample_id="s1",
        sha256="0" * 64,
        source="mock",
        class_label=ClassLabel.BENIGN,
        package_name="com.example",
        version_code=1,
        version_name="1.0",
        label_confidence="B",
    )


def _descriptor() -> dict:
    return {
        "simulated": True,
        "min_sdk": 24,
        "target_sdk": 33,
        "apk_size_bytes": 1024,
        "dex_date": "2024-01-01",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
        ],
        "cert": {
            "subject_cn": "ORG",
            "org": "ORG",
            "issuer_cn": "ORG",
            "digest": "a" * 64,
        },
        "dex": {"classes_dx": 30, "methods_dx": 200, "strings_dx": ["otp code", "wallet"]},
    }


def test_cert_features_filed_under_static_cert_group(tmp_path: Path):
    cfg = load_config()
    artifact = tmp_path / "sample.mockapk.json"
    artifact.write_text(json.dumps(_descriptor()), encoding="utf-8")

    feats = list(extract_one(None, cfg, _sample(), artifact=artifact))
    groups = {f.feature_name: f.group for f in feats}

    for name in ("cert.cn", "cert.org", "cert.issuer_cn", "cert.digest"):
        assert groups[name] == "static_cert"
    assert groups["perm.android.permission.INTERNET"] == "static_manifest"
    assert groups["perm.android.permission.READ_SMS"] == "static_manifest"
    assert groups["sdk.min"] == "static_manifest"
    assert groups["str_ind.otp"] == "static_code"
    assert groups["str_ind.wallet"] == "static_code"

    for f in feats:
        assert f.sha256 == "0" * 64
        assert f.origin in {"simulated", "derived"}
        assert f.source_tool == "androgurd"
        assert f.extractor_version.endswith("-mock")
        assert f.extraction_status == ExtractionStatus.SUCCESS
    assert FEATURE_SCHEMA_VERSION == "1.0.0"
