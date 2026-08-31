"""Real static feature extraction (androguard, no Java).

Reads a genuine APK and emits exactly the same feature schema as the mock
extractor (``perm.*``, ``sdk.*``, ``apk.size_bytes``, ``dex.*``, ``dex.date``,
``cert.*``, ``str_ind.*``, ``is_simulated``) so every downstream stage is
backend-agnostic. Provenance is explicit: ``origin`` is ``measured`` or
``derived``, ``source_tool`` is the androguard version, and the extractor
version is suffixed ``-real`` so simulated and measured rows can never be
confused downstream.

No dynamic analysis and no execution happen here. We only open the APK as a
ZIP and parse binary structures (manifest, signing block, dex string pool).
"""

from __future__ import annotations

import hashlib
import logging
import zipfile
from collections.abc import Generator
from pathlib import Path

try:
    from loguru import logger as _logger

    _logger.disable("androguard")
except Exception:  # noqa: BLE001
    pass
logging.disable(logging.CRITICAL)

from ..models import ExtractionStatus, FeatureRecord, SampleRecord  # noqa: E402

try:
    from androguard import __version__ as _ANDROGUARD_VERSION
    from androguard.core.apk import APK
except Exception as exc:  # noqa: BLE001  (reflexive import guard)
    _ANDROGUARD_VERSION = "unavailable"
    APK = None  # type: ignore[assignment]
    _APK_IMPORT_ERROR = str(exc)
else:
    _APK_IMPORT_ERROR = ""

TOOL: str = f"androguard:{_ANDROGUARD_VERSION}"
REAL_EXTRACTOR_VERSION = "1.0.0-real"
FEATURE_SCHEMA_VERSION = "1.1.0"

# Indicator needles kept byte-identical to the mock extractor.
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


class RealExtractionError(RuntimeError):
    """Raised when a sample's APK cannot be parsed at all."""


def available() -> bool:
    return APK is not None


def extract_real_one(
    sample: SampleRecord,
    apk_path: Path,
) -> Generator[FeatureRecord, None, None]:
    """Yield measured/derived feature records for a genuine APK file."""
    if not available():
        raise RealExtractionError(f"androguard unavailable: {_APK_IMPORT_ERROR}")
    path = Path(apk_path)
    if not path.is_file():
        raise RealExtractionError(f"APK file missing: {path}")
    if _apk_is_simulated(path):
        raise RealExtractionError(f"refusing SIMULATED descriptor as real APK: {path.name}")

    apk = APK(str(path))
    apk_size = path.stat().st_size
    base_env = dict(
        origin="measured",
        source_tool=TOOL,
        extractor_version=REAL_EXTRACTOR_VERSION,
    )

    # static_manifest: permissions
    perms = sorted(set(_clean(p) for p in apk.get_permissions() if p))
    for p in perms:
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sample.sha256,
            feature_name=f"perm.{p}",
            value=1,
            dtype="int",
            group="static_manifest",
            **base_env,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # static_manifest: sdk / apk metrics
    min_sdk = _int_or_none(apk.get_min_sdk_version())
    target_sdk = _int_or_none(apk.get_target_sdk_version())
    for name, value, dtype in (
        ("sdk.min", min_sdk, "int"),
        ("sdk.target", target_sdk, "int"),
        ("apk.size_bytes", apk_size, "int"),
    ):
        if value is None:
            continue
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sample.sha256,
            feature_name=name,
            value=value,
            dtype=dtype,
            group="static_manifest",
            origin="derived" if name in {"sdk.min", "apk.size_bytes"} else "measured",
            source_tool=TOOL,
            extractor_version=REAL_EXTRACTOR_VERSION,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # static_manifest: dex build-date derived from the zip entry timestamps
    dex_date = _dex_build_date(path)
    if dex_date:
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sample.sha256,
            feature_name="dex.date",
            value=dex_date,
            dtype="str",
            group="static_manifest",
            origin="derived",
            source_tool=TOOL,
            extractor_version=REAL_EXTRACTOR_VERSION,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # static_cert: signing certificate identity + digest
    for cert_name, cert_value in _cert_features(apk):
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sample.sha256,
            feature_name=cert_name,
            value=cert_value,
            dtype="str",
            group="static_cert",
            **base_env,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # static_code: dex metrics + string indicator flags
    dex_metrics = _dex_metrics(apk)
    for fname, value, dtype in (
        ("dex.classes", dex_metrics.get("classes"), "int"),
        ("dex.methods", dex_metrics.get("methods"), "int"),
        ("dex.string_count", dex_metrics.get("strings"), "int"),
    ):
        if value is None:
            continue
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sample.sha256,
            feature_name=fname,
            value=value,
            dtype=dtype,
            group="static_code",
            origin="measured",
            source_tool=TOOL,
            extractor_version=REAL_EXTRACTOR_VERSION,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    for name, flag in _indicator_flags(dex_metrics.get("strings_list", [])).items():
        yield FeatureRecord(
            sample_id=sample.sample_id,
            sha256=sample.sha256,
            feature_name=name,
            value=int(flag),
            dtype="int",
            group="static_code",
            origin="derived",
            source_tool=TOOL,
            extractor_version=REAL_EXTRACTOR_VERSION,
            extraction_status=ExtractionStatus.SUCCESS,
        )

    # every real row is explicitly not simulated
    yield FeatureRecord(
        sample_id=sample.sample_id,
        sha256=sample.sha256,
        feature_name="is_simulated",
        value=0,
        dtype="int",
        group="static_code",
        **base_env,
        extraction_status=ExtractionStatus.SUCCESS,
    )


# --------------------------------------------------------------------------- helpers
def _apk_is_simulated(path: Path) -> bool:
    return path.suffix in {".json", ".mockapk.json"} or path.name.startswith("mock")


def _clean(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _int_or_none(value) -> int | None:
    if value in (None, "", "N/A"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dex_build_date(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as zf:
            dates = [
                zf.getinfo(n).date_time
                for n in zf.namelist()
                if n.startswith("classes") and n.endswith(".dex")
            ]
        if not dates:
            return None
        import datetime

        earliest = min(datetime.datetime(y, m, d, h, mi, s) for y, m, d, h, mi, s in dates)
        return earliest.date().isoformat()
    except Exception:  # noqa: BLE001
        return None


def _cert_features(apk) -> list[tuple[str, str]]:
    """Subject/issuer identity + DER SHA-256 digest of the signing certificate."""
    try:
        cert = apk.get_certificates()
    except Exception:  # noqa: BLE001
        return []
    if not cert:
        return []
    c0 = cert[0]
    try:
        subject = dict(c0.subject.native or {})
        issuer = dict(c0.issuer.native or {})
    except Exception:  # noqa: BLE001
        subject, issuer = {}, {}
    try:
        digest = hashlib.sha256(c0.dump()).hexdigest()
    except Exception:  # noqa: BLE001
        digest = ""
    out: list[tuple[str, str]] = []
    if subject.get("common_name"):
        out.append(("cert.cn", subject["common_name"]))
    if subject.get("organization_name"):
        out.append(("cert.org", subject["organization_name"]))
    if issuer.get("common_name"):
        out.append(("cert.issuer_cn", issuer["common_name"]))
    if digest:
        out.append(("cert.digest", digest))
    return out


def _dex_metrics(apk) -> dict:
    metrics: dict = {"classes": None, "methods": None, "strings": None, "strings_list": []}
    try:
        dex_units = apk.get_dex()
    except Exception:  # noqa: BLE001
        return metrics
    if not dex_units:
        return metrics
    try:
        d0 = dex_units[0]
        metrics["classes"] = d0.get_class_manager().get_classes_length()
        metrics["methods"] = len(d0.get_methods())
    except Exception:  # noqa: BLE001
        pass
    strings: list[str] = []
    try:
        for item in d0.get_strings():
            strings.append(_clean(item))
    except Exception:  # noqa: BLE001
        pass
    metrics["strings"] = len(strings)
    metrics["strings_list"] = strings
    return metrics


def _indicator_flags(strings: list[str]) -> dict:
    flags: dict = {}
    hay = [s.lower() for s in strings]
    for group, needles in _STRING_FLAG_GROUPS.items():
        flags[f"str_ind.{group}"] = any(any(n in h for n in needles) for h in hay)
    return flags
