"""Deterministic simulated APK artifacts.

In mock mode a "downloaded APK" is a JSON descriptor (``.mockapk.json``) with a
SHA-256 over the *simulated artifact bytes*, so the uniqueness domain and the
acquisition/validation/extraction contracts stay identical to real mode.

The manifest synthesizer encodes the project's domain knowledge into the
permission/string footprints:

* benign fintech apps request modest, category-consistent permissions;
* lending and agent apps legitimately request READ_SMS (credit-risk scoring /
  transaction SMS receipts) — matching real BD fintech behaviour;
* banking Trojans request SMS/accessibility/overlay/querysystem per their family
  ``primary_techniques`` (overlay, accessibility abuse, SMS/OTP interception,
  USSD automation, remote access, keylogging).
"""

from __future__ import annotations

import hashlib
import json

from ..models import ClassLabel, SampleRecord

# benign baseline always present for network clients
_BENIGN_BASE_PERMS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.VIBRATE",
]

# category -> extra permissions (documented real-world footprint)
_BENIGN_BY_SUBSECTOR: dict[str, list[str]] = {
    "mfs_wallet": [
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_CONTACTS",
    ],
    "mfs_agent": [
        "android.permission.READ_SMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.CAMERA",
    ],
    "bank_retail": [
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.NFC",
    ],
    "digital_banking": [
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
    ],
    "psp_wallet": [
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_CONTACTS",
    ],
    "merchant_pos": [
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.ACCESS_FINE_LOCATION",
    ],
    "sme_ledger": [
        "android.permission.READ_SMS",
        "android.permission.READ_EXTERNAL_STORAGE",
    ],
    "interop_rail": ["android.permission.CAMERA"],
    "remittance": ["android.permission.CAMERA", "android.permission.READ_CONTACTS"],
    "neobank": ["android.permission.CAMERA"],
    "crypto_exchange": ["android.permission.CAMERA"],
    "crypto_wallet": ["android.permission.CAMERA", "android.permission.USE_BIOMETRIC"],
    "lending": ["android.permission.READ_SMS", "android.permission.READ_CONTACTS"],
    "investment": ["android.permission.CAMERA", "android.permission.NFC"],
    "insurance": ["android.permission.CAMERA", "android.permission.READ_EXTERNAL_STORAGE"],
    "microfinance": ["android.permission.READ_SMS", "android.permission.CAMERA"],
    "fintech_utility": ["android.permission.CAMERA", "android.permission.READ_EXTERNAL_STORAGE"],
}

# Trojans: technique -> android feature set (from the threat-family catalogue)
_MAL_PERMS: dict[str, list[str]] = {
    "overlay": [
        "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ],
    "accessibility": [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.QUERY_ALL_PACKAGES",
    ],
    "keylogger": [
        "android.permission.INPUT_METHOD_MANAGER",
    ],
    "sms/otp": [
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_PHONE_STATE",
    ],
    "ussd": [
        "android.permission.CALL_PHONE",
        "android.permission.SEND_SMS",
    ],
    "remote": [
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    ],
    "recordings": [
        "android.permission.RECORD_AUDIO",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ],
    "hidden": [
        "android.permission.HIDE_OVERLAY_PACKAGES",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    ],
}

_MAL_INFRA = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
]

# ICDN identifiers referenced by mock string-extraction
_MALICIOUS_STRINGS: dict[str, list[str]] = {
    "overlay": ["overlay", "touch overlay", "screen overlay"],
    "accessibility": ["accessibility", "accessibilityservice", "nodeinfo"],
    "sms/otp": ["otp", "one time pass", "verification code", "sms", "message center"],
    "ussd": ["ussd", "*247#", "*162#", "*111#"],
    "bank": ["bank", "banking", "bkash", "nagad", "rocket", "transact"],
    "wallet": ["wallet", "e wallet", "mobile wallet", "purse"],
    "payment": ["payment", "transaction", "transfer", "merchant qr"],
    "credential": ["credential", "password", "pin", "login", "passcode"],
}

_BENIGN_STRINGS: dict[str, list[str]] = {
    "mfs": ["balance", "cashout", "send money", "pin", "transaction"],
    "bank": ["acount", "statement", "card", "iban", "otp"],
    "lend": ["loan", "emi", "installment", "credit"],
    "crypto": ["wallet", "address", "private key", "seed phrase"],
    "general": ["notification", "settings", "profile", "help"],
}


def _token(key: str, salt: str) -> str:
    return hashlib.sha256(f"{key}:{salt}".encode()).hexdigest()


def _pick_many(rng, pool: list[str], n: int) -> list[str]:
    items = rng.sample(pool, min(n, len(pool)))
    return sorted(items)


class MockManifest:
    """Simulated outcome of an Androguard parse of a (nonexistent) real APK."""

    def __init__(self, **fields: object):
        self.fields = fields

    def to_dict(self) -> dict[str, object]:
        return dict(self.fields)

    def json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()


def synth_manifest(sample: SampleRecord, salt: str, rng) -> MockManifest:
    """Deterministically synthesize a manifest descriptor for *sample*."""
    package = sample.package_name
    version = f"{sample.version_name or '1.0'}.{sample.version_code}"

    if sample.class_label == ClassLabel.MALICIOUS:
        perms, strings = _malicious_profile(sample, rng)
        target_sdk = rng.randint(23, 34)
        min_sdk = rng.randint(16, 26)
        cert_ou = _malicious_cert(sample, rng)
        uses_feature: list[str] = []
        if "android.permission.QUERY_ALL_PACKAGES" in perms:
            uses_feature.append("android.hardware.touchscreen")
    else:
        perms, strings = _benign_profile(sample, rng)
        target_sdk = rng.randint(26, 35)
        min_sdk = rng.randint(19, 29)
        cert_ou = sample.package_name.split(".")[0].upper()
        uses_feature = ["android.hardware.camera"]

    size_kb = rng.randint(1500, 9500)
    dex_date = sample.dex_date or "2024-01-01"

    fields: dict[str, object] = {
        "package": package,
        "version_name": str(sample.version_name or "1.0"),
        "version_code": sample.version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": perms,
        "uses_features": uses_feature,
        "cert": {
            "subject_cn": f"{cert_ou} (simulated)",
            "org": cert_ou,
            "issuer_cn": cert_ou,
            "digest": _token(f"cert:{package}:{version}", salt),
        },
        "dex": {
            "classes_dx": rng.randint(120, 2200),
            "methods_dx": rng.randint(900, 21000),
            "strings_dx": strings,
        },
        "apk_size_bytes": size_kb * 1024,
        "dex_date": dex_date,
        "sha256_artifact": "",
        "simulated": True,
    }
    # artifact hash over the serialized descriptor minus the hash field
    ctx = hashlib.sha256(json.dumps(fields, sort_keys=True).encode())
    fields["sha256_artifact"] = ctx.hexdigest()
    return MockManifest(**fields)


def _subsector_perms(sample: SampleRecord, rng) -> list[str]:
    base = list(_BENIGN_BASE_PERMS)
    extra = _BENIGN_BY_SUBSECTOR.get(sample.fintech_category, [])
    if extra:
        k = rng.randint(0, len(extra))
        base.extend(rng.sample(extra, k))
    return sorted(set(base))


def _benign_profile(sample: SampleRecord, rng) -> tuple[list[str], list[str]]:
    perms = _subsector_perms(sample, rng)
    strings: list[str] = []
    cat = sample.fintech_category
    if cat in {"lending", "sme_ledger", "microfinance"}:
        strings += _BENIGN_STRINGS["lend"]
    if cat in {"mfs_wallet", "mfs_agent", "psp_wallet", "sme_ledger"}:
        strings += _BENIGN_STRINGS["mfs"]
    if cat in {"bank_retail", "digital_banking"}:
        strings += _BENIGN_STRINGS["bank"]
    if cat in {"crypto_exchange", "crypto_wallet"}:
        strings += _BENIGN_STRINGS["crypto"]
    strings += _BENIGN_STRINGS["general"]
    return perms, sorted(set(strings))


def _malicious_profile(sample: SampleRecord, rng) -> tuple[list[str], list[str]]:
    # techniques drawn from the family object when available, else a generic banker
    fam = _family_lookup(sample.family) if sample.family else None
    techniques: str = "keylogging; sms/otp; overlay"
    if fam is not None:
        techniques = fam.techniques.lower()

    perms = list(_MAL_INFRA)
    strings: list[str] = []
    for keyword, pool in _MALICIOUS_STRINGS.items():
        if keyword in {"bank", "wallet", "payment", "credential"}:
            strings += _pick_many(rng, pool, rng.randint(1, 3))

    if "overlay" in techniques:
        perms += _MAL_PERMS["overlay"]
        strings += _MALICIOUS_STRINGS["overlay"]
    if "accessibility" in techniques or "accessibility abuse" in techniques:
        perms += _MAL_PERMS["accessibility"]
        strings += _MALICIOUS_STRINGS["accessibility"]
    if "sms" in techniques or "otp" in techniques:
        perms += _MAL_PERMS["sms/otp"]
        strings += _MALICIOUS_STRINGS["sms/otp"]
    if "ussd" in techniques:
        perms += _MAL_PERMS["ussd"]
        strings += _MALICIOUS_STRINGS["ussd"]
    if "remote" in techniques or "device-takeover" in techniques or "vnc" in techniques:
        perms += _MAL_PERMS["remote"]
    if "keylog" in techniques or "keylogging" in techniques:
        perms += _MAL_PERMS["keylogger"]
    if "screen" in techniques or "recording" in techniques:
        perms += _MAL_PERMS["recordings"]
    if "hidden" in techniques:
        perms += _MAL_PERMS["hidden"]
    return sorted(set(perms)), sorted(set(strings))


def _family_lookup(name: str):
    from ..config import PROJECT_ROOT
    from .mock_malware import build_family_catalogue

    cat = build_family_catalogue(PROJECT_ROOT / "metadata" / "threat_families.csv")
    return cat.get(name)


def _malicious_cert(sample: SampleRecord, rng) -> str:
    if "sikkahbot" in (sample.family or "").lower():
        return "KOTHASOFT_WEB_SOLUTIONS"  # Cyble-documented cert for SikkahBot-adjacent app
    return sample.family.replace(" ", "_")[:20].upper() or "UNKNOWN_CERT"
