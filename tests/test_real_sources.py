"""Offline unit tests for the real-mode source adapters.

All tests here run without network access: candidate construction, archive
unpacking (password + AES), JSON-LD parsing, catalogue loading, filename
family aliasing and registry wiring.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import pyzipper

from findroid.config import PROJECT_ROOT, AppConfig
from findroid.sources import f_droid
from findroid.sources import malshare_real as ms
from findroid.sources import malwarebazaar_real as mb
from findroid.sources.import_malware import ImportMalwareSource, _family_from_path
from findroid.sources.mock_benign import load_benign_seed_catalog
from findroid.sources.mock_malware import build_family_catalogue
from findroid.sources.play import (
    _first_software_application,
    _install_min_from_text,
    _meta_items,
)
from findroid.sources.registry import SourceError as RegSourceError
from findroid.sources.registry import build_source_registry

# --------------------------------------------------------------------------- MB

_A_ROW = {
    "sha256_hash": "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782",
    "file_type": "apk",
    "file_name": "install.apk",
    "file_size": 4134252,
    "first_seen": "2026-08-22 09:14:00 UTC",
    "tags": ["Android", "banking", "GodFather"],
    "ssdeep": "1536:abcd",
}


def test_mb_candidate_construction():
    src = mb.MalwareBazaarSource(api_key="unit-test-key")
    rec = src._to_candidate(dict(_A_ROW), family="Godfather", signature="GodFather")
    assert rec is not None
    assert rec.suspected_class.value == "malicious"
    assert rec.suspected_family == "Godfather"
    assert rec.sha256 == _A_ROW["sha256_hash"]
    assert rec.source == "malwarebazaar_real"
    assert rec.vt_detection is None
    assert rec.source_reference.endswith(_A_ROW["sha256_hash"])
    ev = json.loads(rec.evidence)
    assert ev["family_confidence"] == "A"
    assert ev["signature"] == "GodFather"


def test_mb_candidate_rejects_bad_rows():
    src = mb.MalwareBazaarSource(api_key="unit-test-key")
    bad = dict(_A_ROW)
    bad["sha256_hash"] = "not-a-sha"
    assert src._to_candidate(bad, family="Godfather", signature="GodFather") is None
    bad2 = dict(_A_ROW)
    bad2["file_type"] = "pe"
    assert src._to_candidate(bad2, family="Godfather", signature="GodFather") is None


def test_mb_family_from_tags():
    assert mb._family_from_tags(["Android", "banking", "GodFather"]) == "Godfather"
    assert mb._family_from_tags(["octo / coper / exobotv2"]) == "Octo / Coper / ExobotV2"
    assert mb._family_from_tags(["nope"]) == ""


def test_mb_decompress_aes_zip():
    payload = b"\x50\x4b\x03\x04fake-apk-bytes"
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_LZMA) as zf:
        zf.setpassword(mb.MB_DOWNLOAD_PASSWORD)
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.writestr("sample.apk", payload)
    buf.seek(0)
    out = mb._decompress_apk(buf.getvalue(), "0" * 64)
    assert out == payload


def test_mb_sha_format_guard():
    with pytest.raises(mb.MalwareBazaarError):
        mb._expect_sha_format("abcd")
    mb._expect_sha_format("a" * 64)


# ---------------------------------------------------------------------- MalShare

def test_malshare_unwrap_infected_aes_raises():
    """AES archives are MalwareBazaar's format; MalShare legacy zips use
    ZipCrypto. An AES archive must fail loudly instead of corrupting bytes."""
    payload = b"PK\x03\x04-aes-malware"
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED) as zf:
        zf.setpassword(b"infected")
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.writestr("carrier.apk", payload)
    buf.seek(0)
    with pytest.raises(ms.MalShareError):
        ms._unwrap_apk(buf.getvalue())


def test_malshare_unwrap_plain_zip():
    payload = b"PK\x03\x04-plain"
    buf = io.BytesIO()
    with pyzipper.ZipFile(buf, "w") as zf:
        zf.writestr("carrier.apk", payload)
    buf.seek(0)
    assert ms._unwrap_apk(buf.getvalue()) == payload


# ------------------------------------------------------------------------- F-Droid

def test_fdroid_catalogue_loader():
    cat = f_droid.load_fdroid_catalogue(
        PROJECT_ROOT / "metadata" / "fdroid_fintech_ids.csv"
    )
    assert len(cat) >= 4
    assert {"de.schildbach.wallet", "org.electrum.electrum"} <= {
        e["package_id"] for e in cat
    }
    for entry in cat:
        assert entry["package_id"] and entry["app_name"]


def test_fdroid_repo_url_template():
    assert f_droid.FDROID_REPO.startswith("https://f-droid.org/repo/")
    assert f_droid.FDROID_API.startswith("https://f-droid.org/api/v1/")
    url = f"{f_droid.FDROID_REPO}de.schildbach.wallet_110300.apk"
    assert url.endswith("de.schildbach.wallet_110300.apk")


def test_fdroid_utility_label():
    assert f_droid.fintech_utility_label({"subsector": "crypto_wallet"}) == "crypto_wallet"
    assert f_droid.fintech_utility_label({"subsector": "fintech_utility"}) == "fintech_utility"
    assert f_droid.fintech_utility_label({"package_id": "com.x.y"}) == "fintech_utility"


# -------------------------------------------------------------------------- Play

_PLAY_HTML = """
<html><body>
<script type="application/ld+json">
[
 {"@context":"https://schema.org"},
 {"@type":"SoftwareApplication","name":"bKash",
  "operatingSystem":"ANDROID",
  "aggregateRating":{"@type":"AggregateRating","ratingValue":"4.4032","ratingCount":"1683035"},
  "offers":{"@type":"Offer","price":"0","priceCurrency":"BDT"},
  "datePublished":"2024-01-05","dateModified":"2025-06-11",
  "applicationCategory":"Finance",
  "interactionStatistic":{"@type":"InteractionCounter","userInteractionCount":"100000000"}}
]
</script>
<meta itemprop="installCount" content="350000000" />
</body></html>
"""


def test_play_jsonld_extract():
    app = _first_software_application(_PLAY_HTML)
    assert app is not None
    assert app["name"] == "bKash"
    rating = app["aggregateRating"]
    assert rating["ratingCount"] == "1683035"
    assert app["offers"]["priceCurrency"] == "BDT"


def test_play_meta_and_install():
    assert "350000000" in _meta_items(_PLAY_HTML, "installCount")
    assert _install_min_from_text(["10M+"]) == "10M+"
    assert _install_min_from_text([]) is None


# ------------------------------------------------------------------ import channels

@pytest.fixture
def _families():
    return build_family_catalogue(PROJECT_ROOT / "metadata" / "threat_families.csv")


def test_import_family_alias(_families):
    assert _family_from_path(Path("godfather__x.apk"), _families) == "Godfather"
    assert _family_from_path(Path("octo__x.apk"), _families) == "Octo / Coper / ExobotV2"
    assert _family_from_path(Path("sikkahbot__x.apk"), _families) == "SikkahBot"
    assert _family_from_path(Path("random.apk"), _families) == ""


def test_import_malware_discover(tmp_path, monkeypatch, _families):
    fake = tmp_path / "teabot__carrier.apk"
    fake.write_bytes(b"\x00\x01\x02")
    manifest = {
        "package_name": "com.trojan.mobilebanking",
        "app_name": "MBank",
        "version_code": 1,
        "version_name": "1.0",
        "sha256": "f" * 64,
        "size_bytes": 3,
        "dex_count": 1,
    }
    import findroid.sources.import_malware as im

    monkeypatch.setattr(im, "read_apk_manifest", lambda _path: dict(manifest))
    src = ImportMalwareSource(import_root=tmp_path, families=_families)
    recs = list(src.discover())
    assert len(recs) == 1
    rec = recs[0]
    assert rec.suspected_class.value == "malicious"
    assert rec.suspected_family == "Anatsa / TeaBot"
    assert rec.package_name == "com.trojan.mobilebanking"
    ev = json.loads(rec.evidence)
    assert ev["filename_family"] == "Anatsa / TeaBot"


# ----------------------------------------------------------------------- registry

def test_registry_mock_mode():
    cfg = AppConfig()
    srcs = build_source_registry(cfg)
    assert set(srcs) == {"mock_play", "mock_malwarebazaar"}


def test_registry_real_requires_config(monkeypatch):
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
    cfg = AppConfig()
    cfg.development.mock_sources = False
    cfg.development.allow_real_apks = False
    with pytest.raises(RegSourceError):
        build_source_registry(cfg)


def test_registry_real_drops_only(monkeypatch):
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
    cfg = AppConfig()
    cfg.development.mock_sources = False
    cfg.development.allow_real_apks = True
    srcs = build_source_registry(cfg)
    assert {"f_droid_real", "play_benign", "import_malware"} <= set(srcs)
    assert "malwarebazaar_real" not in srcs


def test_benign_catalog_loads():
    cat = load_benign_seed_catalog(PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv")
    bd = [p for p in cat.values() if p.country == "BD"]
    assert bd, "expected BD packages in the seed catalogue"
    assert all(p.app_name and p.subsector and p.verification_status for p in bd)
