"""Real MalShare source adapter.

MalShare has no family-signature taxonomy, so it cannot produce *labelled*
malicious candidates on its own (a candidate without family evidence would fail
verification). Its genuine value here is download capacity: ``getfile`` serves
raw APK bytes under a large per-day quota, acting as a backfill when
MalwareBazaar rate-limits.

Discovery stays available (list 24h hashes / hashes of ``Android`` type) but
returns candidates only when the API actually returns rows — today those
windows are empty, so discovery yields nothing without surprising anyone.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Iterable
from urllib.parse import urlencode

import requests

from ..models import CandidateRecord, ClassLabel, VerificationStatus
from .base import BaseSource, SourceError

MALSHARE_API = "https://malshare.com/api.php"


class MalShareError(SourceError):
    """Raised when the MalShare API cannot satisfy the request."""


class MalShareSource(BaseSource):
    kind = "malshare_real"

    def __init__(self, api_key: str = ""):
        super().__init__("malshare_real")
        self._api_key = api_key.strip()

    def credentials_ok(self) -> bool:
        return bool(self._api_key)

    def _get(self, params: dict[str, str]) -> bytes:
        query = {**params, "api_key": self._api_key}
        resp = requests.get(f"{MALSHARE_API}?{urlencode(query)}", timeout=60)
        resp.raise_for_status()
        return resp.content

    # --------------------------------------------------------------- discovery
    def discover(self, *, limit: int | None = None) -> Iterable[CandidateRecord]:
        if not self.credentials_ok():
            raise MalShareError("MalShare credentials missing (set MALSHARE_API_KEY)")
        hashes: list[str] = []
        for action in ("getlist", "type"):
            try:
                if action == "type":
                    body = self._get({"action": "type", "type": "Android"})
                else:
                    body = self._get({"action": action})
                parsed = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(parsed, list):
                    hashes = [h for h in parsed if isinstance(h, str)]
                    if hashes:
                        break
            except Exception:  # noqa: BLE001
                continue
        out: list[CandidateRecord] = []
        for h in hashes[:limit] if limit else hashes:
            h = h.strip().lower()
            if len(h) != 64:
                continue
            evidence = {
                "source": "MalShare",
                "type": "Android",
                "note": "MalShare Android sample; family unclassified — review required",
            }
            out.append(
                CandidateRecord(
                    candidate_id=f"ms-{h[:16]}",
                    source="malshare_real",
                    sha256=h,
                    package_name="",
                    app_name="",
                    version_code=0,
                    version_name="",
                    market="",
                    category="",
                    country="",
                    dex_date=None,
                    vt_detection=None,
                    vt_scan_date=None,
                    first_seen_date=None,
                    play_verification_date=None,
                    suspected_class=ClassLabel.MALICIOUS,
                    suspected_family="",
                    fintech_category="",
                    fintech_basis="",
                    targeting_basis="",
                    evidence=json.dumps(evidence, sort_keys=True),
                    source_reference=f"{MALSHARE_API}?action=details&hash={h}",
                    source_timestamp="",
                    verification_status=VerificationStatus.PENDING,
                )
            )
        return out

    # ---------------------------------------------------------------- download
    def download(self, sha256: str) -> bytes:
        """Return verified bytes for ``sha256`` (``infected`` archive-aware)."""
        if not self.credentials_ok():
            raise MalShareError("MalShare credentials missing (set MALSHARE_API_KEY)")
        target = (sha256 or "").strip().lower()
        if len(target) != 64 or not all(c in "0123456789abcdef" for c in target):
            raise MalShareError(f"invalid sha256 requested: {sha256!r}")
        try:
            body = self._get({"action": "getfile", "hash": target})
        except Exception as exc:  # noqa: BLE001
            raise MalShareError(f"getfile failed for {target}: {exc}") from exc
        apk = _unwrap_apk(body)
        actual = hashlib.sha256(apk).hexdigest()
        if actual != target:
            raise MalShareError(
                f"sha256 mismatch after download: expected {target}, got {actual}"
            )
        return apk


def _unwrap_apk(body: bytes) -> bytes:
    """MalShare serves raw bytes; some rows arrive as ``infected`` ZIPs."""
    if body[:2] != b"PK":
        return body
    for opener, pwd in ((zipfile.ZipFile, b"infected"), (zipfile.ZipFile, None)):
        try:
            with opener(io.BytesIO(body)) as zf:
                members = zf.namelist()
                apk = next((n for n in members if n.endswith(".apk")), "")
                if not apk and members:
                    raise MalShareError(f"no APK member in archive: {members[:4]}")
                if pwd is None:
                    return zf.read(apk)
                return zf.read(apk, pwd=pwd)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
            continue
    raise MalShareError("cannot unpack MalShare archive (unsupported compression/encryption)")


__all__ = ["MalShareError", "MalShareSource", "MALSHARE_API"]
