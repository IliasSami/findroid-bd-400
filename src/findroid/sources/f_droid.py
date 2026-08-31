"""Real F-Droid source adapter.

F-Droid is reachable from this machine and serves genuine APK bytes, which
makes it the *engineering* channel that proves the real acquisition + extraction
path on benign files without a residential device. Mainstream BD fintech apps
are not published on F-Droid, so this adapter is auxiliary: candidates carry a
real SHA-256 (computed by downloading the official APK at discovery) but are
not members of the BD seed catalogue and therefore land in the review queue
unless adjudicated.

Discovery downloads each package once to compute the authentic SHA-256 hash
(the ``/api/v1/packages`` endpoint does not expose hashes). The curated list
lives in ``metadata/fdroid_fintech_ids.csv``.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

import requests

from ..models import CandidateRecord, ClassLabel, VerificationStatus, utcnow
from .base import BaseSource, SourceError

FDROID_API = "https://f-droid.org/api/v1/packages/{pkg}"
FDROID_REPO = "https://f-droid.org/repo/{pkg}_{version_code}.apk"
FDROID_PAGE = "https://f-droid.org/en/packages/{pkg}/"


class FDroidError(SourceError):
    """Raised when F-Droid cannot satisfy the request."""


def load_fdroid_catalogue(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append({k: (v or "").strip() for k, v in row.items()})
    return rows


class FDroidSource(BaseSource):
    kind = "f_droid_real"

    def __init__(self, catalogue: list[dict] | None = None, *, timeout: float = 60):
        super().__init__("f_droid_real")
        self._catalogue = catalogue or []
        self._timeout = timeout

    def credentials_ok(self) -> bool:
        return bool(self._catalogue)

    @classmethod
    def from_metadata(cls, path: Path) -> FDroidSource:
        return cls(load_fdroid_catalogue(path))

    # ------------------------------------------------------------- metadata
    def package_versions(self, package_id: str) -> dict:
        try:
            resp = requests.get(FDROID_API.format(pkg=package_id), timeout=self._timeout)
            resp.raise_for_status()
            info = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise FDroidError(f"F-Droid package lookup failed for {package_id}: {exc}") from exc
        packages = info.get("packages") or []
        suggested = info.get("suggestedVersionCode")
        best = next((p for p in packages if p.get("versionCode") == suggested), packages[0] if packages else None)
        if best is None:
            raise FDroidError(f"no versions for F-Droid package {package_id}")
        return {
            "package_id": package_id,
            "version_code": best.get("versionCode"),
            "version_name": best.get("versionName"),
            "suggested_version_code": suggested,
        }

    # ------------------------------------------------------------- discovery
    def discover(self, *, limit: int | None = None) -> Iterable[CandidateRecord]:
        now = utcnow()
        out: list[CandidateRecord] = []
        for entry in self._catalogue:
            if limit and len(out) >= limit:
                break
            pkg = entry["package_id"]
            try:
                meta = self.package_versions(pkg)
            except FDroidError:
                continue
            local = self._local_cached(pkg, meta["version_code"])
            if local is not None:
                apk = local
            else:
                apk = self.download_apk(pkg, meta["version_code"])
            sha = hashlib.sha256(apk).hexdigest()
            evidence = {
                "source": "F-Droid",
                "package_id": pkg,
                "version_code": meta["version_code"],
                "version_name": meta["version_name"],
                "sha_origin": "computed from official F-Droid APK download",
                "note": "official build from the project's own F-Droid repository",
            }
            out.append(
                CandidateRecord(
                    candidate_id=f"fd-{sha[:16]}",
                    source="f_droid_real",
                    sha256=sha,
                    package_name=pkg,
                    app_name=entry.get("app_name", ""),
                    version_code=meta["version_code"] or 0,
                    version_name=meta["version_name"] or "",
                    market="F-Droid",
                    category=entry.get("subsector", fintech_utility_label(entry)),
                    country=entry.get("country", ""),
                    dex_date=None,
                    vt_detection=0,
                    vt_scan_date=None,
                    first_seen_date=None,
                    play_verification_date=None,
                    suspected_class=ClassLabel.BENIGN,
                    suspected_family="",
                    fintech_category=entry.get("subsector", ""),
                    fintech_basis=entry.get("fintech_basis", "open-source fintech app on F-Droid"),
                    targeting_basis="",
                    evidence=json.dumps(evidence, sort_keys=True),
                    source_reference=FDROID_PAGE.format(pkg=pkg),
                    source_timestamp=now,
                    verification_status=VerificationStatus.PENDING,
                )
            )
        return out

    # ---------------------------------------------------------------- download
    def download_apk(self, package_id: str, version_code: int) -> bytes:
        # Prefer an already-fetched local copy (samples/import/) so acquisition
        # does not re-download a 50-100MB official build we already pulled.
        local = self._local_cached(package_id, version_code)
        if local is not None:
            return local
        url = FDROID_REPO.format(pkg=package_id, version_code=version_code)
        try:
            resp = requests.get(url, timeout=self._timeout)
            resp.raise_for_status()
            return resp.content
        except Exception as exc:  # noqa: BLE001
            raise FDroidError(f"F-Droid APK download failed for {package_id}: {exc}") from exc

    @staticmethod
    def _local_cached(package_id: str, version_code: int) -> bytes | None:
        from ..config import PROJECT_ROOT

        import_root = PROJECT_ROOT / "samples" / "import"
        candidates = [
            import_root / f"{package_id}_{version_code}.apk",
            import_root / f"{package_id}_{version_code}.apk.zip",
        ]
        for c in candidates:
            if c.is_file() and c.stat().st_size > 0 and c.read_bytes()[:2] == b"PK":
                return c.read_bytes()
        return None


def fintech_utility_label(entry: dict) -> str:
    return entry.get("subsector", "fintech_utility")


__all__ = ["FDroidError", "FDroidSource", "load_fdroid_catalogue"]
