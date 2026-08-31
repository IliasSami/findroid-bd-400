"""Real benign source from imported APK drops.

Play's store front works from any network but its APK mirrors (APKPure/APKCombo)
are bot-walled, so the genuine benign APKs for the BD catalogue must be fetched
on a residential network and dropped into ``samples/import/``. This adapter
converts those drops into real candidates:

1. scan ``samples/import/`` for ``*.apk`` and ``*.zip`` (a ``*.zip`` is treated
   as an ``infected``-password archive — theZoo-style drops work too),
2. parse each APK's manifest,
3. match to the verified seed catalogue by package id,
4. enrich with a live Google Play listing (author, rating, price) for the
   benign round-trip evidence.

SHA-256 is computed from the imported bytes, so the provenance chain never
guesses a hash. Unmatched or unparseable files are surfaced via
:meth:`pending_imports` and skipped.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Iterable
from pathlib import Path

from ..acquisition.manifest import ApkReadError, read_apk_manifest
from ..config import PROJECT_ROOT
from ..models import CandidateRecord, ClassLabel, VerificationStatus, utcnow
from .base import BaseSource, SourceError
from .mock_benign import SeedPackage, load_benign_seed_catalog
from .play import PlayError, fetch_play_listing

DEFAULT_IMPORT_ROOT = PROJECT_ROOT / "samples" / "import"


class ImportBenignError(SourceError):
    """Raised when the import directory cannot be scanned."""


class ImportBenignSource(BaseSource):
    kind = "play_benign"

    def __init__(
        self,
        import_root: Path = DEFAULT_IMPORT_ROOT,
        catalog: dict[str, SeedPackage] | None = None,
        *,
        require_play_evidence: bool = False,
    ):
        super().__init__("play_benign")
        self.import_root = Path(import_root)
        self.catalog = catalog if catalog is not None else load_benign_seed_catalog(
            PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv"
        )
        self.require_play_evidence = require_play_evidence
        self._last_import_files: list[Path] = []

    def credentials_ok(self) -> bool:
        return self.import_root.exists()

    # ------------------------------------------------------------- scanning
    def _apk_files(self) -> Iterable[Path]:
        if not self.import_root.exists():
            return
        for path in sorted(self.import_root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() == ".apk":
                yield path
            elif path.suffix.lower() in {".zip", ".apk.zip"}:
                yield path

    def _extract_apk_bytes(self, path: Path) -> bytes | None:
        if path.suffix.lower() == ".apk":
            return path.read_bytes()
        # password-protected archive: theZoo uses ``infected``
        raw = path.read_bytes()
        for opener, pwd in ((zipfile.ZipFile, b"infected"), (zipfile.ZipFile, None)):
            try:
                with opener(io.BytesIO(raw)) as zf:
                    members = zf.namelist()
                    apk = next((n for n in members if n.endswith(".apk")), None)
                    if apk is None:
                        return None
                    if pwd is None:
                        return zf.read(apk)
                    return zf.read(apk, pwd=pwd)
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
                continue
        return None

    def pending_imports(self) -> list[dict]:
        """List import files that did not produce planned candidates.

        Returns ``{file, reason}`` entries for manual triage (wrong package,
        unparseable APK, etc.).
        """
        out: list[dict] = []
        produced = {p.resolve() for p in self._last_import_files}
        for path in self._apk_files():
            if path.resolve() in produced:
                continue
            out.append({"file": str(path), "reason": "skipped (no candidate released)"})
        return out

    # ------------------------------------------------------------- discovery
    def discover(self, *, limit: int | None = None) -> Iterable[CandidateRecord]:
        now = utcnow()
        out: list[CandidateRecord] = []
        released: list[Path] = []
        seen_sha: set[str] = set()
        for path in self._apk_files():
            if limit and len(out) >= limit:
                break
            try:
                apk_bytes = self._extract_apk_bytes(path)
                if apk_bytes is None:
                    continue
                tmp = path if path.suffix.lower() == ".apk" else _write_temp(path, apk_bytes)
                manifest = read_apk_manifest(tmp)
                if tmp is not path:
                    tmp.unlink(missing_ok=True)
            except (ApkReadError, OSError):
                continue
            pkg = manifest.get("package_name") or ""
            seed = _match_seed(pkg, self.catalog)
            if seed is None or seed.is_collision:
                continue
            sha = manifest.get("sha256")
            if not sha or sha in seen_sha:
                continue
            play = {}
            if not self.require_play_evidence:
                try:
                    play = fetch_play_listing(pkg)
                except PlayError:
                    play = {}
            if self.require_play_evidence and not play:
                continue

            evidence = {
                "source": "Google Play round-trip",
                "package_id": pkg,
                "author": play.get("author"),
                "rating_value": play.get("rating_value"),
                "rating_count": play.get("rating_count"),
                "price": play.get("price"),
                "price_currency": play.get("price_currency"),
                "import_file": str(path),
                "sha_origin": "computed from imported APK bytes",
                "note": "APK fetched on a residential network; official Play listing evidence",
            }
            seen_sha.add(sha)
            released.append(path)
            out.append(
                CandidateRecord(
                    candidate_id=f"pb-{sha[:16]}",
                    source="play_benign",
                    sha256=sha,
                    package_name=pkg,
                    app_name=manifest.get("app_name") or seed.app_name,
                    version_code=manifest.get("version_code") or 0,
                    version_name=manifest.get("version_name") or "",
                    market="Google Play",
                    category=seed.subsector,
                    country=seed.country,
                    dex_date=None,
                    vt_detection=0,
                    vt_scan_date=None,
                    first_seen_date=None,
                    play_verification_date=play.get("fetch_date") or None,
                    suspected_class=ClassLabel.BENIGN,
                    suspected_family="",
                    fintech_category=seed.subsector,
                    fintech_basis=f"imported real APK matched to seed entry {seed.app_name}",
                    targeting_basis="",
                    evidence=json.dumps(evidence, sort_keys=True),
                    source_reference=play.get("url", ""),
                    source_timestamp=now,
                    verification_status=VerificationStatus.PENDING,
                )
            )
        self._last_import_files = released
        return out

    def locate_import_file(self, sha256: str) -> Path | None:
        """Return the import file whose candidate hash matches ``sha256``."""
        for path in self._apk_files():
            try:
                apk_bytes = self._extract_apk_bytes(path)
                if apk_bytes is None:
                    continue
                tmp = path if path.suffix.lower() == ".apk" else _write_temp(path, apk_bytes)
                manifest = read_apk_manifest(tmp)
                if tmp is not path:
                    tmp.unlink(missing_ok=True)
            except (ApkReadError, OSError):
                continue
            if manifest.get("sha256") == sha256:
                return path
        return None


def _match_seed(package_id: str, catalog: dict[str, SeedPackage]) -> SeedPackage | None:
    if not package_id:
        return None
    if package_id in catalog:
        return catalog[package_id]
    folded = {p.package_id.casefold(): p for p in catalog.values()}
    matches = [f for key, f in folded.items() if key == package_id.casefold()]
    if len(matches) == 1:
        return matches[0]
    return None


def _write_temp(archive: Path, apk_bytes: bytes) -> Path:
    tmp = archive.with_name(f"{archive.stem}__extracted.apk")
    tmp.write_bytes(apk_bytes)
    return tmp


__all__ = ["ImportBenignError", "ImportBenignSource", "DEFAULT_IMPORT_ROOT"]
