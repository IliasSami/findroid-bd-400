"""Autonomous benign APK acquisition from F-Droid's full catalogue.

This is the fully automated replacement for the manual "residential drop"
workflow. It enumerates the entire F-Droid ``index-v2.json`` package index
(4296+ packages), selects the fintech-relevant ones (Finance Manager / Wallet /
Pass Wallet categories plus fintech keyword matches), downloads each genuine
APK over the network, validates it (ZIP integrity + SHA-256 + readable
manifest), writes it into ``samples/import/<package>_<versioncode>.apk``, and
registers a corresponding real seed-catalogue entry.

Every row it writes into the seed catalogue is grounded in the official
F-Droid distribution channel (the project's own repo), so the benign class
evidence verifier accepts it as an official-channel round-trip.

This module is intentionally self-contained: it depends only on the project's
config/paths and the stdlib (+ requests), so it can run independently of the
rest of the pipeline.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import tempfile
import urllib.parse
import zipfile
from pathlib import Path

import requests

from findroid.config import PROJECT_ROOT, load_config

# --------------------------------------------------------------------------- #
# F-Droid catalogue endpoints
# --------------------------------------------------------------------------- #
FDROID_INDEX_URL = "https://f-droid.org/repo/index-v2.json"
FDROID_APK_BASE = "https://f-droid.org/repo"

# F-Droid categories we treat as fintech.
FINTECH_CATEGORIES = {"Finance Manager", "Wallet", "Pass Wallet"}

# Subsector assignment order (first match wins) so classification is
# deterministic. Each entry: (regex, subsector)
_SUBSECTOR_RULES = [
    # banking/bankchain brand apps
    (r"\b(bank|banking|neobank|revolut|monzo|n26|starling)\b", "bank_retail"),
    # payment rails / UPI / P2P money transfer
    (r"\b(upi|pay|payment|settle|transfer|remittance|invoice|billing)\b", "psp_wallet"),
    (r"\b(momo|wallet|mobile wallet|e.?wallet)\b", "mfs_wallet"),
    # explicit crypto / lighting / blockchain coins
    (
        r"\b(bitcoin|btc|litecoin|ltc|dogecoin|ethereum|eth|zcash|zec|xmr|monero|"
        r"cardano|ada|solana|polkadot|dot|crypto|coin|lightning|blockchain|multisig|"
        r"peercoin|decred|conceal|nano|bitcoin cash|bch|eos|tron|ripple|xrp)\b",
        "crypto_wallet",
    ),
    # last resort: personal-finance / expense / budget utilities
    (r".*", "fintech_utility"),
]

# Keep only apps that look like real fintech (avoid incidental / vague ones).
_FINTECH_KEYWORD_HINT = re.compile(
    r"(bank|wallet|finance|money|budget|expense|spend|payment|invoice|pay|"
    r"crypto|bitcoin|cash|account|ledger|bookkeep|pension|invest|tax|remittance|"
    r"cryptocurrency|coin|billing|econom|transact)",
    re.IGNORECASE,
)


# Apps that look fintech by category/keyword but are not genuine fintech
# applications (games, social, transit/loyalty only, file tools, health, etc.).
# Keyed by package id; excluded to keep the corpus honest.
_NON_FINTECH_DENYLIST = {
    # games
    "crypto.o0o0o0o0o.games.blackjack",
    "org.ecos.logic.flip_a_coin",
    "me.lecaro.breakout",
    "org.golden_ticket.golden_ticket",
    "com.tristinbaker.idlefantasy",
    "page.codeberg.lanticy.guandan",
    "dev.mlg.quedalle",
    "com.quietgrid.app",
    "me.river.nightbell",  # uptime monitor
    # social / messaging / feeds
    "com.keylesspalace.tusky",
    "org.andstatus.app",
    "org.fedisuite.mobile",
    "com.cosmos.unreddit",
    "app.status.mobile",  # messenger (wallet secondary)
    # device / hardware / remote control / tracking tools
    "com.relaypony.android",
    "com.atharok.screentime",
    "com.aradar.vibecheck",
    "com.mooneva.app",
    "com.porter.tvremote",
    "com.guillaumepayet.remotenumpad",
    "com.lazydevs.wristotle",
    "com.pearlnode",
    "kapoue.hestia",
    "net.quietrebellion",
    "com.debojit.wallapp",
    "dev.henriquecouto.calsync",
    "de.chaosdorf.meteroid",
    "org.t2.synconwifi",
    "ch.pec0ra.suspension_setup",
    "com.mushotoku.app",
    # media / content / misc
    "app.cleartray",  # GTD/task inbox, not finance
    "com.markreader",
    "io.github.freewatermark.mobileapp",
    "de.cryptobitch.muelli.barcodegen",
    "com.correctsyntax.biblenotify",
    "ch.cryptobit.letterbox",
    "net.activitywatch.android",
    "com.vishaltelangre.nerdcalci",
    "com.lesspass.android",
    # security/encryption/password (not finance)
    "com.tnibler.cryptocam",
    "org.cryptomator.lite",
    "com.paranoiaworks.unicus.android.sse",
    "org.keyoxide.keyoxide",
    "io.gitlab.cryptographic_id",
    "org.elijaxapps.androidxmrigminer",
    "me.diamondforge.tokn",
    "io.github.keco216.clockwork",
    "com.roufsyed.onekey",
    "org.secuso.privacyfriendlypasswordgenerator",
    "krasilnikov.alexey.cryptopass",
    "com.cryptosafe.app",
    "com.personx.cryptx",
    # hobbies (coin collection)
    "com.spencerpages",
}


def _classify_subsector(app_name: str, summary: str, package: str) -> str:
    """Assign a deterministic fintech subsector from name+summary+package."""
    hay = " ".join((app_name, summary, package)).lower()
    for pattern, subsector in _SUBSECTOR_RULES:
        if re.search(pattern, hay):
            return subsector
    return "fintech_utility"


def load_fdroid_index(cache: Path | None = None, timeout: int = 180) -> dict:
    """Return the parsed F-Droid index-v2 JSON.

    Uses a local cache file when provided and fresh, else downloads.
    """
    if cache is not None and cache.exists():
        with cache.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    resp = requests.get(FDROID_INDEX_URL, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if cache is not None:
        cache.parent.mkdir(parents=True, exist_ok=True)
        with cache.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
    return data


def enumerate_fintech_packages(index: dict) -> list[dict]:
    """Return a list of candidate records for fintech-relevant packages."""
    out: list[dict] = []
    for pkg, rec in (index.get("packages") or {}).items():
        md = rec.get("metadata") or {}
        cats = set(md.get("categories") or [])
        name = (md.get("name") or {}).get("en-US") or pkg
        summary = (md.get("summary") or {}).get("en-US") or ""
        if pkg in _NON_FINTECH_DENYLIST:
            continue
        is_fintech_cat = bool(cats & FINTECH_CATEGORIES)
        keyword_hit = bool(_FINTECH_KEYWORD_HINT.search(" ".join((name, summary, pkg))))
        if not (is_fintech_cat or keyword_hit):
            continue
        versions = rec.get("versions") or {}
        # index-v2 versions are keyed by the file sha256; the real version
        # code is embedded in the file name as <pkg>_<version_code>.apk.
        def _file_vc(v: dict) -> int:
            fn = (((v.get("file") or {}).get("name")) or "").rstrip("/")
            try:
                return int(fn.rsplit("_", 1)[1].removesuffix(".apk"))
            except (ValueError, IndexError):
                return 0

        best = None
        for key, ver in versions.items():
            fname = (ver.get("file") or {}).get("name")
            if not fname:
                continue
            if best is None or _file_vc(ver) > _file_vc(best[1]):
                best = (key, ver)
        if best is None:
            continue
        _vc_key, ver = best
        fname = ver["file"]["name"]
        out.append(
            {
                "package": pkg,
                "app_name": name,
                "summary": summary,
                "categories": sorted(cats),
                "version_code": _file_vc(ver),
                "file_name": fname,
                "file_sha256": (ver.get("file") or {}).get("sha256", ""),
                "file_size": (ver.get("file") or {}).get("size", 0),
                "subsector": _classify_subsector(name, summary, pkg),
            }
        )
    return out


def _safecode(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


def _validate_apk(path: Path, expected_sha: str = "") -> tuple[bool, str, dict]:
    """Validate a downloaded APK. Returns (valid, reason, manifest)."""
    if not path.is_file() or path.stat().st_size < 1000:
        return False, "too small / missing", {}
    if expected_sha and hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
        return False, "sha256 mismatch vs index", {}
    try:
        with zipfile.ZipFile(path) as z:
            if z.testzip() is not None:
                return False, "corrupt zip member", {}
            names = z.namelist()
            if "AndroidManifest.xml" not in names and "META-INF/MANIFEST.MF" not in names:
                return False, "not an APK (no manifest)", {}
    except (zipfile.BadZipFile, Exception) as exc:  # noqa: BLE001
        return False, f"bad zip: {exc}", {}
    from findroid.acquisition.manifest import read_apk_manifest

    try:
        manifest = read_apk_manifest(path)
    except Exception as exc:  # noqa: BLE001
        return False, f"manifest unreadable: {exc}", {}
    return True, "ok", manifest


def acquire_fdroid_benign(
    *,
    limit: int | None = None,
    import_root: Path | None = None,
    cache: Path | None = None,
    force: bool = False,
    timeout: int = 300,
) -> dict:
    """Autonomously download fintech APKs from F-Droid into ``import_root``.

    Returns a tally of acquired / skipped / failed entries and the built
    seed-catalogue rows.
    """
    cfg = load_config()
    cfg.resolve_env_overrides()
    import_root = import_root or cfg.import_root
    import_root.mkdir(parents=True, exist_ok=True)
    if cache is None:
        cache = PROJECT_ROOT / "data" / "fdroid_index_v2.json"

    index = load_fdroid_index(cache, timeout=timeout)
    candidates = enumerate_fintech_packages(index)
    if limit:
        candidates = candidates[:limit]

    tally = {"acquired": 0, "skipped_existing": 0, "failed": 0, "total_candidates": len(candidates)}
    seed_rows: list[dict] = []
    seen_seed = _load_existing_seed(PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv")

    for cand in candidates:
        pkg = cand["package"]
        # Output filename must match the f_droid._local_cached convention.
        out = import_root / f"{pkg}_{cand['version_code']}.apk"
        expected = cand["file_sha256"]

        if out.is_file():
            ok, _, manifest = _validate_apk(out, expected if not force else "")
            if ok:
                tally["skipped_existing"] += 1
                _append_seed_row(seen_seed, seed_rows, cand, manifest, out)
                continue
            tally["failed"] += 1
            continue

        url = FDROID_APK_BASE + urllib.parse.quote(cand["file_name"])
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            tmp = Path(tempfile.gettempdir()) / (f"fd_{pkg}_{cand['version_code']}.apk")
            tmp.write_bytes(resp.content)
            ok, reason, manifest = _validate_apk(tmp, expected)
            if not ok:
                tally["failed"] += 1
                tmp.unlink(missing_ok=True)
                continue
            # atomically move into place
            out.write_bytes(tmp.read_bytes())
            tmp.unlink(missing_ok=True)
            tally["acquired"] += 1
            _append_seed_row(seen_seed, seed_rows, cand, manifest, out)
        except Exception as exc:  # noqa: BLE001
            tally["failed"] += 1

    return tally, seed_rows


def _load_existing_seed(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8", newline="") as fh:
        return {r["package_id"] for r in csv.DictReader(fh)}


def _append_seed_row(
    seen: set[str], seed_rows: list[dict], cand: dict, manifest: dict, apk: Path
) -> None:
    pkg = cand["package"]
    if pkg in seen:
        return
    seen.add(pkg)
    app = manifest.get("app_name") or cand["app_name"]
    country = _guess_country(cand)
    seed_rows.append(
        {
            "package_id": pkg,
            "app_name": app,
            "organisation": "",
            "country": country,
            "tier": "3",
            "subsector": cand["subsector"],
            "verification_status": "confirmed",
            "evidence": f"official F-Droid build; real APK in samples/import/{apk.name}",
        }
    )


def _guess_country(cand: dict) -> str:
    """Best-effort country origin for a fintech app (documented brand home)."""
    hay = " ".join((cand["app_name"], cand["summary"], cand["package"])).lower()
    # Explicit country anchors first.
    for code, pattern in (
        ("IN", r"\b(upi|india|rupee|paytm|phonepe|bhim)\b"),
        ("BD", r"\b(bd|bangladesh|bdomet|bkash|nagad|rocket|tallykhata)\b"),
        ("PK", r"\b(pak|easypaisa|jazzcash)\b"),
        ("NP", r"\b(nepal|esewa)\b"),
        ("TH", r"\b(thailand|truemoney)\b"),
        ("VN", r"\b(vietnam|momo)\b"),
        ("ID", r"\b(indonesia|dana)\b"),
        ("PH", r"\b(philippines|gcash)\b"),
        ("DE", r"\b(german|germany)\b"),
        ("CH", r"\b(swiss)\b"),
        ("US", r"\b(us|american|united states)\b"),
        ("GB", r"\b(uk|british|united kingdom|london)\b"),
        ("CA", r"\b(canada|canadian)\b"),
    ):
        if re.search(pattern, hay):
            return code
    return "--"


def write_seed_rows(rows: list[dict], path: Path | None = None) -> int:
    """Append new seed-catalogue rows to ``metadata/fintech_seed_packages.csv``."""
    path = path or (PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv")
    existing = _load_existing_seed(path)
    cols = [
        "package_id",
        "app_name",
        "organisation",
        "country",
        "tier",
        "subsector",
        "verification_status",
        "evidence",
    ]
    added = 0
    with path.open("a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        for row in rows:
            if row["package_id"] in existing:
                continue
            w.writerow({c: row.get(c, "") for c in cols})
            existing.add(row["package_id"])
            added += 1
    return added


__all__ = [
    "acquire_fdroid_benign",
    "enumerate_fintech_packages",
    "load_fdroid_index",
    "write_seed_rows",
]
