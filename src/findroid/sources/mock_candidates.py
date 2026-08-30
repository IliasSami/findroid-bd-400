"""Deterministic mock candidate generators.

Both generators are seeding a deterministic RNG from a per-package/per-sample
salt, so the entire funnel is reproducible given the same random seed. All
simulated artifacts are flagged SIMULATED; real acquisition would replace these
with genuine hashes and metadata.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections.abc import Iterable
from datetime import date

from ..config import AppConfig
from ..models import CandidateRecord, ClassLabel, VerificationStatus, utcnow
from .mock_benign import SeedPackage, package_label
from .mock_malware import ThreatFamily, family_budget, vdetect_window_for


# deterministic pseudo-random sources
def _rng(salt: str, seed: int) -> random.Random:
    digest = hashlib.sha256(f"{seed}:{salt}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big") % (2**32))


def _sim_sha(parts: Iterable[str]) -> str:
    body = "\x1f".join(parts)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _dex_date(rng: random.Random, window_start: date, window_end: date) -> str:
    days = (window_end - window_start).days
    delta = rng.randint(0, max(days, 1))
    d = window_start.toordinal() + delta
    return date.fromordinal(d).isoformat()


_WINDOW_START = date(2023, 1, 1)
_WINDOW_END = date(2026, 8, 31)


def generate_benign_candidates(
    catalog: dict[str, SeedPackage],
    cfg: AppConfig,
    *,
    limit: int | None = None,
    exclude_verification: bool = False,
) -> list[CandidateRecord]:
    """Generate benign candidates from the seed catalog.

    ``exclude_verification`` (default False) keeps every eligible package;
    the verifier decides later. Collision entries are never generated.
    """
    seed = cfg.project.random_seed
    now = utcnow()
    out: list[CandidateRecord] = []

    def eligible(p: SeedPackage) -> bool:
        if p.is_collision:
            return False
        if exclude_verification and not (p.is_confirmed or p.is_synthetic):
            return False
        return True

    # deterministic package ordering
    for pkg in sorted(catalog.values(), key=lambda p: p.package_id):
        if not eligible(pkg):
            continue
        rng = _rng(f"benign:{pkg.package_id}:{pkg.app_name}", seed)
        n_versions = rng.randint(4, 8)
        base_vc = 1000 + rng.randint(0, 900)
        for i in range(n_versions):
            base = hashlib.sha256(
                f"ben:{pkg.package_id}:{i}:{pkg.app_name}".encode()
            ).hexdigest()
            ver = ".".join(str(rng.randint(1, 5)) for _ in range(3))
            month_shift = rng.randint(0, 24)
            sha = _sim_sha([base, str(i), str(month_shift), pkg.package_id])
            dex = _dex_date(rng, _WINDOW_START, _WINDOW_END)
            first_seen = _dex_date(rng, _WINDOW_START, _WINDOW_END)
            play_check = _dex_date(rng, _WINDOW_START, _WINDOW_END)
            # benign apps have vt_detection == 0; simulated resolutions always 0.
            out.append(
                CandidateRecord(
                    candidate_id=f"cb-{sha[:16]}-{i}",
                    source="mock_play",
                    sha256=sha,
                    package_name=pkg.package_id,
                    app_name=pkg.app_name,
                    version_code=base_vc + i,
                    version_name=ver,
                    market="Google Play",
                    category=package_label(pkg),
                    country=pkg.country,
                    dex_date=dex,
                    vt_detection=0,
                    vt_scan_date=play_check,
                    first_seen_date=first_seen,
                    play_verification_date=play_check,
                    suspected_class=ClassLabel.BENIGN,
                    suspected_family="",
                    fintech_category=pkg.subsector,
                    fintech_basis=f"seed catalogue entry {pkg.app_name}",
                    targeting_basis="",
                    evidence=pkg.evidence,
                    source_reference=f"mock:{pkg.package_id}#v{i} SIMULATED",
                    source_timestamp=play_check,
                    verification_status=VerificationStatus.PENDING,
                    created_at=now,
                    updated_at=now,
                )
            )
    return out[:limit] if limit else out


def generate_malicious_candidates(
    families: dict[str, ThreatFamily],
    cfg: AppConfig,
    *,
    limit: int | None = None,
    spike_for_sikkahbot: bool = True,
) -> list[CandidateRecord]:
    """Generate synthetic malware candidates from the family catalogue.

    ``spike_for_sikkahbot`` keeps the BD-focused family over-weighted (its
    simulated VT detections deliberately land below the confident threshold for
    a subset, forcing evidence-driven label assignment).
    """
    seed = cfg.project.random_seed
    now = utcnow()
    out: list[CandidateRecord] = []
    order = list(families.values())

    for fam in order:
        budget = family_budget(fam.family)
        rng = _rng(f"mal:{fam.family}", seed)
        targets = _impersonation_targets(fam)
        for i in range(budget):
            rng = _rng(f"mal:{fam.family}:{i}", seed)
            lo, hi = vdetect_window_for(fam.vt_band)
            vt = rng.randint(lo, hi)
            vn = ".".join(str(rng.randint(1, 5)) for _ in range(3))
            slug = re.sub(r"[^a-z0-9]+", "_", fam.family.lower()).strip("_")
            pkg = f"mock.mal.{slug}.{i:03d}"
            brand = rng.choice(targets) if targets else "generic brand"
            sha = _sim_sha(["mal", fam.family, str(i), vn, pkg])
            dex = _dex_date(rng, _WINDOW_START, _WINDOW_END)
            first_seen = _dex_date(rng, _WINDOW_START, _WINDOW_END)
            out.append(
                CandidateRecord(
                    candidate_id=f"cm-{sha[:16]}-{i}",
                    source="mock_malwarebazaar",
                    sha256=sha,
                    package_name=pkg,
                    app_name=f"Fake{brand}",
                    version_code=1000 + i,
                    version_name=vn,
                    market="sideload" if rng.random() < 0.7 else "Google Play",
                    category="impersonation",
                    country="",
                    dex_date=dex,
                    vt_detection=vt,
                    vt_scan_date=first_seen,
                    first_seen_date=first_seen,
                    play_verification_date=None,
                    suspected_class=ClassLabel.MALICIOUS,
                    suspected_family=fam.family,
                    fintech_category="",
                    fintech_basis="",
                    targeting_basis=brand,
                    evidence=fam.provenance_note,
                    source_reference=f"mock:{slug}#{i} SIMULATED",
                    source_timestamp=first_seen,
                    verification_status=VerificationStatus.PENDING,
                    created_at=now,
                    updated_at=now,
                )
            )
    return out[:limit] if limit else out


def _impersonation_targets(fam: ThreatFamily) -> list[str]:
    from .mock_malware import BD_TARGET_BRANDS

    if "bangladesh" in fam.region_focus.lower():
        return list(BD_TARGET_BRANDS)
    if set(fam.family.lower().split()) & {"coper", "blankbot", "mamont"}:
        return ["generic bank", "generic wallet", "generic exchange"]
    return ["generic bank", "generic wallet", "generic social", "generic exchange"]
