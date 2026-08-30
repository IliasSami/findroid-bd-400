"""Deterministic candidate generation (pre-seed check)."""

from __future__ import annotations

from findroid.config import PROJECT_ROOT
from findroid.sources.mock_benign import load_benign_seed_catalog
from findroid.sources.mock_candidates import (
    generate_benign_candidates,
    generate_malicious_candidates,
)
from findroid.sources.mock_malware import build_family_catalogue


def test_benign_generation_deterministic(cfg):
    catalog = load_benign_seed_catalog(PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv")
    a = generate_benign_candidates(catalog, cfg)
    b = generate_benign_candidates(catalog, cfg)
    assert len(a) == len(b)
    assert {c.sha256 for c in a} == {c.sha256 for c in b}
    assert len({c.sha256 for c in a}) == len(a)  # no duplicates


def test_malicious_generation_deterministic(cfg):
    families = build_family_catalogue(PROJECT_ROOT / "metadata" / "threat_families.csv")
    a = generate_malicious_candidates(families, cfg)
    b = generate_malicious_candidates(families, cfg)
    assert len(a) == len(b)
    assert {c.sha256 for c in a} == {c.sha256 for c in b}


def test_pools_meet_quota_design(cfg):
    catalog = load_benign_seed_catalog(PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv")
    families = build_family_catalogue(PROJECT_ROOT / "metadata" / "threat_families.csv")
    benign = generate_benign_candidates(catalog, cfg)
    mal = generate_malicious_candidates(families, cfg)
    assert cfg.candidate_pool.benign_min <= len(benign) <= cfg.candidate_pool.benign_max
    assert len(mal) >= cfg.candidate_pool.malicious_min
    assert all(c.source == "mock_play" for c in benign)
    assert all(c.source == "mock_malwarebazaar" for c in mal)
