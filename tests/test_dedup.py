"""Deduplication fingerprint determinism."""

from __future__ import annotations

from findroid.deduplication.dedup import build_permission_fingerprint


def test_permission_fingerprint_deterministic():
    perms_a = ["READ_SMS", "SYSTEM_ALERT_WINDOW", "INTERNET", "READ_SMS"]
    perms_b = ["INTERNET", "READ_SMS", "SYSTEM_ALERT_WINDOW"]
    assert build_permission_fingerprint(perms_a) == build_permission_fingerprint(perms_b)


def test_permission_fingerprint_distinguishes_sets():
    a = build_permission_fingerprint(["READ_SMS"])
    b = build_permission_fingerprint(["READ_SMS", "INTERNET"])
    assert a != b
