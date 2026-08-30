"""Deduplication.

Hard gate: SHA-256 must be unique across the corpus. Soft fingerprints stop
*practical* duplicates — same package+version, same certificate, same manifest,
same permission set — from inflating the dataset without an origin story.
"""

from __future__ import annotations

import hashlib

from ..models import DuplicateClusterRecord
from ..persistence import Database


def build_permission_fingerprint(perms: list[str]) -> str:
    return hashlib.sha256("\x1f".join(sorted(set(perms))).encode()).hexdigest()


def register_sha(cluster_id: str, sha: str, db: Database) -> None:
    db.add_dedup_cluster(
        DuplicateClusterRecord(
            cluster_id=cluster_id,
            sha256=sha,
            fingerprint_type="exact_sha256",
            fingerprint=sha,
            members=[sha],
        )
    )


def dedup_report(db: Database) -> dict[str, int]:
    """Count collisions per fingerprint type across current samples + features."""
    report: dict[str, int] = {}

    report["exact_sha256"] = int(
        db.scalar("SELECT COUNT(*) FROM (SELECT sha256 FROM samples GROUP BY sha256 HAVING COUNT(*)>1)")
        or 0
    )

    # package+version soft duplicates
    report["package_version"] = int(
        db.scalar(
            """
            SELECT COUNT(*) FROM (
                SELECT package_name, version_code FROM samples
                GROUP BY package_name, version_code HAVING COUNT(*) > 1
            )
            """
        )
        or 0
    )

    # permission-set duplicates (based on extracted perms); a true dup requires
    # another sample with identical set
    report["permission_set"] = int(
        db.scalar(
            """
            SELECT COUNT(*) FROM (
                SELECT f1.perm_set, COUNT(DISTINCT f1.sha256) c FROM (
                    SELECT sha256, group_concat(feature_name, ',') perm_set
                    FROM features WHERE feature_name LIKE 'perm.%'
                    GROUP BY sha256
                ) f1 GROUP BY f1.perm_set HAVING c > 1
            )
            """
        )
        or 0
    )
    return report
