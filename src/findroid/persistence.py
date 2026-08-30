"""SQLite persistence layer.

Thirteen tables track the full provenance chain: candidates -> verification ->
labels -> samples -> acquisition -> extraction runs -> features -> dedup
clusters -> quality gates -> dataset versions -> errors.

``origin`` distinguishes *measured* (observed from the sample) from *derived*
(computed from measured values) from *simulated* (produced by the mock
acquisition/extraction backends, only ever used in development mode).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import UTC
from pathlib import Path
from typing import Any

from .models import (
    CandidateRecord,
    DuplicateClusterRecord,
    ErrorRecord,
    ExtractionRunRecord,
    FeatureRecord,
    GateResult,
    LabelRecord,
    ReviewRecord,
    SampleRecord,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source_key     TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    display_name   TEXT NOT NULL,
    configured     INTEGER NOT NULL DEFAULT 0,
    last_sync_ts   TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    candidate_id          TEXT PRIMARY KEY,
    source                TEXT NOT NULL,
    sha256                TEXT NOT NULL,
    package_name          TEXT NOT NULL,
    app_name              TEXT NOT NULL DEFAULT '',
    version_code          INTEGER NOT NULL DEFAULT 0,
    version_name          TEXT NOT NULL DEFAULT '',
    market                TEXT NOT NULL DEFAULT '',
    category              TEXT NOT NULL DEFAULT '',
    country               TEXT NOT NULL DEFAULT '',
    dex_date              TEXT,
    vt_detection          INTEGER,
    vt_scan_date          TEXT,
    first_seen_date       TEXT,
    play_verification_date TEXT,
    suspected_class       TEXT NOT NULL DEFAULT 'unknown',
    suspected_family      TEXT NOT NULL DEFAULT '',
    fintech_category      TEXT NOT NULL DEFAULT '',
    fintech_basis         TEXT NOT NULL DEFAULT '',
    targeting_basis       TEXT NOT NULL DEFAULT '',
    evidence              TEXT NOT NULL DEFAULT '',
    source_reference      TEXT NOT NULL DEFAULT '',
    source_timestamp      TEXT NOT NULL DEFAULT '',
    verification_status   TEXT NOT NULL DEFAULT 'pending',
    verification_notes    TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    UNIQUE (sha256)
);
CREATE INDEX IF NOT EXISTS idx_candidates_class ON candidates (suspected_class);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates (verification_status);
CREATE INDEX IF NOT EXISTS idx_candidates_package ON candidates (package_name);

CREATE TABLE IF NOT EXISTS verification (
    verification_id   TEXT PRIMARY KEY,
    candidate_id      TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    status            TEXT NOT NULL,
    checks            TEXT NOT NULL DEFAULT '{}',
    notes             TEXT NOT NULL DEFAULT '',
    checked_at        TEXT NOT NULL,
    FOREIGN KEY (candidate_id) REFERENCES candidates (candidate_id)
);

CREATE TABLE IF NOT EXISTS labels (
    sample_id          TEXT PRIMARY KEY,
    sha256             TEXT NOT NULL,
    class_label        TEXT NOT NULL,
    confidence         TEXT NOT NULL,
    family             TEXT NOT NULL DEFAULT '',
    family_confidence  TEXT,
    targeting_basis    TEXT NOT NULL DEFAULT '',
    vt_detection       INTEGER,
    evidence_refs      TEXT NOT NULL DEFAULT '',
    source_note        TEXT NOT NULL DEFAULT '',
    reviewed           INTEGER NOT NULL DEFAULT 0,
    reviewer           TEXT NOT NULL DEFAULT '',
    review_timestamp   TEXT,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE (sha256)
);

CREATE TABLE IF NOT EXISTS label_evidence (
    evidence_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id     TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    value         TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT '',
    fetched_at    TEXT,
    FOREIGN KEY (sample_id) REFERENCES labels (sample_id)
);
CREATE INDEX IF NOT EXISTS idx_label_evidence_sample ON label_evidence (sample_id);

CREATE TABLE IF NOT EXISTS samples (
    sample_id              TEXT PRIMARY KEY,
    sha256                 TEXT NOT NULL,
    source                 TEXT NOT NULL,
    class_label            TEXT NOT NULL,
    package_name           TEXT NOT NULL,
    app_name               TEXT NOT NULL DEFAULT '',
    version_code           INTEGER NOT NULL DEFAULT 0,
    version_name           TEXT NOT NULL DEFAULT '',
    apk_size               INTEGER NOT NULL DEFAULT 0,
    fintech_category       TEXT NOT NULL DEFAULT '',
    fintech_basis          TEXT NOT NULL DEFAULT '',
    targeting_basis        TEXT NOT NULL DEFAULT '',
    label_confidence       TEXT NOT NULL,
    family                 TEXT NOT NULL DEFAULT '',
    family_confidence      TEXT,
    label_evidence_ref     TEXT NOT NULL DEFAULT '',
    market                 TEXT NOT NULL DEFAULT '',
    country                TEXT NOT NULL DEFAULT '',
    dex_date               TEXT,
    vt_detection           INTEGER,
    acquisition_status     TEXT NOT NULL DEFAULT 'pending',
    apk_validation_status  TEXT NOT NULL DEFAULT 'NOT_CHECKED',
    feature_extraction_status TEXT NOT NULL DEFAULT 'NOT_RUN',
    dataset_version        TEXT NOT NULL DEFAULT '',
    created_at             TEXT NOT NULL,
    UNIQUE (sha256)
);
CREATE INDEX IF NOT EXISTS idx_samples_class ON samples (class_label);
CREATE INDEX IF NOT EXISTS idx_samples_package ON samples (package_name);

CREATE TABLE IF NOT EXISTS extraction_runs (
    run_id              TEXT PRIMARY KEY,
    sample_id           TEXT NOT NULL,
    sha256              TEXT NOT NULL,
    status              TEXT NOT NULL,
    extractor_version   TEXT NOT NULL,
    feature_schema_version TEXT NOT NULL,
    duration_ms         INTEGER NOT NULL DEFAULT 0,
    error_code          TEXT NOT NULL DEFAULT '',
    error_message       TEXT NOT NULL DEFAULT '',
    feature_count       INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    FOREIGN KEY (sample_id) REFERENCES samples (sample_id)
);
CREATE INDEX IF NOT EXISTS idx_extraction_runs_sample ON extraction_runs (sample_id);

CREATE TABLE IF NOT EXISTS features (
    feature_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id        TEXT NOT NULL,
    sha256           TEXT NOT NULL,
    feature_name     TEXT NOT NULL,
    value            TEXT NOT NULL,
    dtype            TEXT NOT NULL,
    [group]          TEXT NOT NULL,
    origin           TEXT NOT NULL,
    source_tool      TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    extraction_status TEXT NOT NULL,
    extracted_at     TEXT NOT NULL,
    FOREIGN KEY (sample_id) REFERENCES samples (sample_id)
);
CREATE INDEX IF NOT EXISTS idx_features_sample ON features (sample_id);
CREATE INDEX IF NOT EXISTS idx_features_name ON features (feature_name);

CREATE TABLE IF NOT EXISTS dedup_clusters (
    cluster_id       TEXT PRIMARY KEY,
    sha256           TEXT NOT NULL,
    fingerprint_type TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    members          TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dedup_clusters_fp ON dedup_clusters (fingerprint_type, fingerprint);

CREATE TABLE IF NOT EXISTS quality_checks (
    check_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    gate        TEXT NOT NULL,
    passed      INTEGER NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'FAIL',
    detail      TEXT NOT NULL DEFAULT '',
    run_hash    TEXT NOT NULL DEFAULT '',
    checked_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dataset_versions (
    dataset_version TEXT PRIMARY KEY,
    total           INTEGER NOT NULL,
    benign          INTEGER NOT NULL,
    malicious       INTEGER NOT NULL,
    config_hash     TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    notes           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS review_queue (
    sample_id        TEXT PRIMARY KEY,
    candidate_label  TEXT NOT NULL,
    candidate_family TEXT NOT NULL DEFAULT '',
    confidence       TEXT NOT NULL,
    reason           TEXT NOT NULL,
    evidence         TEXT NOT NULL DEFAULT '',
    review_required  INTEGER NOT NULL DEFAULT 1,
    review_status    TEXT NOT NULL DEFAULT 'REVIEW_REQUIRED',
    reviewer         TEXT NOT NULL DEFAULT '',
    review_timestamp TEXT,
    final_decision   TEXT NOT NULL DEFAULT '',
    review_notes     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS errors (
    error_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    stage      TEXT NOT NULL,
    sample_id  TEXT NOT NULL DEFAULT '',
    sha256     TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class Database:
    """Thin wrapper around an SQLite connection with table helpers."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ---------------------------------------------------------------- generic
    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        """First column of the first row; raises when no row is returned."""
        row = self.conn.execute(sql, params).fetchone()
        if row is None:
            raise RuntimeError(f"scalar query returned no row: {sql}")
        return row[0]

    # --------------------------------------------------------------- candidates
    def upsert_candidate(self, rec: CandidateRecord) -> None:
        self.execute(
            """
            INSERT INTO candidates (
                candidate_id, source, sha256, package_name, app_name, version_code,
                version_name, market, category, country, dex_date, vt_detection,
                vt_scan_date, first_seen_date, play_verification_date,
                suspected_class, suspected_family, fintech_category, fintech_basis,
                targeting_basis, evidence, source_reference, source_timestamp,
                verification_status, verification_notes, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(candidate_id) DO UPDATE SET
                updated_at=excluded.updated_at,
                vt_detection=COALESCE(excluded.vt_detection, candidates.vt_detection),
                verification_status=excluded.verification_status,
                verification_notes=excluded.verification_notes
            """,
            (
                rec.candidate_id,
                rec.source,
                rec.sha256,
                rec.package_name,
                rec.app_name,
                rec.version_code,
                rec.version_name,
                rec.market,
                rec.category,
                rec.country,
                rec.dex_date,
                rec.vt_detection,
                rec.vt_scan_date,
                rec.first_seen_date,
                rec.play_verification_date,
                rec.suspected_class.value,
                rec.suspected_family,
                rec.fintech_category,
                rec.fintech_basis,
                rec.targeting_basis,
                rec.evidence,
                rec.source_reference,
                rec.source_timestamp,
                rec.verification_status.value,
                rec.verification_notes,
                rec.created_at,
                rec.updated_at,
            ),
        )

    def get_candidate(self, candidate_id: str) -> dict[str, Any] | None:
        row = self.fetchone("SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,))
        return dict(row) if row else None

    def get_candidate_by_sha(self, sha256: str) -> dict[str, Any] | None:
        row = self.fetchone("SELECT * FROM candidates WHERE sha256 = ?", (sha256,))
        return dict(row) if row else None

    def all_candidates(self, limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM candidates ORDER BY candidate_id"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [dict(r) for r in self.fetchall(sql)]

    # -------------------------------------------------------------- verification
    def add_verification(self, record: dict[str, Any]) -> None:
        self.execute(
            """
            INSERT OR IGNORE INTO verification (
                verification_id, candidate_id, sha256, status, checks, notes, checked_at
            ) VALUES (?,?,?,?,?,?,?)
            """,
            (
                record["verification_id"],
                record["candidate_id"],
                record["sha256"],
                record["status"],
                json.dumps(record.get("checks", {})),
                record.get("notes", ""),
                record["checked_at"],
            ),
        )

    # ------------------------------------------------------------------- labels
    def upsert_label(self, rec: LabelRecord) -> None:
        self.execute(
            """
            INSERT INTO labels (
                sample_id, sha256, class_label, confidence, family, family_confidence,
                targeting_basis, vt_detection, evidence_refs, source_note, reviewed,
                reviewer, review_timestamp, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(sample_id) DO UPDATE SET
                class_label=excluded.class_label,
                confidence=excluded.confidence,
                family=excluded.family,
                family_confidence=excluded.family_confidence,
                targeting_basis=excluded.targeting_basis,
                vt_detection=excluded.vt_detection,
                evidence_refs=excluded.evidence_refs,
                source_note=excluded.source_note,
                updated_at=excluded.updated_at
            """,
            (
                rec.sample_id,
                rec.sha256,
                rec.class_label.value,
                rec.confidence.value,
                rec.family,
                rec.family_confidence.value if rec.family_confidence else None,
                rec.targeting_basis,
                rec.vt_detection,
                "|".join(rec.evidence_refs),
                rec.source_note,
                int(rec.reviewed),
                rec.reviewer,
                rec.review_timestamp,
                rec.created_at,
                rec.updated_at,
            ),
        )

    def add_review(self, rec: ReviewRecord) -> None:
        self.execute(
            """
            INSERT OR REPLACE INTO review_queue (
                sample_id, candidate_label, candidate_family, confidence, reason,
                evidence, review_required, review_status, reviewer, review_timestamp,
                final_decision, review_notes
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                rec.sample_id,
                rec.candidate_label,
                rec.candidate_family,
                rec.confidence.value,
                rec.reason,
                rec.evidence,
                int(rec.review_required),
                rec.review_status,
                rec.reviewer,
                rec.review_timestamp,
                rec.final_decision,
                rec.review_notes,
            ),
        )

    def pending_reviews(self) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.fetchall(
                "SELECT * FROM review_queue WHERE review_status = 'REVIEW_REQUIRED' ORDER BY sample_id"
            )
        ]

    # ------------------------------------------------------------------- samples
    def upsert_sample(self, rec: SampleRecord) -> None:
        self.execute(
            """
            INSERT INTO samples (
                sample_id, sha256, source, class_label, package_name, app_name,
                version_code, version_name, apk_size, fintech_category, fintech_basis,
                targeting_basis, label_confidence, family, family_confidence,
                label_evidence_ref, market, country, dex_date, vt_detection,
                acquisition_status, apk_validation_status, feature_extraction_status,
                dataset_version, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(sample_id) DO UPDATE SET
                acquisition_status=excluded.acquisition_status,
                apk_validation_status=excluded.apk_validation_status,
                feature_extraction_status=excluded.feature_extraction_status,
                dataset_version=excluded.dataset_version
            """,
            (
                rec.sample_id,
                rec.sha256,
                rec.source,
                rec.class_label.value,
                rec.package_name,
                rec.app_name,
                rec.version_code,
                rec.version_name,
                rec.apk_size,
                rec.fintech_category,
                rec.fintech_basis,
                rec.targeting_basis,
                rec.label_confidence.value,
                rec.family,
                rec.family_confidence.value if rec.family_confidence else None,
                rec.label_evidence_reference,
                rec.market,
                rec.country,
                rec.dex_date,
                rec.vt_detection,
                rec.acquisition_status.value,
                rec.apk_validation_status.value,
                rec.feature_extraction_status.value,
                rec.dataset_version,
                rec.created_at,
            ),
        )

    def get_sample(self, sample_id: str) -> dict[str, Any] | None:
        row = self.fetchone("SELECT * FROM samples WHERE sample_id = ?", (sample_id,))
        return dict(row) if row else None

    def count_samples(self, class_label: str | None = None) -> int:
        if class_label:
            row = self.fetchone(
                "SELECT COUNT(*) AS n FROM samples WHERE class_label = ?", (class_label,)
            )
        else:
            row = self.fetchone("SELECT COUNT(*) AS n FROM samples")
        return int(row["n"]) if row else 0

    def count_active_samples(self, class_label: str) -> int:
        row = self.fetchone(
            "SELECT COUNT(*) AS n FROM samples WHERE class_label = ? AND dataset_version != ''",
            (class_label,),
        )
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------ extraction runs
    def add_extraction_run(self, rec: ExtractionRunRecord) -> None:
        self.execute(
            """
            INSERT INTO extraction_runs (
                run_id, sample_id, sha256, status, extractor_version,
                feature_schema_version, duration_ms, error_code, error_message,
                feature_count, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                rec.run_id,
                rec.sample_id,
                rec.sha256,
                rec.status.value,
                rec.extractor_version,
                rec.feature_schema_version,
                rec.duration_ms,
                rec.error_code,
                rec.error_message,
                rec.feature_count,
                rec.created_at,
            ),
        )

    # ------------------------------------------------------------------- features
    def add_feature(self, rec: FeatureRecord) -> None:
        self.execute(
            """
            INSERT INTO features (
                sample_id, sha256, feature_name, value, dtype, [group],
                origin, source_tool, extractor_version, extraction_status, extracted_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                rec.sample_id,
                rec.sha256,
                rec.feature_name,
                _encode_value(rec.value, rec.dtype),
                rec.dtype,
                rec.group,
                rec.origin,
                rec.source_tool,
                rec.extractor_version,
                rec.extraction_status.value,
                rec.extracted_at,
            ),
        )

    def feature_count(self, sample_id: str) -> int:
        row = self.fetchone(
            "SELECT COUNT(*) AS n FROM features WHERE sample_id = ?", (sample_id,)
        )
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------- dedup
    def add_dedup_cluster(self, rec: DuplicateClusterRecord) -> None:
        self.execute(
            """
            INSERT OR REPLACE INTO dedup_clusters (
                cluster_id, sha256, fingerprint_type, fingerprint, members, created_at
            ) VALUES (?,?,?,?,?,?)
            """,
            (
                rec.cluster_id,
                rec.sha256,
                rec.fingerprint_type,
                rec.fingerprint,
                "|".join(rec.members),
                rec.created_at,
            ),
        )

    def fingerprint_match(self, fingerprint_type: str, fingerprint: str) -> dict[str, Any] | None:
        row = self.fetchone(
            "SELECT * FROM dedup_clusters WHERE fingerprint_type = ? AND fingerprint = ?",
            (fingerprint_type, fingerprint),
        )
        return dict(row) if row else None

    # -------------------------------------------------------------------- gates
    def add_gate(self, rec: GateResult, run_hash: str = "") -> None:
        self.execute(
            """
            INSERT INTO quality_checks (gate, passed, severity, detail, run_hash, checked_at)
            VALUES (?,?,?,?,?,?)
            """,
            (rec.gate, int(rec.passed), rec.severity, rec.detail, run_hash, _now()),
        )

    def gates_summary(self) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.fetchall(
                "SELECT gate, passed, severity FROM quality_checks ORDER BY check_id DESC LIMIT 80"
            )
        ]

    # ------------------------------------------------------------- versioning
    def register_version(
        self,
        version: str,
        total: int,
        benign: int,
        malicious: int,
        config_hash: str,
        notes: str = "",
    ) -> None:
        self.execute(
            """
            INSERT OR REPLACE INTO dataset_versions (
                dataset_version, total, benign, malicious, config_hash, created_at, notes
            ) VALUES (?,?,?,?,?,?,?)
            """,
            (version, total, benign, malicious, config_hash, _now(), notes),
        )

    # ------------------------------------------------------------------- errors
    def log_error(self, rec: ErrorRecord) -> None:
        self.execute(
            """
            INSERT INTO errors (stage, sample_id, sha256, error_code, message, created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (rec.stage, rec.sample_id, rec.sha256, rec.error_code, rec.message, rec.created_at),
        )

    def recent_errors(self, limit: int = 20) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.fetchall(
                "SELECT * FROM errors ORDER BY error_id DESC LIMIT ?", (limit,)
            )
        ]


def _encode_value(value: Any, dtype: str) -> str:
    if value is None:
        return ""
    if dtype.startswith("list") or isinstance(value, (list, set, tuple)):
        return json.dumps(list(value))
    if dtype == "float":
        return repr(float(value))
    return str(value)


def _now() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat(timespec="seconds")
