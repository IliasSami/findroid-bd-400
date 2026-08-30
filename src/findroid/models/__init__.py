"""Canonical typed records for FinDroid-BD 400.

Every pipeline stage exchanges these records. Provenance is preserved by never
dropping the ``sha256`` / source fields between stages.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class VerificationStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    MANUAL_REVIEW = "manual_review"
    COLLISION = "collision"
    DUPLICATE = "duplicate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ClassLabel(StrEnum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    A = "A"
    B = "B"
    C = "C"


class ExtractionStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"


class ValidationStatus(StrEnum):
    VALID = "VALID"
    PARTIAL = "PARTIAL"
    INVALID = "INVALID"
    NOT_CHECKED = "NOT_CHECKED"


class AcquisitionStatus(StrEnum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    COMPLETED = "completed"
    FAILED = "failed"
    SIMULATED = "simulated"
    SKIPPED = "skipped"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_hex(data: bytes) -> str:
    """Deterministic 64-hex digest. For mock metadata generation only.

    Real acquisition always recomputes the digest from the downloaded bytes.
    """
    return sha256_bytes(data)


class CandidateRecord(BaseModel):
    candidate_id: str
    source: str
    sha256: str
    package_name: str
    app_name: str = ""
    version_code: int = 0
    version_name: str = ""
    market: str = ""
    category: str = ""
    country: str = ""
    dex_date: str | None = None
    vt_detection: int | None = None
    vt_scan_date: str | None = None
    first_seen_date: str | None = None
    play_verification_date: str | None = None
    suspected_class: ClassLabel = ClassLabel.UNKNOWN
    suspected_family: str = ""
    fintech_category: str = ""
    fintech_basis: str = ""
    targeting_basis: str = ""
    evidence: str = ""
    source_reference: str = ""
    source_timestamp: str = ""
    verification_status: VerificationStatus = VerificationStatus.PENDING
    verification_notes: str = ""
    created_at: str = Field(default_factory=utcnow)
    updated_at: str = Field(default_factory=utcnow)

    @field_validator("sha256")
    @classmethod
    def _sha256_format(cls, v: str) -> str:
        v = v.strip().lower()
        if not (v == "" or (len(v) == 64 and all(c in "0123456789abcdef" for c in v))):
            raise ValueError(f"invalid sha256: {v!r}")
        return v

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


class SampleRecord(BaseModel):
    sample_id: str
    sha256: str
    source: str
    class_label: ClassLabel
    package_name: str
    app_name: str = ""
    version_code: int = 0
    version_name: str = ""
    apk_size: int = 0
    fintech_category: str = ""
    fintech_basis: str = ""
    targeting_basis: str = ""
    label_confidence: Confidence
    family: str = ""
    family_confidence: Confidence | None = None
    label_evidence_reference: str = ""
    market: str = ""
    country: str = ""
    dex_date: str | None = None
    vt_detection: int | None = None
    acquisition_status: AcquisitionStatus = AcquisitionStatus.PENDING
    apk_validation_status: ValidationStatus = ValidationStatus.NOT_CHECKED
    feature_extraction_status: ExtractionStatus = ExtractionStatus.NOT_RUN
    dataset_version: str = ""
    created_at: str = Field(default_factory=utcnow)

    @field_validator("sha256")
    @classmethod
    def _sha256_format(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError(f"invalid sha256: {v!r}")
        return v

    def as_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        if isinstance(self.class_label, ClassLabel):
            d["class_label"] = self.class_label.value
        if isinstance(self.label_confidence, Confidence):
            d["label_confidence"] = self.label_confidence.value
        return d


class LabelRecord(BaseModel):
    sample_id: str
    sha256: str
    class_label: ClassLabel
    confidence: Confidence
    family: str = ""
    family_confidence: Confidence | None = None
    targeting_basis: str = ""
    vt_detection: int | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    source_note: str = ""
    reviewed: bool = False
    reviewer: str = ""
    review_timestamp: str | None = None
    created_at: str = Field(default_factory=utcnow)
    updated_at: str = Field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["class_label"] = self.class_label.value
        d["confidence"] = self.confidence.value
        if self.family_confidence is not None:
            d["family_confidence"] = self.family_confidence.value
        d["evidence_refs"] = "|".join(self.evidence_refs)
        return d


class FeatureRecord(BaseModel):
    sample_id: str
    sha256: str
    feature_name: str
    value: Any
    dtype: str
    group: str
    origin: str  # measured | derived | simulated
    source_tool: str
    extractor_version: str
    extraction_status: ExtractionStatus
    extracted_at: str = Field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["extraction_status"] = self.extraction_status.value
        return d


class ExtractionRunRecord(BaseModel):
    run_id: str
    sample_id: str
    sha256: str
    status: ExtractionStatus
    extractor_version: str
    feature_schema_version: str
    duration_ms: int = 0
    error_code: str = ""
    error_message: str = ""
    feature_count: int = 0
    created_at: str = Field(default_factory=utcnow)


class ReviewRecord(BaseModel):
    sample_id: str
    candidate_label: str
    candidate_family: str = ""
    confidence: Confidence
    reason: str
    evidence: str = ""
    review_required: bool = True
    review_status: str = "REVIEW_REQUIRED"
    reviewer: str = ""
    review_timestamp: str | None = None
    final_decision: str = ""
    review_notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["confidence"] = self.confidence.value
        return d


class DuplicateClusterRecord(BaseModel):
    cluster_id: str
    sha256: str
    fingerprint_type: str  # exact_sha256 | package_version | manifest | certificate | permissions
    fingerprint: str
    members: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["members"] = "|".join(self.members)
        return d


class GateResult(BaseModel):
    gate: str
    passed: bool
    detail: str = ""
    severity: str = "FAIL"  # PASS | WARNING | FAIL

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


class ErrorRecord(BaseModel):
    stage: str
    sample_id: str = ""
    sha256: str = ""
    error_code: str
    message: str
    created_at: str = Field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()
