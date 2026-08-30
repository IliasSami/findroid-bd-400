"""APK validation.

Validates that an acquired descriptor is self-consistent and matches the
labelled sample metadata. In mock mode this re-reads the descriptor and checks
package / version / certificate integrity keys; real mode would verify the
signature block of a real APK.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..config import AppConfig
from ..models import SampleRecord, ValidationStatus


def validate_descriptor(cfg: AppConfig, sample: SampleRecord) -> tuple[ValidationStatus, str]:
    p = _descriptor_path(cfg, sample)
    if not p.exists():
        return ValidationStatus.INVALID, "artifact descriptor missing"
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ValidationStatus.INVALID, "artifact descriptor unreadable"
    problems: list[str] = []
    if payload.get("package") != sample.package_name:
        problems.append("package mismatch")
    if int(payload.get("version_code", -1)) != sample.version_code:
        problems.append("version_code mismatch")
    if not payload.get("cert"):
        problems.append("certificate block missing")
    if payload.get("simulated") is not True:
        problems.append("descriptor not flagged simulated")
    if problems:
        return ValidationStatus.INVALID, "; ".join(problems)
    return ValidationStatus.VALID, "descriptor self-consistent"


def _descriptor_path(cfg: AppConfig, sample: SampleRecord) -> Path:
    rel = Path(sample.class_label.value) / sample.sha256[:2] / (sample.sha256 + ".mockapk.json")
    return cfg.samples_root / rel
