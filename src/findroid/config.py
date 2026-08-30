"""Configuration-first design.

All pipeline parameters live in YAML under ``configs/`` and are loaded once into
a validated :class:`AppConfig`. The resolved configuration can be hashed so every
run can be pinned to the exact configuration that produced it.
"""

from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ProjectConfig(BaseModel):
    name: str = "FinDroid-BD-400"
    version: str = "1.0.0"
    random_seed: int = 20260831


class DatasetConfig(BaseModel):
    total: int = 400
    benign: int = 240
    malicious: int = 160


class CandidatePoolConfig(BaseModel):
    benign_min: int = 330
    benign_max: int = 360
    malicious_min: int = 220
    malicious_max: int = 250


class SourceToggleConfig(BaseModel):
    enabled: bool = True


class SourcesTopConfig(BaseModel):
    androzoo: SourceToggleConfig | None = None
    malwarebazaar: SourceToggleConfig | None = None


class DevelopmentConfig(BaseModel):
    mock_sources: bool = True
    mock_acquisition: bool = True
    mock_extraction: bool = True
    allow_real_apks: bool = False


class AnalysisConfig(BaseModel):
    static: bool = True
    dynamic: bool = False


class SecurityConfig(BaseModel):
    execute_apks: bool = False


class AmbiguousRange(BaseModel):
    min: int = 1
    max: int = 3


class LabelsTopConfig(BaseModel):
    benign_vt_max: int = 0
    malicious_vt_min: int = 4
    ambiguous_range: AmbiguousRange = AmbiguousRange()


class OutputConfig(BaseModel):
    csv: bool = True
    parquet: bool = True
    output_json: bool = True
    html_report: bool = True


class AppConfig(BaseModel):
    """Union of all configuration files."""

    project: ProjectConfig = Field(default_factory=ProjectConfig)
    dataset: DatasetConfig = Field(default_factory=DatasetConfig)
    candidate_pool: CandidatePoolConfig = Field(default_factory=CandidatePoolConfig)
    sources: SourcesTopConfig = Field(default_factory=SourcesTopConfig)
    development: DevelopmentConfig = Field(default_factory=DevelopmentConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    labels: LabelsTopConfig = Field(default_factory=LabelsTopConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    # Free-form extras (sources.yaml, labeling.yaml, features.yaml, selection.yaml)
    sources_detail: dict[str, Any] = Field(default_factory=dict)
    labeling: dict[str, Any] = Field(default_factory=dict)
    features: dict[str, Any] = Field(default_factory=dict)
    selection: dict[str, Any] = Field(default_factory=dict)

    @property
    def data_root(self) -> Path:
        configured = os.environ.get("FINDROID_DATA_ROOT", "").strip()
        return Path(configured) if configured else PROJECT_ROOT / "data"

    @property
    def db_path(self) -> Path:
        configured = os.environ.get("FINDROID_DB_PATH", "").strip()
        return Path(configured) if configured else PROJECT_ROOT / "database" / "findroid.db"

    @property
    def samples_root(self) -> Path:
        configured = os.environ.get("FINDROID_APK_VAULT", "").strip()
        return Path(configured) if configured else PROJECT_ROOT / "samples"

    @property
    def reports_root(self) -> Path:
        return PROJECT_ROOT / "reports"

    def version_latest(self, db) -> str:
        row = db.fetchone(
            "SELECT dataset_version FROM dataset_versions ORDER BY created_at DESC LIMIT 1"
        )
        if row is None:
            raise RuntimeError("no dataset version registered yet; run the build phase first")
        return row["dataset_version"]

    def config_hash(self) -> str:
        payload = self._canonical_payload()
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _canonical_payload(self) -> str:
        core = self.model_dump(exclude={"sources_detail", "labeling", "features", "selection"})
        return json.dumps(
            {
                "core": core,
                "sources_detail": self.sources_detail,
                "labeling": self.labeling,
                "features": self.features,
                "selection": self.selection,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def resolve_env_overrides(self) -> None:
        """Allow environment variables to override mock/real mode at runtime."""
        self.development.mock_sources = _env_bool("FINDROID_MOCK_SOURCES", self.development.mock_sources)
        self.development.mock_acquisition = _env_bool(
            "FINDROID_MOCK_ACQUISITION", self.development.mock_acquisition
        )
        self.development.allow_real_apks = _env_bool(
            "FINDROID_ALLOW_REAL_APKS", self.development.allow_real_apks
        )

    def missing_credentials(self) -> list[str]:
        missing: list[str] = []
        if not self.development.mock_sources:
            if not os.environ.get("ANDROZOO_API_KEY", "").strip():
                missing.append("ANDROZOO_API_KEY")
            if not os.environ.get("MALWAREBAZAAR_API_KEY", "").strip():
                missing.append("MALWAREBAZAAR_API_KEY")
        return missing


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


_CONF_FILES = (
    "project.yaml",
    "sources.yaml",
    "labeling.yaml",
    "features.yaml",
    "selection.yaml",
)


@lru_cache(maxsize=1)
def load_config(base_dir: Path | None = None) -> AppConfig:
    base = base_dir or PROJECT_ROOT
    cfg_dir = base / "configs"

    def _read(name: str) -> dict[str, Any]:
        path = cfg_dir / name
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    project = _read("project.yaml")
    sources_detail = _read("sources.yaml")
    labeling = _read("labeling.yaml")
    features = _read("features.yaml")
    selection = _read("selection.yaml")

    dev = DevelopmentConfig(**project.get("development", {}))
    mock_extraction = os.environ.get("FINDROID_MOCK_EXTRACTION", "").strip().lower() in {"1", "true", "yes", "on"}

    cfg = AppConfig(
        project=ProjectConfig(**project.get("project", {})),
        dataset=DatasetConfig(**project.get("dataset", {})),
        candidate_pool=CandidatePoolConfig(**project.get("candidate_pool", {})),
        sources=SourcesTopConfig(
            androzoo=SourceToggleConfig(**project.get("sources", {}).get("androzoo", {})),
            malwarebazaar=SourceToggleConfig(**project.get("sources", {}).get("malwarebazaar", {})),
        ),
        development=dev,
        analysis=AnalysisConfig(**project.get("analysis", {})),
        security=SecurityConfig(**project.get("security", {})),
        labels=LabelsTopConfig(**project.get("labels", {})),
        output=OutputConfig(**project.get("output", {})),
        sources_detail=sources_detail,
        labeling=labeling,
        features=features,
        selection=selection,
    )
    if mock_extraction:
        cfg.development.mock_extraction = True
    return cfg
