# ARCHITECTURE.md

## Overview

FinDroid-BD 400 is a deterministic, configuration-first, mock-first pipeline
that assembles a 400-sample (240 benign / 160 malicious) Android fintech
dataset. Every stage exchanges typed Pydantic records (`src/findroid/models/`),
persists to one SQLite database, and can be resumed from any phase.

```
configs/*.yaml ──► AppConfig (validated, hashable)
                        │
pipeline/run_pipeline.py  Pipeline (10 phases, resumable)
                        │
      ┌─────────────────┼─────────────────────────────┐
      ▼                 ▼                             ▼
candidate        verification/               dataset/export  ──► data/releases/<v>/
discovery        labeling                    (Gates 1–8)     ──► reports/
   │                 │                             │             ──► database/findroid.db
   ▼                 ▼                             ▼
source mocks     review_queue                  SQLite: candidates, verification,
   ▼                 │                          labels, samples, features,
acquisition       adjudication                 dedup_clusters, dataset_versions …
   ▼
extraction (static_manifest + fintech groups)
```

## Module map

| Path | Responsibility |
|---|---|
| `src/findroid/config.py` | `AppConfig`; loads `configs/*.yaml`; env overrides; `config_hash()`; `missing_credentials()` |
| `src/findroid/models/__init__.py` | Typed records + enums (`CandidateRecord`, `SampleRecord`, `LabelRecord`, `FeatureRecord`, `ReviewRecord`, `GateResult`, …) |
| `src/findroid/persistence.py` | SQLite schema (13 tables) + `Database` helper (incl. `scalar()`) |
| `src/findroid/sources/` | Candidate generation; `mock_candidates.py` (deterministic, quota-driven) |
| `src/findroid/verification/` | `verify.py` (status adjudication, promotion rule), `labels.py` (A/B/C triage, Confidence bands) |
| `src/findroid/deduplication/dedup.py` | SHA-256 exact dedup + fingerprint clustering |
| `src/findroid/acquisition/` | mock downloader writing `.mockapk.json` descriptors; APK validation |
| `src/findroid/extraction/` | feature extraction; `features/schema.py` (`ROW_CONTRACT`, `FEATURE_GROUPS`) |
| `src/findroid/reporting/overview.py` | `render_reports(db, cfg, reports_root)` → CSV/MD reports |
| `src/findroid/dataset/` | `builder.py` (selection), `gates.py` (G1–G8), `export.py` (release writer) |
| `src/findroid/cli/main.py` | console entry `findroid` wrapping `pipeline.run_pipeline.main` |
| `pipeline/run_pipeline.py` | `PHASES`/`PHASE_ORDER`; `Pipeline` class; `main()`; resume logic |
| `pipeline/01_init.py … 10_report.py` | numbered phase scripts sharing `_phase.py` (absolute-import bootstrap) |
| `configs/` | `project.yaml`, `sources.yaml`, `labeling.yaml`, `features.yaml`, `selection.yaml` |
| `metadata/` | seed catalogues (`fintech_seed_packages.csv`, `threat_families.csv`) |
| `tests/` | 30 tests: config, verification, dedup, labeling, sources, E2E pipeline |

## Configuration flow

1. `load_config()` reads the five YAML files once (cached).
2. `AppConfig` validates with Pydantic and resolves env overrides
   (`resolve_env_overrides()`), then `missing_credentials()` warns if real
   acquisition would run without API keys.
3. `config_hash()` produces a canonical SHA-256 of the resolved config; the
   released manifest records it so a release is pinned to its configuration.

## Phase contract

Each phase is a `Pipeline` method receiving `(self, db, cfg)`, logging a
summary line, and returning after committing. `Pipeline.run(start)` executes
from the given phase to the end; a `SystemExit` raised by gate failure halts
the pipeline (release stays BLOCKED). Phase order is centralized in
`PHASE_ORDER`; scripts are thin wrappers.

## Resumability

- Tables are created with `CREATE TABLE/INDEX IF NOT EXISTS`.
- Candidate re-seeding clears and regenerates deterministically.
- `--phase <name>` skips earlier phases. Major re-builds (schema change) are
  pushed to a new dataset version rather than mutating old releases.

## Determinism

- `project.random_seed = 20260831`; all mock generation uses seeded RNG.
- Extracted features are keyed by sha256; selection order is stable.
- Tests assert byte-level determinism of the dataset CSV across runs.