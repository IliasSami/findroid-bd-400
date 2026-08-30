# DATA_DICTIONARY.md

The canonical source of truth is the SQLite schema in
`src/findroid/persistence.py` (`_SCHEMA`, 13 tables) and the typed records in
`src/findroid/models/__init__.py`. Release `<version>` dataset rows must carry
the `ROW_CONTRACT` columns (`src/findroid/features/schema.py`).

## Row contract (every final release row)

| Column | Type | Meaning |
|---|---|---|
| `sample_id` | str | stable sample identifier |
| `sha256` | str | content SHA-256 (64 hex) — provenance anchor |
| `source` | str | origin source (`benign_seed_catalogue`, `malware_families`, `androzoo`, `malwarebazaar`, …) |
| `class_label` | `benign`/`malicious`/`unknown` | final class |
| `label_confidence` | `A`/`B`/`C` | label confidence band |
| `family` | str | documented family (empty for benign) |
| `package_name` | str | Android package name |
| `app_name` | str | market app name |
| `version_code` | int | APK version code |
| `version_name` | str | APK version string |
| `fintech_category` | str | fintech category (validated) |
| `country` | str | market/registration country |
| `vt_detection` | int | VirusTotal detection count (mock in current build) |

Downstream feature columns are appended in `FEATURE_GROUPS` order
(`static_manifest`, `static_code`, `static_cert`, `fintech`, `dynamic`).

## Database tables

| Table | Purpose |
|---|---|
| `sources` | source registry (key, kind, configured flag) |
| `candidates` | raw candidates, provenance + verification status |
| `verification` | per-candidate verification check ledger |
| `labels` | final/transitional labels with confidence + evidence |
| `label_evidence` | evidence rows backing labels |
| `samples` | selected/released samples and their stage status |
| `extraction_runs` | per-sample extraction run ledger |
| `features` | extracted feature rows (name, value, dtype, group, origin, tool) |
| `dedup_clusters` | duplicate clusters by fingerprint type |
| `quality_checks` | gate results per run |
| `dataset_versions` | released versions + `config_hash` |
| `review_queue` | human-review items (`REVIEW_REQUIRED`) |
| `errors` | stage error ledger |

## Candidates table (key columns)

Any of `suspected_class` (`benign`/`malicious`/`unknown`), `verification_status`
(`pending`, `verified`, `rejected`, `manual_review`, `collision`, `duplicate`,
`insufficient_evidence`), `fintech_category`, `fintech_basis`, `targeting_basis`,
`evidence`, `source_reference`, `source_timestamp`, `vt_detection`.

## Labels table (key columns)

`sample_id`, `sha256`, `class_label`, `confidence`, `family`,
`family_confidence`, `targeting_basis`, `vt_detection`, `evidence_refs`
(pipe-joined), `reviewed`, `reviewer`, `review_timestamp`.

## Samples table (stage status columns)

`acquisition_status` (`pending`, `downloading`, `completed`, `failed`,
`simulated`, `skipped`); `apk_validation_status`
(`VALID`/`PARTIAL`/`INVALID`/`NOT_CHECKED`); `feature_extraction_status`
(`SUCCESS`/`PARTIAL`/`FAILED`/`NOT_RUN`); `dataset_version`.

## Review queue table

`sample_id`, `candidate_label`, `candidate_family`, `confidence`, `reason`,
`evidence`, `review_required`, `review_status` (`REVIEW_REQUIRED` by default),
`reviewer`, `review_timestamp`, `final_decision`, `review_notes`.

## Feature row

`feature_name` qualified by group prefix (`perm.`, `sdk.`, `cert.`, `dex.`,
`apk.`, `str_ind.`, `drop_`, `fin_`, `is_simulated`); see
`docs/FEATURE_EXTRACTION.md`. `origin` is one of `measured | derived |
simulated`; `source_tool`, `extractor_version`, and `extraction_status` are
always recorded.

## Enumerations

Defined as `StrEnum` in `src/findroid/models/__init__.py`:
`VerificationStatus`, `ClassLabel`, `Confidence`, `ExtractionStatus`,
`ValidationStatus`, `AcquisitionStatus`. Store their `.value` strings.