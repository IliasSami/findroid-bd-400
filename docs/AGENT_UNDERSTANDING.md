# AGENT_UNDERSTANDING.md

This file records the implementing agent's understanding of the project at the
time of implementation (Section 8 of the MASTER prompt). Discrepancies with
other project artifacts are stated rather than hidden.

## Project objective

Design, implement, validate, document, and operationalize a reproducible
pipeline that constructs a **400-sample** Android fintech dataset —
`FinDroid-BD 400` — targeting Bangladesh banking / mobile financial services
(BKash, Nagad, Rocket, and regional bank apps), plus the real fintech-malware
families documented as targeting those institutions.

The repository is the *reference implementation*: it builds the dataset in a
fully deterministic **mock-first** mode so the pipeline, schema, gates, and
reports are engineering-validated before any real acquisition is attempted.

## Dataset target

- Total: **400**
- Benign: **240**
- Malicious: **160**

## Benign definition

An APK is benign when no trusted source reports it as malware and the
application is a genuine, legitimate app (seeded from the verified fintech
packages catalogue in `metadata/fintech_seed_packages.csv`, e.g. BKash,
Nagad, Rocket, banking apps). Label confidence depends on the strength of
vendor documentation (`configs/labeling.yaml`: clean state on Play, vendor
pages, last-scan dates) — see `docs/LABELING_PROTOCOL.md`.

## Malicious definition

An APK is malicious when at least one trusted source (documented family
report, VirusTotal detections ≥ `labels.malicious_vt_min` = 4, family
write-ups) provides evidence of malicious intent — e.g. banking trojan,
accessibility-abusing overlay banker, aggressive adware, fraud app.
Families come from `metadata/threat_families.csv` and must be associated with
financial targeting to be eligible for this corpus.

## Fintech definition

A candidate is fintech when its `fintech_category` is one of the recognized
categories and the classification is supported by an explicit
`fintech_basis`. Category values are validated against the schema contract.
Shopping, tools, games, and generic utilities are rejected as non-fintech.
The classification decision assigns a score/basis per candidate and is
recorded in `fintech_basis`; weak/no basis routes the candidate to review,
not to silent acceptance.

## Data sources

- `metadata/fintech_seed_packages.csv` — benign seed catalogue (package
  names, markets, categories, fintech categories).
- `metadata/threat_families.csv` — documented malicious families with
  targeting/basis notes (drawn from public research; see PROVENANCE).
- Runtime acquisition sources (declared but **not executed** in this build):
  AndroZoo and MalwareBazaar. Both source toggles exist in
  `configs/project.yaml`; `development.mock_sources: true` is the operational
  default and no real API is called without an API key and an explicit
  opt-out of mock mode.

## Label policy

See `configs/labeling.yaml` and `docs/LABELING_PROTOCOL.md`.

- Labels are **A/B/C** confidence bands, never unqualified "benign"/"malicious".
- Benign: low/zero VT detections = B (or A with strong vendor-document-based
  clean evidence); >0 but ≤ `benign_vt_max` triggers `benign_dirty` handling.
- Malicious: VT ≥ `malicious_vt_min` (4) or strong family documentation.
- Every label records `label_evidence_reference`, `fintech_basis`,
  `targeting_basis`. Out-of-band C-confidence candidates go to the review
  queue (`REVIEW_REQUIRED`) and never reach the release.
- Verification (not labeling) decides promotion; only `verified` + A/B
  confidence candidates are eligible for selection.

## Feature policy

Static-first. Feature groups (declared order): `static_manifest`,
`static_code`, `static_cert`, `fintech`, `dynamic`.

**Implementation reality (stated):** in the current mock build the extractor
emits `static_manifest` features (manifest-derived and derived aggregations;
simulated artifact descriptors) and `fintech` features. `static_code` and
`static_cert` exist as declared groups exactly like the schema contract
requires, `static_cert` features are filed under the `static_manifest` group
by the extractor (schema-name-only group), and `dynamic` is schema-name-only
— no dynamic detonation is implemented (`analysis.dynamic: false`,
`security.execute_apks: false`). Every feature row records its `origin` as
`measured | derived | simulated` and `source_tool`, so downstream users can
filter by provenance.

## Duplicate policy

`deduplication/dedup.py`:

- Exact duplicate = identical `sha256`.
- Near-duplicate clustering by `package_version`, `manifest`, `certificate`,
  and `permissions` fingerprints; clusters are recorded in
  `dedup_clusters` with a `fingerprint_type`.
- Selection only reaches mutually-unique rows; G8 enforces the selection's
  package-name distinctness.

## Security restrictions

- `security.execute_apks: false` — APKs are never executed.
- `development.allow_real_apks: false` — no live APK bytes are written or run.
- Real acquisition requires explicit opt-out of mock mode, API keys, and
  reverting `allow_real_apks`. See `docs/SECURITY.md`.

## Free-resource constraints

- No paid or gated APIs. Only documented public endpoints (AndroZoo/MalwareBazaar
  community APIs carry free research tiers) are referenced.
- All local computation runs on CPU; the build is deterministic via
  `project.random_seed` (`20260831`) and monkey-patch-free reproducibility.

## Pipeline stages

`init` → `candidate_discovery` → `verification` → `review_adjudication` →
`acquisition` → `extraction` → `validation_summary` → `dataset_build` →
`export` → `report`.

Each phase maps to `pipeline/{01..10}_*.py`; resume via `--phase <name>`.

## Expected outputs

- SQLite provenance database `database/findroid.db` (13 tables).
- Release package under `data/releases/<version>/`:
  `findroid_bd_<version>_dataset.csv`, `findroid_bd_<version>_label.csv`,
  `findroid_bd_<version>_manifest.json` (content-hashed).
- `reports/`: `distributions.csv`, `review_queue.csv`, `pipeline_summary.md`.

## Known uncertainties

- Real per-app labels are unverifiable without real sources; everything in
  the current build is **simulated provenance** and must be treated as such.
- `vt_detection` values are mock values, not real VirusTotal scans.
- Java-free host: local APK parsing is not exercised end-to-end (extraction
  runs against simulated `.mockapk.json` descriptors).

## Known inconsistencies (recorded, not silently fixed)

- `static_cert` is a declared group but features are filed under
  `static_manifest`; schema columns exist, the group is not separately exercised.
- `dynamic` group is schema-name-only.
- `configs/project.yaml` declares `output.html_report` and CSVs/parquet toggles;
  the exporter writes CSV + JSON manifest + label CSV today and **not**
  parquet/HTML, even though the flags exist.
- The review-adjudication phase logs `still_required` — benign reviews are
  never auto-resolved; 65 benign samples remain `REVIEW_REQUIRED` by design.
- The parent-spec pilot (`findroid_bd_pilot_v0.1.csv`) is a 0.1 pilot with a
  different shape; this repo's schema is the v1.0 contract.

## Open implementation decisions

- Whether real acquisition (AndroZoo/MalwareBazaar) will be enabled on a
  Java-capable host in a later phase — currently out of scope.
- Whether `static_cert`/`dynamic` groups will receive extractor support.
- Whether the exporter will emit parquet/HTML when those flags are used.
- Whether REVIEW_REQUIRED samples are later adjudicated by a human reviewer
  into the release, or remain excluded (current default: excluded).