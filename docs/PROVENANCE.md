# PROVENANCE.md

## What provenance means here

Every artifact in the pipeline carries provenance fields that let a downstream
user answer three questions: *where did this come from*, *was it a real
observation or a simulation*, and *what configuration produced it*.

```
candidate ──(candidate_id, source, source_reference, source_timestamp,
              evidence, sha256)──► verification ──► label ──► sample
                                                           └──(dataset_version,
                                                               config_hash)
```

## Provenance fields on candidates

`CandidateRecord` (also the `candidates` table) records:

- `source` — which catalogue/source produced the row (`benign_seed_catalogue`,
  `malware_families`, `androzoo`, `malwarebazaar`, …).
- `source_reference` / `source_timestamp` — where and when.
- `sha256` — content hash anchor, never dropped between stages.
- `evidence` — free-text evidentiary basis (family notes, vendor doc cues).
- `fintech_basis` / `targeting_basis` — *why* this row is fintech / financially
  targeted.
- `verification_status` + `verification_notes` — what the policy checks found.

## Seed catalogues (`metadata/`)

- `fintech_seed_packages.csv` — benign catalogue: `package_id, app_name,
  organisation, country, tier, subsector, verification_status, evidence`.
  Rows carry a `verification_status` and `evidence` column (e.g. "Play listing
  2026-08").
- `threat_families.csv` — malicious families: `family, first_reported,
  region_focus, primary_techniques, delivery_vector, typical_vt_detection,
  provenance_note`. Provenance notes name the public research they were drawn
  from (e.g. Zimperium 2026, ThreatIntel-Andro). These are *documented public
  observations*, not this project's findings.
- `play_policy_timeline.csv` and `metadata/source_metadata/` supplement the
  catalogue provenance.

## Simulated vs real provenance

- **Simulated (current mode).** Candidate metadata is generated deterministically
  from the catalogues + seeded RNG. Artifact descriptors (`.mockapk.json`) carry
  a `simulated: true` marker; the extractor emits an `is_simulated` feature and
  stamps every feature with `origin` and SIMULATED extractor version
  (`0.2.0-mock`). Nothing in the release can be mistaken for a real sample.
- **Real (declared, not executed).** AndroZoo/MalwareBazaar would supply the
  hash/package/date and real bytes; the sha256 is recomputed from downloaded
  bytes; sources record API provenance. Not enabled in this build
  (`development.mock_sources: true`).

## Configuration provenance

- Resolved config is pinned by `config_hash()` (canonical JSON of
  `AppConfig`, sorted keys, compact separators).
- Every release row in `dataset_versions` records `total`, `benign`,
  `malicious`, `config_hash`, and `notes`.
- The release manifest (`data/releases/<v>/…_manifest.json`) records a
  `content_sha256`, so released files are self-verifying.

## Provenance guarantees that are NOT claimed

- Real per-app labels — none exist until real sources are acquired.
- `vt_detection` — mock values in this build (not VirusTotal responses).
- No claim that released binaries correspond to real apps: no binaries are
  released (hashes + feature vectors only, per AndroZoo redistribution terms).