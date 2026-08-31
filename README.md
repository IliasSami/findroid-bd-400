# FinDroid-BD 400

Reproducible 400-sample Android **fintech** malware research corpus builder
(targeting Bangladesh banking / mobile financial services), produced by a
static-only, deterministic, mock-first pipeline. Educational / research only.

## Quick start

```bash
uv sync --extra dev          # install the project + dev tooling
uv run findroid --help       # CLI usage
uv run findroid run          # full pipeline (init -> reports), resumable
uv run findroid baseline     # classifier baseline on the latest release
```

Individual phases are also runnable as scripts:

```bash
uv run python pipeline/01_init.py
uv run python pipeline/08_dataset_build.py
```

## Phase map (PHASE order)

`init` `candidate_discovery` `verification` `review_adjudication` `acquisition`
`extraction` `validation_summary` `dataset_build` `export` `report`

Resume from any phase with `--phase <phase>`, e.g.
`uv run findroid run --phase dataset_build`.

## Design invariants

- **No guess as evidence.** Anything unverifiable goes to the review queue
  (`REVIEW_REQUIRED`), never silently downstream (`configs/labeling.yaml`).
- **Simulated is labelled.** All mock artifacts carry explicit `SIMULATED` /
  `mock.*` markers; real acquisition (AndroZoo/MalwareBazaar) is out of scope.
- **BD-first.** Benign seeds come from the verified catalogue in
  `metadata/fintech_seed_packages.csv`; malicious families from
  `metadata/threat_families.csv` (metadata drawn from public research).
- **Gates before release.** The builder runs Gates 1-8 (row count, 60/40
  balance, APK validity, fintech classification, malware evidence, benign
  evidence, unique SHA-256, package dedup) and refuses to release on any FAIL.
- **Configuration pinned.** Every release records `config_hash()` so a dataset
  can be re-derived from the exact configuration that produced it.

## Outputs

```
data/releases/<version>/        dataset CSV + label CSV + manifest (content-hashed)
reports/                        pipeline reports + baseline JSON/CSV (simulated sanity metrics)
database/findroid.db            full provenance chain (SQLite, 13 tables)
samples/                        simulated artifact descriptors (.mockapk.json)
```

## Documentation

- `docs/ARCHITECTURE.md` — module map, phase contract, determinism
- `docs/DATA_DICTIONARY.md` — schema + row contract
- `docs/LABELING_PROTOCOL.md` — A/B/C labels and the promotion rule
- `docs/FEATURE_EXTRACTION.md` — feature groups/catalogue and origins
- `docs/PROVENANCE.md`, `docs/REPRODUCIBILITY.md` — where rows come from; how to re-derive
- `docs/SECURITY.md`, `docs/DATASET_RELEASE.md` — controls and release policy
- `docs/TROUBLESHOOTING.md`, `docs/QUICKSTART.md`, `docs/INSTALLATION.md`
- `docs/AGENT_UNDERSTANDING.md` — recorded decisions, uncertainties, open items
- `docs/BASELINE.md` — classifier sanity check on the mock export (Section 62 compliant)

## Research integrity

> The synthetic pilot is not the real dataset.
> Pilot results must not be presented as empirical findings.
> No fabricated samples are allowed.
> No fabricated labels are allowed.
> No fabricated source citations are allowed.
> No unresolved ambiguity may be silently hidden.
> All final samples must have provenance.

This build is an **engineering validation exercise**, not a scientific result.
Every artifact explicitly carries SIMULATED / `mock.*` markers; real
acquisition and empirical labels remain out of scope until a real build runs.

## Validation

```bash
uv run pytest -q
uv run ruff check src pipeline tests
MYPYPATH=src uv run mypy -p findroid
```