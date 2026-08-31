# DATASET_RELEASE.md

## Release policy (no release before final validation — Section 69)

The export directory is **not** written unless gates pass and the build
registers a version. In this pipeline:

```
dataset_build (Gates 1–8)  ── all PASS ──► dataset_versions += vX.Y.Z
                                                │
                                                ▼
                                     export ──► data/releases/<version>/
```

If any gate returns `FAIL`, the build raises `SystemExit` and **no** release
directory is created for that version. A release you can see on disk
therefore means gates passed.

## One build goal. Scores are a justification — not a free pass.

Scores never override gates. A stronger-looking run cannot release a corpus
that fails G1–G8 (Section 69: "no dataset release before final validation").

## Release layout

```
data/releases/<version>/
  findroid_bd_<version>_dataset.csv      # 400 rows, ROW_CONTRACT + features
  findroid_bd_<version>_dataset.parquet  # same table (when output.parquet)
  findroid_bd_<version>_label.csv        # per-sample label + confidence + family
  findroid_bd_<version>_label.parquet    # same (when output.parquet)
  findroid_bd_<version>_manifest.json    # build bookkeeping (below)
```

No APK binaries are released — hashes and feature vectors only (AndroZoo terms
/ SECURITY.md). Manifest `content_sha256` covers the produced files.

## Manifest contents

| Field | Meaning |
|---|---|
| `version` | release tag (`v1.0.0`) |
| `build_mode` | mock toggles + explicit SIMULATED note |
| `dataset` / `class_breakdown` | 240 / 160 / 400 |
| `gates` | per-gate `passed` / `severity` / `detail` |
| `config_hash` | pinned config (`AppConfig.config_hash()`) |
| `content_sha256` | content hash of the release files |
| `files` | list of non-manifest release files covered by the content hash |
| `row_count` | 400 |
| `generated_at` | run timestamp (informational only) |

## Current release state

- `v1.0.0` — the first validated build (all 8 gates PASS).
- `v1.1.0` — a later build revision regenerated during development; both exist
  under `data/releases/` as historical artifacts. `dataset_versions` documents
  the latest (`version_latest()`).

Both are **engineering-validated mock builds**; neither is an empirical
dataset. The manifest's `build_mode.note` states this on every file produced.

## Releasing a new version

1. Decide the version (register `dataset_version` — sizes/config change ⇒ bump).
2. Re-run the build: `uv run findroid run` (or `--phase dataset_build`).
3. Confirm all gates PASS (also visible in `reports/pipeline_summary.md` and
   `reports/distributions.csv`).
4. Confirm the manifest's `config_hash` matches the config that produced it.
5. Commit list in the release notes: config diff + funnel counts + gate detail.

## Renowning a release

- Do **not** hand-edit CSVs in `data/releases/`. Regenerate through the
  pipeline; the manifest and gate ledger keep it honest.
- The 400/240/160 contract is enforced by G1/G2 at build time, not by
  documentation.
- Do not ship `samples/` or `database/` with releases — they are gitignored
  and local-only by policy.