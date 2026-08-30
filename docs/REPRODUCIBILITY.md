# REPRODUCIBILITY.md

## What reproducibility is claimed

- A fixed configuration + fixed seed + fixed code produces the **same**
  release (dataset CSV bytes, label CSV, manifest hash) every run.
- The pipeline's ten phases form a deterministic DAG; candidate generation,
  dedup, selection, extraction, and export are all seeded or keyed-stable.
- Tests enforce this: `tests/test_sources.py` asserts catalog determinism,
  `tests/test_pipeline_e2e.py` asserts byte-level dataset determinism across
  two fresh runs with identical env.

## Determinism mechanisms

1. **Fixed seed.** `configs/project.yaml` → `project.random_seed: 20260831`.
   All candidate/artifact RNG is seeded from this value (plus stable per-row
   keys such as sha256), so ordering and mock values are stable across runs and
   machines.
2. **Ordered features.** `select_features()` orders columns by group then name;
   the row contract columns are fixed.
3. **Stable export keys.** Export iterates samples by deterministic sample_id
   ordering; no run ID, wall clock, or unordered dict is allowed into release
   rows.
4. **Configuration pinning.** `dataset_versions` records `config_hash`
   (`AppConfig.config_hash()`) per release; the manifest stores it. Two
   releases with different config are distinguishable, and a release can be
   re-derived by checking out the recorded config.

## Environment influence

| Input | Effect |
|---|---|
| `random_seed` | defines mock catalogue sampling |
| `FINDROID_*` env overrides | change data root/db/vault & mock toggles |
| Python/OS | none, so long as `write_csv` ordering is stable (tested) |

Reproduction on another machine: install the same revision (`git rev-parse
HEAD`), keep config files unchanged, run `uv sync --extra dev` then
`uv run findroid run`.

## Getting the same numbers as this README's run summary

```bash
git checkout <commit of this build>           # commit pinned in the release notes
uv sync --extra dev
uv run findroid run
cat reports/pipeline_summary.md                # compare funnel counts
git hash-object data/releases/v1.0.0/findroid_bd_v1.0.0_dataset.csv
```

The manifest's `content_sha256` trusts the release file free of tampering; the
source-of-truth comparison is regenerating and diffing the CSV.

## What is NOT reproducible (honesty section)

- Real-world provenance (VT responses, Play listings) — simulated in this
  build; real values would of course vary over time.
- Any downstream model numbers — this repo builds the dataset, not models.
- Cross-version repro: a different build revision may legitimately change the
  schema or funnel; pin the revision, not "latest".