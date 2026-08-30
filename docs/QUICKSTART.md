# QUICKSTART.md

## 1. Install

```bash
cd findroid-bd-400
uv sync --extra dev
```

## 2. Run the full pipeline (mock mode, default)

```bash
uv run findroid run
```

This runs all ten phases in order: `init` `candidate_discovery` `verification`
`review_adjudication` `acquisition` `extraction` `validation_summary`
`dataset_build` `export` `report`. On completion you get:

- `database/findroid.db` — full provenance chain (13 tables).
- `data/releases/v1.0.0/` — dataset CSV, label CSV, content-hashed manifest.
- `reports/` — `distributions.csv`, `review_queue.csv`, `pipeline_summary.md`.

The run is deterministic for a fixed configuration and seed and is safe to
re-run from scratch (schema uses `IF NOT EXISTS`, tables are re-seeded).

## 3. Resume from a phase

```bash
uv run findroid run --phase dataset_build
```

Re-runs `dataset_build` and the remaining phases, skipping the completed ones.

## 4. Run a single phase as a script

```bash
uv run python pipeline/01_init.py
uv run python pipeline/05_acquisition.py
```

The scripts are numbered in PHASE order (`01 init` … `10 report`).

## 5. Inspect the outputs

```bash
head -3 data/releases/v1.0.0/findroid_bd_v1.0.0_dataset.csv
cat reports/pipeline_summary.md
sqlite3 database/findroid.db "select verification_status, count(*) from candidates group by 1;"
```

## 6. Validate

```bash
uv run pytest -q
uv run ruff check src pipeline tests
MYPYPATH=src uv run mypy -p findroid
```

## Expected run summary (current build)

| Funnel | Count |
|---|---|
| benign candidates discovered | 339 |
| malicious candidates discovered | 250 |
| unique sha256 across candidates | 589 |
| verified / manual_review | 462 / 127 |
| adjudication accepted / still required | 62 / 65 |
| mock-downloaded | 524 |
| extraction success / partial / failed | 524 / 0 / 0 |
| APK validation VALID | 524 |
| selected benign / malicious | 240 / 160 |
| gates G1–G8 | all PASS |
| released version | v1.0.0 |

The exact numbers can drift slightly if configuration changes; they are
reported in `reports/pipeline_summary.md` on every run.

## Environment variables (all optional)

| Variable | Effect | Default |
|---|---|---|
| `FINDROID_DATA_ROOT` | override `data/` root | `<repo>/data` |
| `FINDROID_DB_PATH` | override SQLite path | `<repo>/database/findroid.db` |
| `FINDROID_APK_VAULT` | override samples root | `<repo>/samples` |
| `FINDROID_MOCK_SOURCES` | `1/true` = force mock candidates | from YAML (`true`) |
| `FINDROID_MOCK_ACQUISITION` | `1/true` = force mock download | from YAML (`true`) |
| `FINDROID_MOCK_EXTRACTION` | `1/true` = force mock extraction | from YAML (`true`) |
| `FINDROID_ALLOW_REAL_APKS` | `1/true` = allow real APK bytes | from YAML (`false`) |
| `ANDROZOO_API_KEY` | needed when real AndroZoo is enabled | unset |
| `MALWAREBAZAAR_API_KEY` | needed when real MalwareBazaar is enabled | unset |