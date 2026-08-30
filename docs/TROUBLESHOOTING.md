# TROUBLESHOOTING.md

## The pipeline refuses to start

**Symptom:** `uv run findroid run` dies at import with
`No module named 'pipeline'` or missing `findroid`.

**Cause:** package not installed (editable) or run outside the repo root.

**Fix:** `cd findroid-bd-400 && uv sync --extra dev`. The CLI entry needs the
`src` layout installed (`[tool.setuptools.packages.find] where = ["src"]`).

## `findroid` says "unknown command" or prints help unexpectedly

`run` must be the first argument: `uv run findroid run [--phase <name>]`.
Anything else prints `__doc__`/usage and exits 0/2.

## Phase failure halts the pipeline

Any phase exception raises `SystemExit("Pipeline halted at phase <name>")`.

- Fix the underlying cause (see node: check `database/findroid.db` tables and
  `errors` table).
- Re-run with `--phase <name>` to resume from the failed phase; earlier phases
  are already committed and left untouched.

## "index idx_candidates_class already exists" (resume)

**Cause:** running against a schema created by an older revision.

**Fix:** delete `database/findroid.db` and re-run from `init`, or upgrade the
revision. Current schema uses `CREATE INDEX IF NOT EXISTS` for all indexes, so
this only bites when the DB was created by pre-fix code.

## Release is BLOCKED / dataset not exported

`dataset_build` runs Gates 1–8; any `FAIL` raises `SystemExit` before export.

| Gate | Blocks when |
|---|---|
| G1 row_count | total ≠ 400 |
| G2 balance | benign/malicious ≠ 240/160 |
| G3 apk_validity | any INVALID apk |
| G4 fintech_classification | any row missing fintech evidence |
| G5 malware_evidence | any malicious row weak (no evidence/family) |
| G6 benign_evidence | any benign row has VT detections > 0 |
| G7 unique_sha256 | any duplicate sha256 in the 400 |
| G8 package_dedup | oversized version pile-up for one package (WARNING-only) |

Inspect: `SELECT gate, passed, severity, detail FROM quality_checks ORDER BY
check_id DESC LIMIT 8;`. Most fixes require re-deriving samples — bump the
dataset version and re-run.

## "no dataset version registered yet; run the build phase first"

`report` reads the latest version via `config.version_latest(db)`; this raises
when `dataset_versions` is empty. Run `--phase dataset_build` first.

## 65 samples stuck in REVIEW_REQUIRED

By design (`c_requires_review`, C-confidence and unresolved benign candidates
never promote; benign reviews are never auto-resolved). Query:
`SELECT * FROM review_queue WHERE review_status='REVIEW_REQUIRED';` and
adjudicate manually if inclusion is desired (open decision; default excludes).

## Extraction reports NO_ARTIFACT / FAILED

`samples/` descriptor missing or unreadable. Descriptors are produced by
acquisition; re-run `--phase acquisition` (which regenerates the `.mockapk.json`
files), then `--phase extraction`. Check `errors` for `stage='extraction'`.

## Tests fail or mypy/ruff issues

```bash
uv run pytest -q            # 30 tests
uv run ruff check src pipeline tests
MYPYPATH=src uv run mypy -p findroid
```

- `ruff` auto-fixes: `uv run ruff check src pipeline tests --fix`.
- pyproject mypy excludes `.venv` and `pipeline`; the `[[tool.mypy.overrides]]`
  block is for `androguard.*` (missing stubs).
- Reinstall freshly if the venv predates the current `pyproject.toml`
  (`uv sync --extra dev`).

## Offline / no keys warnings

`WARNING: missing credentials: ANDROZOO_API_KEY, MALWAREBAZAAR_API_KEY` is a
warning, not an error, because mock mode is on. It becomes blocking only when
`mock_sources` is disabled without keys.

## Column-order disagreement with the parent-spec pilot

The parent `findroid_bd_pilot_v0.1.csv` is a 0.1 pilot with an earlier shape.
The v1.0 row contract (`docs/DATA_DICTIONARY.md`) is what release exports use;
do not engineer against the pilot file.