# BASELINE.md

## What this is

A deterministic, holdout-only classifier baseline on the released dataset.
Its purpose is **engineering validation**: proving that the feature vectors
carry class signal and the export is usable as ML input. Given that the
corpus is a SIMULATED pilot — candidate metadata, detections, and labels
are mock-generated from the seed catalogues — **perfect or near-perfect
accuracy is expected and means nothing about real-world malware detection
(MASTER prompt, Section 62).**

## Run

```bash
uv run findroid baseline
```

Reads the latest versioned release under `data/releases/`, builds a
numeric-only feature matrix, fits a stratified holdout baseline, and writes
three reports to `reports/`.

## Outputs

| File | Format | Contents |
|---|---|---|
| `reports/baseline_summary.json` | JSON | disclaimer, seed, release version, feature columns, per-model accuracy/F1/confusion matrix |
| `reports/baseline_metrics.csv` | CSV long | `model, target, metric, value` rows (overall accuracy/macro-F1 + per-class precision/recall/F1/support) |
| `reports/baseline_predictions.csv` | CSV long | `model, sample_id, class_label, prediction, prob_malicious` for each test-set row |

## Protocol

- Holdout split: **25% stratified random** (`StratifiedShuffleSplit`, seed from
  `project.random_seed`, maintaining 60/40 benign/malicious ratio).
- Models: `LogisticRegression(liblinear, class_weight="balanced")` and
  `RandomForest(300 trees, class_weight="balanced_subsample")`.
- Feature matrix: release CSV minus row-contract + identity/textual columns
  (`cert.cn`, `cert.digest`, `dex.date`) + `vt_detection` (excluded because
  labels were derived from it). Constant columns are dropped.
- All numerical inputs are `StandardScaler`-fitted on the train split.

## Features used (15 on v1.1.0)

`apk.size_bytes`, `dex.classes`, `dex.methods`, `sdk.min`, `sdk.target`,
`dex.string_count`, plus 9 `str_ind.*` indicator flags
(otp/sms/ussd/overlay/accessibility/bank_brand/wallet/payment/credential).

## Expected results on the current build

Both models achieve **accuracy = 1.0, macro F1 = 1.0** on the mock holdout.
This is not a finding — it is a consequence of the synthetic provenance
(`discoverability > proof`), confirming the export produces a usable numeric
matrix. The confusion matrix is `[[60, 0], [0, 40]]`.

## Determinism

Two runs with the same seed produce **byte-identical** `baseline_summary.json`.
Reproducibility is guaranteed by: fixed seed in config, `random_state` on
all models, identical scaler fit order, and `write_csv` ordering stability.

## Known limitations (honesty)

- Not a real malware-detection benchmark. Do not cite these numbers as
  empirical evidence.
- No cross-validation or hyperparameter search. This is the simplest
  possible sanity check.
- `n_features` is 15 in v1.1.0 (permissions were filtered to distinct set
  in that release). A v1.0.0 run would report 46 features. The column set
  is auto-detected from the release CSV.