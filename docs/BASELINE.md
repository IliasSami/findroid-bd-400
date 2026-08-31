# BASELINE.md

## What this is

A deterministic, holdout-only classifier **sanity baseline** on the released
**real** dataset (`v1.0.0`, 311 samples). Its purpose is **engineering
validation**: proving the static feature vectors carry class signal and the
export is usable as ML input. It is **not** an empirical malware-detection
benchmark, and the numbers here must not be cited as a production detection
result.

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

- Holdout split: **25% stratified random** (`StratifiedShuffleSplit`, seed
  `20260831`, preserving the 147/164 benign/malicious ratio).
- Models: `LogisticRegression(liblinear, class_weight="balanced")` and
  `RandomForest(300 trees, class_weight="balanced_subsample")`.
- Feature matrix: numeric-only columns from the release CSV (row-contract,
  identity and label-derived columns excluded; constant columns dropped).
- All numerical inputs are `StandardScaler`-fitted on the train split.

## Results on v1.0.0 (real 311 samples, 3 features)

| Model | Accuracy | Macro F1 |
|---|---|---|
| Logistic regression | 0.795 | 0.794 |
| Random forest | 0.936 | 0.936 |

Features used: `static_manifest.apk.size_bytes`, `static_manifest.sdk.min`,
`static_manifest.sdk.target`. The feature export carries clear class signal
(RF ≈ 0.94) despite this being the smallest possible feature set — a
meaningful sanity check that the real labels and features are usable for ML.

## Determinism

Two runs with the same seed produce **byte-identical**
`baseline_summary.json`. Reproducibility is guaranteed by: fixed seed,
`random_state` on all models, identical scaler fit order, and `write_csv`
ordering stability.

## Known limitations (honesty)

- **Not a real malware-detection benchmark** and not a tuned model — no
  cross-validation or hyperparameter search. Only 3 low-level static features
  were in the v1.0.0 numeric export, so the baseline is a lower bound.
- A proper evaluation requires feature engineering (permissions, intents,
  API calls), cross-validated training, and a held-out independent test set.
- Baseline numbers are an engineering sanity check, not a claim about
  detection efficacy in the wild.
