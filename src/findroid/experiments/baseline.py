"""Deterministic classifier baseline on the released mock dataset.

Engineering validation only. This corpus is SIMULATED — candidate metadata,
detections, and labels were generated deterministically from the seed
catalogues — so the numbers produced here are a sanity check that (a) the
extracted feature vectors carry class signal and (b) the release export is
usable as an ML input. They are NOT an empirical malware-detection result
and must not be presented as one (Section 62 of the MASTER prompt).

Run: ``uv run findroid baseline``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler

from ..config import load_config

# Row-contract columns are metadata, not model inputs. ``vt_detection`` is also
# excluded: labels were derived from its threshold (benign == 0, malicious >= 4),
# so including it would make the task trivial and teach nothing about the
# extracted feature vectors.
ROW_CONTRACT_BLOCK = {
    "sample_id",
    "sha256",
    "source",
    "class_label",
    "label_confidence",
    "family",
    "package_name",
    "app_name",
    "version_code",
    "version_name",
    "fintech_category",
    "country",
    "vt_detection",
}

# Free-text / identity-like feature columns that are not numeric model inputs.
TEXTUAL_FEATURE_BLOCK = {"cert.cn", "cert.digest", "dex.date"}

TEST_SIZE = 0.25


def _version_key(d: Path) -> tuple[int, ...]:
    return tuple(int(part) for part in d.name.lstrip("v").split(".") if part.isdigit())


def latest_release_dir(data_root: Path) -> Path:
    """Latest versioned release directory under ``data/releases``."""
    releases = data_root / "releases"
    if not releases.is_dir():
        raise FileNotFoundError(f"no data/releases directory under {data_root}")
    versions = sorted((p for p in releases.iterdir() if p.is_dir()), key=_version_key)
    if not versions:
        raise FileNotFoundError(f"no versioned releases under {releases}")
    return versions[-1]


def dataset_csv_path(release_dir: Path) -> Path:
    matches = list(release_dir.glob("*_dataset.csv"))
    if not matches:
        raise FileNotFoundError(f"no *_dataset.csv under {release_dir}")
    return matches[0]


def build_feature_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Numeric-only feature matrix, dropping identity/textual/contract columns.

    Retains columns that parse cleanly to numbers for every row and are not
    constant. Column order is the CSV's order (stable by construction).
    """
    blocked = ROW_CONTRACT_BLOCK | TEXTUAL_FEATURE_BLOCK
    candidate = [c for c in df.columns if c not in blocked]
    numeric: list[str] = []
    for col in candidate:
        series = pd.to_numeric(df[col], errors="coerce")
        if bool(series.notna().all()):
            numeric.append(col)
    if not numeric:
        raise ValueError("no numeric feature columns found in the release CSV")
    X = df.loc[:, numeric].apply(pd.to_numeric, errors="coerce")
    X = X.loc[:, X.nunique() > 1]
    if X.shape[1] < 2:
        raise ValueError("feature matrix collapses to fewer than 2 non-constant columns")
    return X, list(X.columns)


def encode_label(df: pd.DataFrame) -> np.ndarray:
    mapping = {"benign": 0, "malicious": 1}
    if "class_label" not in df.columns:
        raise KeyError("release CSV is missing the class_label column")
    y = df["class_label"].map(mapping)
    if bool(y.isna().any()):
        raise ValueError("class_label contains values outside {benign, malicious}")
    return y.to_numpy(dtype=int)


def _models(seed: int) -> dict[str, Any]:
    return {
        "logistic_regression": LogisticRegression(
            solver="liblinear",
            C=1.0,
            class_weight="balanced",
            random_state=seed,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced_subsample",
            random_state=seed,
        ),
    }


def run_baseline(
    df: pd.DataFrame,
    *,
    seed: int,
    version: str,
    release_path: str,
    reports_root: Path,
) -> dict[str, Any]:
    """Train holdout baselines on the feature matrix and write CSV/JSON reports.

    Returns the full results dict mirroring ``reports/baseline_summary.json``.
    """
    X, feature_cols = build_feature_matrix(df)
    y = encode_label(df)
    sample_ids = df["sample_id"].astype(str).tolist()

    splitter = StratifiedShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=seed)
    train_idx, test_idx = next(iter(splitter.split(X, y)))
    scaler = StandardScaler().fit(X.iloc[train_idx])
    X_train = scaler.transform(X.iloc[train_idx])
    X_test = scaler.transform(X.iloc[test_idx])
    y_train, y_test = y[train_idx], y[test_idx]

    models: dict[str, Any] = {}
    pred_rows: list[dict[str, Any]] = []
    test_ids = [sample_ids[i] for i in test_idx]

    for name, clf in _models(seed).items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        proba = (
            clf.predict_proba(X_test)[:, 1].tolist()
            if hasattr(clf, "predict_proba")
            else [float(p) for p in y_pred]
        )
        report = classification_report(
            y_test,
            y_pred,
            output_dict=True,
            target_names=["benign", "malicious"],
            zero_division=0,
        )
        overall = {
            "accuracy": float(report["accuracy"]),
            "macro_f1": float(report["macro avg"]["f1-score"]),
        }
        per_class = {
            str(k): {kk: float(vv) for kk, vv in v.items()}
            for k, v in report.items()
            if isinstance(v, dict) and k not in ("macro avg", "weighted avg")
        }
        cm = [[int(v) for v in row] for row in confusion_matrix(y_test, y_pred)]
        models[name] = {"overall": overall, "per_class": per_class, "confusion_matrix": cm}
        for sid, yi, pi, p_mal in zip(
            test_ids, y_test.tolist(), y_pred.tolist(), proba, strict=True
        ):
            pred_rows.append(
                {
                    "model": name,
                    "sample_id": sid,
                    "class_label": "malicious" if yi else "benign",
                    "prediction": "malicious" if pi else "benign",
                    "prob_malicious": round(float(p_mal), 6),
                }
            )

    summary: dict[str, Any] = {
        "disclaimer": (
            "SIMULATED corpus: labels and metadata are mock-generated. These numbers "
            "are an engineering sanity check of the feature export, not empirical "
            "malware-detection results (MASTER prompt, Section 62)."
        ),
        "release": {"version": version, "path": release_path},
        "seed": seed,
        "n_samples": int(len(df)),
        "n_features": X.shape[1],
        "feature_columns": feature_cols,
        "holdout": {"test_size": TEST_SIZE, "stratified": True},
        "models": models,
    }

    reports_root.mkdir(parents=True, exist_ok=True)
    (reports_root / "baseline_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    metric_rows: list[dict[str, Any]] = []
    for name, m in models.items():
        metric_rows.append(
            {"model": name, "target": "overall", "metric": "accuracy", "value": m["overall"]["accuracy"]}
        )
        metric_rows.append(
            {"model": name, "target": "overall", "metric": "macro_f1", "value": m["overall"]["macro_f1"]}
        )
        for cls, stats in m["per_class"].items():
            for metric in ("precision", "recall", "f1-score", "support"):
                metric_rows.append(
                    {"model": name, "target": cls, "metric": metric, "value": stats[metric]}
                )
    pd.DataFrame(metric_rows).to_csv(reports_root / "baseline_metrics.csv", index=False)
    pd.DataFrame(pred_rows).to_csv(reports_root / "baseline_predictions.csv", index=False)

    return summary


def main(argv: list[str] | None = None) -> int:
    """Console entry: run the baseline against the latest release."""
    cfg = load_config()
    cfg.resolve_env_overrides()
    release_dir = latest_release_dir(cfg.data_root)
    csv_path = dataset_csv_path(release_dir)
    df = pd.read_csv(csv_path)
    summary = run_baseline(
        df,
        seed=cfg.project.random_seed,
        version=release_dir.name,
        release_path=str(csv_path),
        reports_root=cfg.reports_root,
    )
    print(f"baseline vs {release_dir.name}: {summary['n_samples']} rows, "
          f"{summary['n_features']} features, seed {summary['seed']}")
    for name, m in summary["models"].items():
        o = m["overall"]
        print(
            f"  {name:>20}: accuracy={o['accuracy']:.3f}  macro_f1={o['macro_f1']:.3f}  "
            f"cm={m['confusion_matrix']}"
        )
    print("wrote: reports/baseline_summary.json, baseline_metrics.csv, baseline_predictions.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
