"""Tests for the classifier baseline experiment."""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from findroid.experiments.baseline import build_feature_matrix, encode_label, run_baseline

ROW_CONTRACT = {
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


def _mini_df() -> pd.DataFrame:
    n = 40
    rows = []
    for i in range(n):
        malicious = i >= 24  # 16 malicious / 24 benign, 60/40
        rows.append(
            {
                "sample_id": f"s{i:03d}",
                "sha256": "a" * 64,
                "source": "mock",
                "class_label": "malicious" if malicious else "benign",
                "label_confidence": "B",
                "family": "Godfather" if malicious else "",
                "package_name": f"com.example.app{i}",
                "app_name": f"app{i}",
                "version_code": 1,
                "version_name": "1.0",
                "fintech_category": "banking",
                "country": "BD",
                "vt_detection": 8 if malicious else 0,
                "cert.cn": "CN=mock",
                "cert.digest": "d" * 64,
                "dex.date": "2026-01-01",
                "perm.a": int(malicious),
                "perm.b": int(not malicious),
                "sdk.min": 24 + (i % 5),
                "dex.methods": 1000 + (10 * i),
                "str_ind.overlay": int(malicious),
                "str_ind.bank_brand": 1,
                "is_simulated": 1,
            }
        )
    return pd.DataFrame(rows)


def test_feature_matrix_blocks_contract_and_textual():
    df = _mini_df()
    X, cols = build_feature_matrix(df)
    assert set(cols) == {"perm.a", "perm.b", "sdk.min", "dex.methods", "str_ind.overlay"}
    assert ROW_CONTRACT.isdisjoint(set(cols))
    assert {"cert.cn", "cert.digest", "dex.date"}.isdisjoint(set(cols))
    assert not X.isna().any().any()


def test_feature_matrix_drops_constant_columns():
    df = _mini_df()
    X, cols = build_feature_matrix(df)
    assert "is_simulated" not in cols
    assert "str_ind.bank_brand" not in cols
    assert len(cols) == 5


def test_encode_label_maps_benign_malicious():
    df = _mini_df()
    y = encode_label(df)
    assert y.dtype == np.int64
    assert set(y) == {0, 1}
    assert y.sum() == 16


def test_run_baseline_writes_reports_deterministically(tmp_path):
    df = _mini_df()
    a = run_baseline(
        df,
        seed=7,
        version="v9.9.9",
        release_path="tmp/dataset.csv",
        reports_root=tmp_path,
    )
    b = run_baseline(
        df,
        seed=7,
        version="v9.9.9",
        release_path="tmp/dataset.csv",
        reports_root=tmp_path,
    )
    assert a["models"] == b["models"]
    assert a["n_samples"] == 40
    assert a["n_features"] == 5
    assert "disclaimer" in a

    summary = json.loads((tmp_path / "baseline_summary.json").read_text())
    metrics = pd.read_csv(tmp_path / "baseline_metrics.csv")
    preds = pd.read_csv(tmp_path / "baseline_predictions.csv")
    assert summary["models"] == a["models"]
    assert set(metrics["metric"]) == {"accuracy", "macro_f1", "precision", "recall", "f1-score", "support"}
    assert set(preds["model"]) == {"logistic_regression", "random_forest"}
    assert len(preds) == 2 * 10  # two models x 25% of 40
    assert preds["prob_malicious"].between(0, 1).all()
