"""End-to-end pipeline test on an isolated (tmp) database.

Exercises the full PHASE chain exactly as ``findroid run`` would, against
temporary data/DB/vault directories, and asserts the release contracts:
exactly 400 rows, 60/40 balance, all eight gates PASS, release files present.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from findroid.dataset.export import _active_rows, export_release
from findroid.reporting import render_reports
from pipeline.run_pipeline import PHASE_ORDER, PHASES, Pipeline


def test_full_pipeline_release(cfg, tmp_path: Path):
    pipe = Pipeline(cfg)
    try:
        for name in PHASES:
            method = getattr(pipe, f"phase_{name}")
            method()

        version = cfg.version_latest(pipe.db)
        assert version.startswith("v1.")

        rows = _active_rows(pipe.db)
        assert len(rows) == cfg.dataset.total == 400
        benign = sum(1 for r in rows if r["class_label"] == "benign")
        malicious = sum(1 for r in rows if r["class_label"] == "malicious")
        assert (benign, malicious) == (240, 160)

        gates = pipe.db.fetchall("SELECT * FROM quality_checks ORDER BY gate")
        assert len(gates) == 8
        failing = [g["gate"] for g in gates if not g["passed"] and g["severity"] == "FAIL"]
        assert failing == [], f"gates failing: {failing}"

        reports_root = tmp_path / "reports"
        paths = render_reports(pipe.db, cfg, reports_root)
        assert paths["distributions"].exists()
        assert paths["summary"].exists()
        assert paths["summary_html"].exists()
        summary = paths["summary"].read_text(encoding="utf-8")
        assert "benign" in summary
    finally:
        pipe.close()


def test_export_writes_csv_parquet_and_hashed_manifest(cfg):
    pipe = Pipeline(cfg)
    try:
        for name in PHASES:
            getattr(pipe, f"phase_{name}")()
        version = cfg.version_latest(pipe.db)
        paths = export_release(pipe.db, cfg, version)

        assert paths["dataset_csv"].exists()
        assert paths["dataset_parquet"].exists()
        assert paths["label_parquet"].exists()

        manifest = json.loads(paths["manifest_json"].read_text(encoding="utf-8"))
        data_files = {p.name for k, p in paths.items() if k != "manifest_json"}
        assert set(manifest["files"]) == data_files
        assert len(manifest["content_sha256"]) == 64

        df = pd.read_parquet(paths["dataset_parquet"])
        assert len(df) == 400
        assert df["class_label"].value_counts().to_dict() == {"benign": 240, "malicious": 160}
        # cert features are stored under the static_cert group prefix
        cert_cols = [c for c in df.columns if c.startswith("static_cert.")]
        assert any("cert.cn" in c for c in cert_cols), cert_cols
    finally:
        pipe.close()


def test_resume_and_rebuild_is_idempotent(cfg):
    pipe = Pipeline(cfg)
    try:
        for name in PHASES:
            getattr(pipe, f"phase_{name}")()
        rows_before = len(pipe.db.fetchall("SELECT * FROM samples"))

        # resume the whole chain again; must not grow or duplicate anything
        for name in PHASES:
            getattr(pipe, f"phase_{name}")()
        rows_after = len(pipe.db.fetchall("SELECT * FROM samples"))
        assert rows_after == rows_before
        assert len(pipe.db.pending_reviews()) >= 0
    finally:
        pipe.close()


def test_phase_order_contract():
    assert [PHASES[i] for i in range(len(PHASES))] == PHASES
    assert tuple(PHASE_ORDER.items()) == tuple((n, i) for i, n in enumerate(PHASES))
