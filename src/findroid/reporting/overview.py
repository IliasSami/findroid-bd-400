"""Reporting: distribution overviews + human-readable summary.

Writes stable artifacts under ``reports/`` that let any reader reproduce the
corpus inventory without re-running the pipeline.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from ..config import AppConfig
from ..persistence import Database


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _active(db: Database) -> list[dict]:
    return [dict(r) for r in db.fetchall("SELECT * FROM samples WHERE dataset_version != ''")]


def render_reports(
    db: Database,
    cfg: AppConfig,
    reports_root: Path,
) -> dict[str, Path]:
    active = _active(db)
    all_samples = [dict(r) for r in db.fetchall("SELECT * FROM samples")]

    # distributions ----------------------------------------------------------
    classes = Counter(s["class_label"] for s in active)
    countries = Counter(s["country"] for s in active)
    fintech = Counter(s["fintech_category"] for s in active if s["class_label"] == "benign")
    conf = Counter(s["label_confidence"] for s in active)
    vt_bins = Counter(_vt_bin(s["vt_detection"]) for s in active)
    statuses = Counter(
        r["verification_status"] for r in db.fetchall("SELECT verification_status FROM candidates")
    )

    out = {
        "class_distribution": [
            {"class": k, "count": v, "share": round(v / max(len(active), 1), 4)} for k, v in sorted(classes.items())
        ],
        "country_distribution": [
            {"country": k, "count": v} for k, v in sorted(countries.items(), key=lambda x: -x[1])
        ],
        "fintech_subsector_distribution": [
            {"subsector": k, "count": v} for k, v in sorted(fintech.items(), key=lambda x: -x[1])
        ],
        "label_confidence_distribution": [
            {"confidence": k, "count": v} for k, v in sorted(conf.items())
        ],
        "vt_band_distribution": [
            {"vt_band": k, "count": v} for k, v in sorted(vt_bins.items())
        ],
    }

    dist_path = reports_root / "distributions.csv"
    rows = []
    for name, items in out.items():
        for item in items:
            keys = list(item.keys())
            rows.append(
                {
                    "distribution": name,
                    "key": item[keys[0]],
                    "value": ", ".join(f"{k}={v}" for k, v in item.items() if k != keys[0]),
                }
            )
    _write_csv(dist_path, rows)

    # review queue -----------------------------------------------------------
    review_rows = [
        dict(r) for r in db.fetchall("SELECT * FROM review_queue ORDER BY sample_id")
    ]
    _write_csv(reports_root / "review_queue.csv", review_rows)

    # pipeline summary -------------------------------------------------------
    gates = db.fetchall("SELECT DISTINCT gate, severity FROM quality_checks ORDER BY gate")
    lines = [
        "# FinDroid-BD 400 — pipeline summary",
        "",
        f"- configured total: {cfg.dataset.total} (benign {cfg.dataset.benign} / malicious {cfg.dataset.malicious})",
        f"- active version rows: {len(active)}",
        f"- candidates registered: {len(all_samples)}",
        f"- verification status mix: {dict(sorted(statuses.items()))}",
        "",
        "## Distributions",
    ]
    for name, items in out.items():
        lines.append(f"\n### {name}")
        lines.append("| key | value |")
        lines.append("|---|---|")
        for item in items:
            keys = list(item.keys())
            key = item[keys[0]]
            value = ", ".join(f"{k}={v}" for k, v in item.items() if k != keys[0])
            lines.append(f"| {key} | {value} |")
    lines.append("\n## Quality gates")
    lines.append("| gate | severity |")
    lines.append("|---|---|")
    for g in gates:
        lines.append(f"| {g['gate']} | {g['severity']} |")
    summary = "\n".join(lines) + "\n"

    summary_path = reports_root / "pipeline_summary.md"
    summary_path.write_text(summary, encoding="utf-8")

    return {"distributions": dist_path, "review_queue": reports_root / "review_queue.csv", "summary": summary_path}


def _vt_bin(vt) -> str:
    if vt is None:
        return "none"
    if vt == 0:
        return "0 (clean)"
    if vt < 4:
        return "else"
    if vt < 10:
        return "4-9"
    if vt < 30:
        return "10-29"
    return "30+"
