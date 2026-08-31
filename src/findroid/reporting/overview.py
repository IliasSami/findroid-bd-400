"""Reporting: distribution overviews + human-readable summary.

Writes stable artifacts under ``reports/`` that let any reader reproduce the
corpus inventory without re-running the pipeline. ``output.html_report`` adds a
self-contained ``pipeline_summary.html`` view of the same data.
"""

from __future__ import annotations

import csv
import html
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

    paths = {
        "distributions": dist_path,
        "review_queue": reports_root / "review_queue.csv",
        "summary": summary_path,
    }

    if cfg.output.html_report:
        html_path = reports_root / "pipeline_summary.html"
        html_path.write_text(
            _render_html_summary(
                dataset=cfg.dataset,
                active=len(active),
                all_samples=len(all_samples),
                statuses=statuses,
                distributions=out,
                gates=gates,
            ),
            encoding="utf-8",
        )
        paths["summary_html"] = html_path

    return paths


def _render_html_summary(*, dataset, active, all_samples, statuses, distributions, gates) -> str:
    def esc(value) -> str:
        return html.escape(str(value))

    table = []
    for name, items in distributions.items():
        table.append(f"<h3>{esc(name)}</h3>")
        table.append("<table>")
        for item in items:
            keys = list(item.keys())
            key = item[keys[0]]
            value = ", ".join(f"{k}={v}" for k, v in item.items() if k != keys[0])
            table.append(f"<tr><td>{esc(key)}</td><td>{esc(value)}</td></tr>")
        table.append("</table>")

    gate_rows = "\n".join(
        f"<tr><td>{esc(g['gate'])}</td><td>{esc(g['severity'])}</td></tr>" for g in gates
    )
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>FinDroid-BD 400 — pipeline summary</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; line-height: 1.5; }}
  h1, h2, h3 {{ color: #1a1a1a; }}
  table {{ border-collapse: collapse; margin: 0.25rem 0 1rem; }}
  td, th {{ border: 1px solid #d0d0d0; padding: 0.25rem 0.6rem; font-size: 0.9rem; }}
  th {{ background: #f2f2f2; }}
  .muted {{ color: #666; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>FinDroid-BD 400 — pipeline summary</h1>
<p class="muted">Engineering validation artifacts. This corpus is SIMULATED; do
not present these numbers as empirical results (MASTER prompt, Section 62).</p>
<ul>
<li>configured total: {esc(dataset.total)} (benign {esc(dataset.benign)} / malicious {esc(dataset.malicious)})</li>
<li>active release rows: {esc(active)}</li>
<li>candidates registered: {esc(all_samples)}</li>
<li>verification status mix: {esc(dict(sorted(statuses.items())))}</li>
</ul>
<h2>Distributions</h2>
{''.join(table)}
<h2>Quality gates</h2>
<table>
<tr><th>gate</th><th>severity</th></tr>
{gate_rows}
</table>
</body>
</html>
"""


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
