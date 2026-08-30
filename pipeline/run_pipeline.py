"""End-to-end pipeline runner.

Mirrors the MASTER prompt's PHASE 0-16 execution order as discrete, resumable
phases over the FinDroid-BD-400 SQLite database. Every phase is idempotent
within a stage (states in the DB) so a failure can be fixed and resumed.

Run from the repository root:
    uv run findroid --help
    uv run findroid run            # full pipeline (fresh or resumable)
    uv run findroid run --phase 7  # resume from phase 7
"""

from __future__ import annotations

import sys
import traceback

from findroid import config as _cfg
from findroid import reporting
from findroid.acquisition.acquire import acquire_samples
from findroid.config import AppConfig, load_config
from findroid.dataset.builder import build_dataset
from findroid.dataset.export import export_release
from findroid.dataset.review import adjudicate_pending
from findroid.extraction.extract import run_extraction_for_all
from findroid.persistence import Database
from findroid.sources.mock_benign import load_benign_seed_catalog
from findroid.sources.mock_candidates import (
    generate_benign_candidates,
    generate_malicious_candidates,
)
from findroid.sources.mock_malware import build_family_catalogue
from findroid.verification.verify import verify_pending_candidates

PHASES = [
    "init",
    "candidate_discovery",
    "verification",
    "review_adjudication",
    "acquisition",
    "extraction",
    "validation_summary",
    "dataset_build",
    "export",
    "report",
]

PHASE_ORDER = {name: i for i, name in enumerate(PHASES)}


class Pipeline:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.db = Database(cfg.db_path)
        self.catalog = load_benign_seed_catalog(
            _cfg.PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv"
        )
        self.families = build_family_catalogue(
            _cfg.PROJECT_ROOT / "metadata" / "threat_families.csv"
        )

    # ---------------------------------------------------------------- helpers
    def close(self) -> None:
        self.db.close()

    def log(self, phase: str, lines: list) -> None:
        print(f"\n== phase {PHASE_ORDER[phase]}: {phase} ==")
        for line in lines:
            print("  ", line)

    # ------------------------------------------------------------------ phases
    def phase_init(self) -> list:
        self.db._init_schema()
        for key in ("mock_play", "mock_malwarebazaar"):
            self.db.execute(
                "INSERT OR IGNORE INTO sources (source_key, kind, display_name, configured) VALUES (?,?,?,?)",
                (key, key, key, int(not self.cfg.development.mock_sources)),
            )
        self.db.commit()
        return ["schema ready", f"db: {self.cfg.db_path}"]

    def phase_candidate_discovery(self) -> list:
        already = int(self.db.scalar("SELECT COUNT(*) FROM candidates"))
        if already:
            return [f"candidates already present: {already} (resume)"]
        benign = generate_benign_candidates(self.catalog, self.cfg)
        mal = generate_malicious_candidates(self.families, self.cfg)
        for c in benign + mal:
            self.db.upsert_candidate(c)
        self.db.commit()
        return [
            f"benign candidates: {len(benign)}",
            f"malicious candidates: {len(mal)}",
            f"unique sha256: {len({c.sha256 for c in benign + mal})}",
        ]

    def phase_verification(self) -> list:
        tally = verify_pending_candidates(self.db, self.cfg, self.catalog, self.families)
        return [f"verification tally: {tally}"]

    def phase_review_adjudication(self) -> list:
        tally = adjudicate_pending(self.db, self.cfg, families=self.families, catalog=self.catalog)
        remaining = len(self.db.pending_reviews())
        return [f"adjudication: {tally}", f"reviews still required: {remaining}"]

    def phase_acquisition(self) -> list:
        tally = acquire_samples(self.db, self.cfg)
        return [f"acquisition: {tally}"]

    def phase_extraction(self) -> list:
        tally = run_extraction_for_all(self.db, self.cfg)
        return [tally and f"extraction: {tally}"]

    def phase_validation_summary(self) -> list:
        rows = self.db.fetchall(
            "SELECT apk_validation_status, COUNT(*) n FROM samples GROUP BY apk_validation_status"
        )
        return [f"apk validation: { {r['apk_validation_status']: r['n'] for r in rows} }"]

    def phase_dataset_build(self) -> list:
        res = build_dataset(self.db, self.cfg)
        out = [
            f"benign available/selected: {res['benign_available']}/{res['benign_selected']}",
            f"malicious available/selected: {res['malicious_available']}/{res['malicious_selected']}",
            f"gates_passed: {res['gates_passed']}",
            f"version: {res['version']}",
        ]
        for g in res["gates"]:
            out.append(f"  [{g['severity']}] {g['gate']}: {g['detail']}")
        if not res["gates_passed"]:
            raise SystemExit("dataset build failed gates; fix before exporting")
        return out

    def phase_export(self) -> list:
        version = self.cfg.version_latest(self.db)
        paths = export_release(self.db, self.cfg, version)
        return [f"released {version}: " + ", ".join(str(p.name) for p in paths.values())]

    def phase_report(self) -> list:
        reports_root = self.cfg.reports_root
        paths = reporting.render_reports(self.db, self.cfg, reports_root)
        return [f"reports written: {', '.join(str(p.name) for p in paths.values())}"]

    # ------------------------------------------------------------------- run
    def run(self, start_phase: str = "init") -> None:
        names = [n for n in PHASES if PHASE_ORDER[n] >= PHASE_ORDER[start_phase]]
        for name in names:
            method = getattr(self, f"phase_{name}")
            try:
                self.log(name, method())
            except SystemExit:
                raise
            except Exception as exc:  # noqa: BLE001
                print(f"\nphase {name} FAILED: {exc}")
                traceback.print_exc()
                raise SystemExit(f"Pipeline halted at phase {name}") from exc


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv.pop(0)
    if cmd == "run":
        start = "init"
        if argv and argv[0] == "--phase":
            argv.pop(0)
            if argv:
                start = argv.pop(0)
                if start not in PHASE_ORDER:
                    print(f"unknown phase {start!r}; known: {PHASES}")
                    return 2
        cfg = load_config()
        cfg.resolve_env_overrides()
        missing = cfg.missing_credentials()
        if missing:
            print("WARNING: missing credentials:", ", ".join(missing))
        pipe = Pipeline(cfg)
        try:
            pipe.run(start)
        finally:
            pipe.close()
        return 0
    print(f"unknown command {cmd!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
