"""End-to-end pipeline runner.

Mirrors the MASTER prompt's PHASE 0-16 execution order as discrete, resumable
phases over the FinDroid-BD-400 SQLite database. Every phase is idempotent
within a stage (states in the DB) so a failure can be fixed and resumed.

Run from the repository root:
    uv run findroid --help
    uv run findroid run            # full pipeline (fresh or resumable)
    uv run findroid run --phase 7  # resume from phase 7
    uv run findroid baseline       # classifier baseline on the latest release
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
from findroid.sources.registry import build_source_registry
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
        for key, source in build_source_registry(self.cfg).items():
            self.db.execute(
                "INSERT OR REPLACE INTO sources (source_key, kind, display_name, configured) VALUES (?,?,?,?)",
                (key, source.kind, key, 1),
            )
        self.db.commit()
        return ["schema ready", f"db: {self.cfg.db_path}"]

    def phase_candidate_discovery(self) -> list:
        already = int(self.db.scalar("SELECT COUNT(*) FROM candidates"))
        if already:
            return [f"candidates already present: {already} (resume)"]
        if self.cfg.development.mock_sources:
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
        registry = build_source_registry(self.cfg)
        discovered = []
        for key, source in registry.items():
            try:
                recs = list(source.discover())
            except Exception as exc:  # noqa: BLE001
                print(f"  source {key} discovery failed: {exc}")
                continue
            inserted = 0
            for rec in recs:
                try:
                    self.db.upsert_candidate(rec)
                    inserted += 1
                except Exception as exc:  # noqa: BLE001
                    print(f"  drop duplicate/conflict {rec.sha256[:16]} ({exc})")
            discovered.append((key, inserted))
            print(f"  source {key}: {inserted} released")
        self.db.commit()
        sha_b = len(self.db.fetchall("SELECT DISTINCT sha256 FROM candidates WHERE suspected_class='benign'"))
        sha_m = len(self.db.fetchall("SELECT DISTINCT sha256 FROM candidates WHERE suspected_class='malicious'"))
        return [
            "real discovery",
            ", ".join(f"{k}: {n}" for k, n in discovered),
            f"distinct benign sha: {sha_b}",
            f"distinct malicious sha: {sha_m}",
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
    if cmd == "baseline":
        from findroid.experiments.baseline import main as baseline_main

        return baseline_main(argv)
    if cmd == "fetch-benign":
        return cmd_fetch_benign(argv)
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


def cmd_fetch_benign(argv: list[str]) -> int:
    """Print the residential-fetch manifest for the confirmed benign catalogue.

    APKPure/APKCombo/APK-Mirror are bot-walled from this machine, so the user
    downloads the listed APKs on a residential network and drops them (any
    filename) into ``samples/import/`` — or uses the theZoo/APKPure mobile app.
    The next real run in ``samples/import/`` picks up whatever is present;
    missing packages simply produce skipped acquisition rows.
    """
    cfg = load_config()
    catalog = load_benign_seed_catalog(
        _cfg.PROJECT_ROOT / "metadata" / "fintech_seed_packages.csv"
    )
    eligible = sorted(
        (p for p in catalog.values() if not p.is_synthetic and not p.is_collision),
        key=lambda p: (p.country, p.package_id),
    )
    import_root = cfg.import_root
    print(f"# benign APK fetch manifest ({len(eligible)} packages)")
    print(f"# drop each APK into: {import_root}  (name does not matter)")
    print("# package,app_name,subsector,country,play_url")
    for p in eligible:
        url = f"https://play.google.com/store/apps/details?id={p.package_id}"
        print(f"{p.package_id},{p.app_name},{p.subsector},{p.country},{url}")
    print("# after downloading: rerun with the real-mode env (see docs/REAL_BUILD_PLAN.md)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
