# SECURITY.md

## Threat model / non-goals

This repo processes **malware descriptors**, not live samples, in its default
mode. The hard rules are:

- **APKs are never executed.** `security.execute_apks: false` is a schema
  default; there is no dynamic detonation path in the pipeline (`analysis.dynamic
  false`, `docs/FEATURE_EXTRACTION.md`).
- **Real APKs are not written or run by default.**
  `development.allow_real_apks: false`; acquisition in this build creates
  simulated `.mockapk.json` descriptors only.
- **No redistribution of binaries.** Releases contain hashes + feature vectors,
  never APK files. This also satisfies AndroZoo's research-only terms.
- **Educational/research only.** The dataset exists to build and evaluate
  defensive models.

## Operational controls when real acquisition is enabled

Switching to real sources is deliberately not a one-line edit:

1. Set `development.mock_sources: false` and `mock_acquisition: false`
   (or the equivalent env overrides `FINDROID_MOCK_SOURCES=0` /
   `FINDROID_MOCK_ACQUISITION=0`).
2. Provide `ANDROZOO_API_KEY` and/or `MALWAREBAZAAR_API_KEY`. `load_config()`
   → `missing_credentials()` prints a warning when keys are absent and real
   sources are requested.
3. Set `development.allow_real_apks: true` to permit real bytes into the vault.

Recommended hygiene for a real run:

- Download into an isolated sandbox/vault path (see `FINDROID_APK_VAULT` env
  override; never the repo tree).
- Keep the database and release artifacts on the same isolated volume.
- Do not run acquired APKs on a device with a real SIM / real financial
  credentials.
- Static analysis only, on a Java-capable host; no emulator detonation.
- If a new family targeting a Bangladeshi institution is identified, follow
  responsible disclosure (notify institution/CERT) — see the parent project's
  WRITING_INTEGRITY guidance.

## Secrets handling

- API keys are read from environment variables only (`ANDROZOO_API_KEY`,
  `MALWAREBAZAAR_API_KEY`); they are never stored in YAML, the database, or
  releases.
- `.gitignore` excludes `database/`, `data/releases/`, `reports/` so generated
  artifacts with hashes of real samples are not committed by accident.

## Supply-chain

- Dependencies are pinned as ranges in `pyproject.toml` and resolved by the
  lockfile (`uv.lock`); `pip-audit` / `pip check` can be run before a real
  acquisition phase as an extra gate.
- The only network-capable dependency used today is `requests`, and no network
  call is made while mock mode is on.