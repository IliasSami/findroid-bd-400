# FinDroid-BD: Android FinTech & Financial Malware Research Dataset

> **A reproducible, real-data research dataset of 311 validated Android fintech apps and
> banking-trojan malware samples** — built for cybersecurity education, malware-analysis
> research, Android security ML pipelines, and threat-intelligence teaching. Educational
> and academic-research use only.

**Dataset version:** `v1.0.0` · **311 real samples** (147 benign fintech + 164 real banking-trojan malware) · **all 8 quality gates PASS**

---

## 📌 What this repository is

FinDroid-BD (`Fin`tech `Droid` `B`angla`d`esh / fintech-android) is an **open-source, reproducible
data-science pipeline** that assembles a labelled, hash-verified Android dataset for **fintech
cybersecurity research**. It combines:

- **147 real benign fintech Android apps** (official F-Droid builds: crypto wallets, mobile-money
  wallets, bank/PSP wallets, personal-finance and expense trackers, currency converters, stock
  trackers, invoicing tools) — hash-verified and feature-extracted.
- **164 real Android banking-trojan APKs** (sourced from the public **MalwareBazaar** research
  repository) spanning 10 known malware families.

Every sample carries an **authentic SHA-256**, a validated APK, a **fintech label**, malware **family**,
66 static-extracted feature columns, and full **provenance**. The dataset is exported as CSV and
Parquet (`data/releases/v1.0.0/`) and as a fully queryable SQLite provenance database
(`database/findroid.db`, 13 tables).

---

## 🎯 Who it is for

Students, educators, security researchers, and machine-learning engineers who need a **clean,
attributable, gate-checked** Android fintech–malware dataset for:

- Malware family classification (Anatsa/TeaBot, Cerberus/Alien/ERMAC, Coper/CopyBara/Octo,
  Crocodilus, ExobotV2, Godfather, Hook, ToxicPanda/TgToxic, Vultur)
- Android mobile-money / fintech app identification
- Static feature engineering for Android security ML
- Threat-intelligence education and reproducible-research training

---

## ✨ Highlights

- **Real data, not synthetic.** Both benign (F-Droid official builds) and malicious
  (MalwareBazaar) artefacts are genuine APK binaries with computed SHA-256 hashes.
- **Reproducible.** Pinned config (`config_hash` in the release manifest), deterministic static
  features, resumable pipeline (`uv run findroid run --phase <phase>`).
- **Gated release.** 8 automated quality gates (row count, class balance, APK validity, fintech
  classification, malware evidence, benign evidence, unique SHA-256, package dedup) must all pass
  before a version is released.
- **Full provenance.** Every sample traces to a public source with evidence strings.
- **Open & documented.** 15+ docs, license-friendly config, Python + SQLite + CSV/Parquet.

---

## 🚀 Quick start

```bash
git clone https://github.com/IliasSami/findroid-bd-400.git
cd findroid-bd-400
uv sync --extra dev                 # install project + dev tooling
uv run findroid --help              # CLI usage
uv run findroid run --phase dataset_build   # build/verify the dataset
uv run findroid baseline            # run classifiers on the released dataset
uv run pytest -q                    # run the test suite
```

The ready-to-use dataset is already released in `data/releases/v1.0.0/`:
`findroid_bd_v1.0.0_dataset.csv`, `..._label.csv`, Parquet equivalents, and a content-hashed
`..._manifest.json`.

| File | Contents |
|------|----------|
| `findroid_bd_v1.0.0_dataset.csv` | 311 rows × (row contract + 66 static features) |
| `findroid_bd_v1.0.0_label.csv` | sample → `class_label`, `label_confidence`, family |
| `findroid_bd_v1.0.0_dataset.parquet` / `label.parquet` | same, Parquet-encoded |
| `findroid_bd_v1.0.0_manifest.json` | provenance, config hash, all 8 gate results |

---

## 🧠 Dataset facts (entities)

### Class balance — `v1.0.0`

| Class | Count | Source | Verification |
|-------|-------|--------|--------------|
| **Benign fintech** | 147 | F-Droid official builds | zero VirusTotal detections; official-channel evidence |
| **Malicious banking trojans** | 164 | MalwareBazaar research repo | family-specific A/B confidence; VT band checks |
| **Total** | **311** | — | all 8 gates PASS |

### Threat & entity coverage

Known **Android banking-trojan families** represented: **Cerberus**, **Alien**, **ERMAC**, **Hook**,
**Coper**, **CopyBara**, **Octo**, **Anatsa** (TeaBot), **Crocodilus**, **ExobotV2**, **Godfather**,
**Vultur**, **ToxicPanda** (TgToxic). Benign side covers **crypto wallets**, **mobile-money/PSP
wallets**, **bank-retail fintech**, and **fintech-utility** (budgeting, expense, currency, invoicing,
stock, lending) apps.

### Provenance & reproducibility

- Benign seeds: `metadata/fintech_seed_packages.csv` (F-Droid catalogue + curated near-fintech).
- Threat families: `metadata/threat_families.csv` (public research metadata).
- Malicious acquisition: `MalwareBazaar` API → verified SHA-256 → static extraction.
- Config pinned: `configs/project.yaml` → recorded as `config_hash` in each release manifest.

---

## 🏗️ Pipeline (10 resumable phases)

`init` → `candidate_discovery` → `verification` → `review_adjudication` → `acquisition` →
`extraction` → `validation_summary` → `dataset_build` → `export` → `report`

- **Candidate discovery** — real sources: MalwareBazaar (malicious), F-Droid / import-scan (benign).
- **Verification & adjudication** — fintech-class and malware-evidence checks; anything ambiguous
  goes to the review queue (never silently downstream).
- **Acquisition** — hash-verified artifact acquisition into the vault.
- **Extraction** — deterministic static feature extraction (66 features across permission, intent,
  API, certificate, and manifest groups).
- **Dataset build** — 8 gates; refuses to release on any FAIL.

---

## 📚 Documentation

| Doc | Purpose |
|-----|---------|
| `docs/ARCHITECTURE.md` | module map, phase contract, determinism |
| `docs/DATA_DICTIONARY.md` | schema + row contract + 66 feature catalogue |
| `docs/LABELING_PROTOCOL.md` | A/B/C label confidence and the promotion rule |
| `docs/FEATURE_EXTRACTION.md` | static feature groups and origins |
| `docs/PROVENANCE.md` / `docs/REPRODUCIBILITY.md` | where rows come from; how to re-derive |
| `docs/SECURITY.md` / `docs/DATASET_RELEASE.md` | controls, responsible-use, release policy |
| `docs/REAL_BUILD_PLAN.md` | full plan + results of the real-data build |
| `docs/QUICKSTART.md`, `docs/INSTALLATION.md`, `docs/TROUBLESHOOTING.md`, `docs/BASELINE.md` | guides |

---

## ⚙️ Design & research-integrity invariants

- **No guess as evidence** — unverifiable items go to the review queue.
- **Simulated is labelled** — any synthetic artifact carries explicit `SIMULATED`/`mock.*` markers.
- **Gates before release** — G1 row-count, G2 balance, G3 APK validity, G4 fintech classification,
  G5 malware evidence, G6 benign evidence, G7 unique SHA-256, G8 package dedup.
- **Configuration pinned** — every release records its exact config hash.
- No fabricated samples, labels, or citations; full provenance required for every final sample.

---

## 🔒 Responsible use & security

- **Educational / academic research only.** The malicious samples are real banking trojans sourced
  from the public **MalwareBazaar** research repository and are included for **defensive**
  analysis and education.
- Handle payloads in an **isolated, offline analysis sandbox**. Do not install or execute samples on
  any production or personal device.
- APK binaries are **not** stored in this git repository; the dataset ships as metadata/hashes/features
  via CSV/Parquet/SQLite, with acquisition scripts that re-fetch payloads from public research
  repositories by SHA-256 hash.
- See `docs/SECURITY.md` for the full responsible-use and release policy.

---

## 📊 Technologies

Python · SQLite · Pandas/Parquet · F-Droid index (index-v2 JSON) · MalwareBazaar REST API ·
static APK/Android manifest parsing · uv packaging · pytest · ruff · mypy

## 🗂 Related topics / keywords

`android malware dataset` · `android banking trojan` · `fintech malware` · `mobile financial malware`
· `Anatsa` · `Cerberus` · `ERMAC` · `TeaBot` · `Hook` · `Coper` · `Octo` · `Godfather` · `Vultur` ·
`Crocodilus` · `ToxicPanda` · `mobile money security` · `Android static analysis` ·
`machine learning android security` · `mobile threat intelligence` · `Bangladesh fintech security`
· `malware family classification` · `Android APK security` · `mobile malware research`
· `Mitre`-adjacent mobile threat research · `reproducible dataset` · `cybersecurity education`

---

## 📜 License & attribution

See project files for licensing. Dataset provenance and attribution are documented per sample and in
`docs/PROVENANCE.md`. Malware samples retain their original public-research provenance (MalwareBazaar);
benign apps retain their F-Droid/official-source attribution.

*For research, teaching, and defensive security purposes only.*


---

## 👤 Author & Research Lead

Engineered and maintained by **[Ilias Sami](https://iliassami.com)** (legal name Ilias Ahmed) — Strategic AEO & GEO Architect and Cybersecurity Researcher.
- **Official Hub:** [https://iliassami.com](https://iliassami.com)
- **Background & Credentials:** [https://iliassami.com/about](https://iliassami.com/about)
- **Related Open-Source Projects:** [Scrawly Desktop SEO Crawler](https://github.com/IliasSami/scrawly-seo-crawler) and [Backlink Building Skill](https://github.com/IliasSami/backlink-building-skill)
