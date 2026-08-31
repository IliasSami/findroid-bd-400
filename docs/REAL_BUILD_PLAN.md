# Real Build Plan — FinDroid-BD 400

Goal (MASTER prompt): a reproducible **300–400 sample** Android dataset of
**fintech mobile apps**, ~60% benign fintech (bKash, Nagad, BRAC Bank, Astha,
Rocket, UCB, TallyKhata, SureCash, Paytm, PhonePe, ...) and ~40% malicious
(banking/fintech trojans), each with static feature extraction. **No AndroZoo
key** is available, so acquisition uses alternative public sources below.

This document is the step-by-step execution plan, grounded in the reachability
survey run on 2026-08-31 from the build environment.

---

## 1. Acquisition channel survey (empirically verified)

| Source | Reachability from build env | Role |
|---|---|---|
| **MalwareBazaar API** (`mb-api.abuse.ch/api/v1/`) | 200 endpoint / **401 while unauthenticated** — all queries now key-gated | Malicious (free API key required) |
| **Google Play** (`play.google.com/store/apps/details?id=...`) | **200** | Benign verification evidence (listing, title, developer, category) |
| **F-Droid** (`f-droid.org/api/v1`, `/repo/*.apk`) | **200** | Real APK bytes; open-source benign fintech-adjacent apps; engineering fixture |
| APKPure | 403 (WAF) | BD benign — **fetch on a residential device** |
| APKCombo | 200 root, **410 product pages** | BD benign — **fetch on a residential device** |
| APKMirror | 403 | fallback — fetch on a residential device |
| Uptodown | 410 | not usable |
| Aptoide API v7 | 200, but **does not host BD catalog apps** | not usable for the catalog |
| androidapks.com / other mirrors | no bKash/nagad entries | not usable |

**Implication:** the pipeline is split-hair honest: two channels work from this
machine today (Play metadata for benign verification, F-Droid for real open APK
bytes, androguard for extraction), and two channels need one human action each
(MalwareBazaar free API key; BD fintech APKs downloaded on a residential
network where APKPure/APKCombo are not bot-walled). Nothing is faked: samples
that cannot be acquired yet simply stay `pending`.

## 2. Target composition (config `dataset:`)

- `total = 400`, `benign = 240` (60%), `malicious = 160` (40%).
- Benign population priority:
  1. BD fintech tier-1 (bKash, Nagad, Rocket, BRAC Bank Astha, Citytouch, EBL
     Skybanking, CellFin, upay, SureCash, TallyKhata, ...) — `fintech_seed_packages.csv`,
  2. regional fintech (Paytm, PhonePe, BHIM, Easypaisa, JazzCash, eSewa, GCash,
     MoMo, TrueMoney, DANA, ...),
  3. global fintech (PayPal, Wise, Revolut, Cash App, Venmo, Coinbase, ...),
  4. open-source fintech-adjacent apps served by F-Droid (documented as a
     supplement only if the BD/regional pools fall short).
- Malicious population priority: families authored to target fintech wallets /
  banks — SikkahBot (BD), Godfather, Anatsa/TeaBot, Cerberus/ERMAC, CopyBara,
  Hook, Octo/Coper, PixPirate, etc. (`metadata/threat_families.csv`), sampled at
  a cap of 160.

## 3. Stage-by-stage execution

### S0. Precursors (this session)
- [x] Reachability survey + channel verdict (table above).
- [x] androguard 4.1.4 installed and **proven** on a genuine APK (manifest,
  permissions, SDK, certificate subject/issuer/digest, DEX class/method/string
  counts) — no Java required.
- [x] Real F-Droid APK bytes downloaded + integrity-checked (zip + sha256).
- [ ] Real static extractor + sources + acquisition modules wired (below).

### S1. Benign: catalog + verification evidence (this session, automated)
1. Expand `metadata/fintech_seed_packages.csv` (Play-verified) to cover the
   240-slot benign pool with buffer (brands/entities above).
2. `findroid sources` hits **Google Play metadata** per package → record
   listing evidence (offered-by, category, installs, date) into the candidates
   as real `evidence` + `play_verification_date`. Play 200 → `VERIFIED` benign
   suspicion; missing/blocked → left unverified.
3. Emit `CandidateRecord`s (`source="play_mirror"|"f_droid"`, real sha256 once
   APK bytes exist; otherwise pending acquisition).

### S2. Benign: APK acquisition — two paths (hybrid)
- **Path B1 (this build env, automated):** F-Droid packages matching catalog
  entries (or documented fintech-adjacent supplements). Straight bytes:
  `GET https://f-droid.org/repo/{pkg}_{vercode}.apk`, sha256, zip-validate,
  stash in `samples/benign/<sha2>/`.
- **Path B2 (residential device, one manual step, tool provided):**
  `findroid fetch-benign --source apkpure|apkcombo|apkmirror` — a self-contained
  CLI that downloads the 240 BD fintech APKs on the user's own network (where
  these mirrors are not bot-walled), recomputes SHA-256 locally, and writes them
  into the same vault layout + a `real_acquire_manifest.json`. The build
  environment then ingests the vault without re-downloading.

### S3. Malicious: MalwareBazaar (needs free API key from the user)
1. Fetch per-family, per-tag sample lists for fintech targets
   (`query=search_tag&tag=android`, per-family signatures where available).
2. Pull metadata (`query=query_hash`) → signature/family + **VirusTotal
   engine counts** (MB reports them per sample) → real evidence + `vt_detection`.
3. `query=download` → APK bytes → sha256 → vault `samples/malicious/<sha2>/`.
4. Dedup on sha256; cap at 160; keep the 65-slot pipeline honest.

### S4. Verification + dedup + labeling (unchanged machinery, real evidence)
- Same stages as mock mode, but `evidence`/`source_reference` now carry real
  URLs (Play listing, MalwareBazaar signature page, F-Droid package page) and
  `verification_status` is decided on Play listing + signed-cert identity
  (benign) vs MB family evidence + VT counts (malicious).

### S5. Static feature extraction (this session, automated, androguard)
`src/findroid/extraction/static_real.py` — pure-Python, no Java:
- `static_manifest`: `perm.*` (declared permissions), `sdk.min`, `sdk.target`,
  `apk.size_bytes`, `dex.date` (embedded class timestamps).
- `static_cert`: `cert.cn`, `cert.org`, `cert.issuer_cn`, `cert.digest`
  (SHA-256 of DER) from the v1/v2/v3 signing block.
- `static_code`: `dex.classes`, `dex.methods`, `dex.string_count`, and the
  `str_ind.{otp,sms,ussd,overlay,accessibility,bank_brand,wallet,payment,
  credential}` flags over the DEX string pool.
- `is_simulated=0`, `source_tool="androguard:4.1.4"`, extractor version `1.0.0-real`.
Schema is byte-for-byte the mock schema so every downstream stage is unchanged.

### S6. Selection, gates, export, release
- Balance 240/160, gates 1–8, export CSV+parquet+manifest — identical to mock
  releases but populated from real features; release version `2.0.0+real`.

## 4. Labeling policy (unchanged, evidence-driven)
- Benign label requires positive Play listing evidence AND the signing
  certificate scope matching the catalogued organisation; `benign_vt_max=0`.
- Malicious label requires MB signature/family + `vt_detection>=4`
  (`malicious_vt_min`); below-threshold families (e.g., SikkahBot LOW VT) rely
  on family/behavioural evidence as documented.

## 5. What needs the user (exactly two things)
1. **MalwareBazaar API key** (free, ~30 s at https://bazaar.abuse.ch/account/):
   `export MALWAREBAZAAR_API_KEY=<key>` → the 160 malicious APKs download
   automatically. Optional if samples land in the vault manually.
2. **BD fintech APKs on a residential network**: run the provided
   `findroid fetch-benign` tool on any laptop to grab bKash/Nagad/BRAC/Astha &
   friends from APKPure/APKCombo into the vault (a few minutes), OR drop a
   handful of APKs into `samples/import/`.

Everything else — verification evidence, dedup, extraction, labeling, gates,
export — runs automatically in the build environment on the real bytes.