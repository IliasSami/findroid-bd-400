# FEATURE_EXTRACTION.md

> Scope honesty: the current build runs a **simulated static extractor**
> (`src/findroid/extraction/extract.py`,
> `EXTRACTOR_VERSION = "0.2.0-mock"`). It reads the simulated artifact
> descriptor (`.mockapk.json`) in `samples/` and emits feature rows; it does
> not parse real APK bytes. Every feature row records `origin` and SIMULATED
> markers so simulated rows can be cleanly excluded from any downstream
> analysis.

## Feature groups (`src/findroid/features/schema.py`)

Declared order (matches the FinDroid schema contract):

```
static_manifest, static_code, static_cert, fintech, dynamic
```

**Implemented today:** `static_manifest` (permissions + sdk/cert/dex/apk
metrics) and `static_code` (string-indicator flags + counts). `static_cert`
and `dynamic` are declared groups with no dedicated extractor walk; the cert
features emitted today are filed under `static_manifest` (see
`AGENT_UNDERSTANDING.md`, "known inconsistencies"). Export output is ordered
by `select_features(names, FEATURE_GROUPS)` — group order, then feature name.

## Feature catalogue (mock extractor)

| Feature | dtype | Group | Origin |
|---|---|---|---|
| `perm.<permission>` | int (1) | static_manifest | simulated |
| `sdk.min` | int | static_manifest | simulated |
| `sdk.target` | int | static_manifest | simulated |
| `cert.cn` | str | static_manifest | simulated |
| `cert.digest` | str | static_manifest | simulated |
| `dex.classes` | int | static_manifest | simulated |
| `dex.methods` | int | static_manifest | simulated |
| `apk.size_bytes` | int | static_manifest | simulated |
| `dex.date` | str | static_manifest | simulated |
| `str_ind.otp` | int (0/1) | static_code | derived |
| `str_ind.sms` | int (0/1) | static_code | derived |
| `str_ind.ussd` | int (0/1) | static_code | derived |
| `str_ind.overlay` | int (0/1) | static_code | derived |
| `str_ind.accessibility` | int (0/1) | static_code | derived |
| `str_ind.bank_brand` | int (0/1) | static_code | derived |
| `str_ind.wallet` | int (0/1) | static_code | derived |
| `str_ind.payment` | int (0/1) | static_code | derived |
| `str_ind.credential` | int (0/1) | static_code | derived |
| `dex.string_count` | int | static_code | derived |
| `is_simulated` | int (0/1) | static_code | derived |

String-indicator needles are defined in `_STRING_FLAG_GROUPS`
(`extract.py`): otp, sms, ussd, overlay, accessibility, bank_brand
(bkash/nagad/rocket/bank/banking), wallet, payment, credential.

## Origin semantics

- `measured` — read directly from an artifact (not produced in mock).
- `derived` — computed aggregation over measured/simulated values
  (`str_ind.*`, counts).
- `simulated` — synthetic value from the mock descriptor.

## Per-feature provenance (`features` table)

Every row stores `source_tool` (`androgurd` in mock) and
`extractor_version`, so feature provenance is auditable row-by-row.

## Extraction status

`ExtractionStatus`: `SUCCESS` (≥1 feature), `PARTIAL` (0 features, no error),
`FAILED` (error — recorded in `errors`). Missing artifact descriptor →
`FAILED` with `NO_ARTIFACT`. Runs are logged to `extraction_runs` with
`feature_schema_version` and `feature_count`.

## Extension path to real extraction

When real acquisition is enabled, the artifact descriptor walk is replaced by
an Androguard pass over the actual APK (`androguard>=4.1.2` is a declared
dependency but is not exercised in mock mode). Feature names/schema stay
stable; only `origin` and `source_tool` change. The exporter column set is
derived from the `features` table, so real runs slot into the same contract
without schema changes.