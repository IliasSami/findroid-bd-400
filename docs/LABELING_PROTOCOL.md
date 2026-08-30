# LABELING_PROTOCOL.md

> Research-integrity note (Section 62 of the MASTER prompt): in the current
> build all candidate metadata is **simulated provenance**. These labels are
> engineering-validation artifacts, not empirical findings. Every label is
> tagged with its confidence band; nothing unverifiable is silently accepted.

## Confidence bands (`configs/labeling.yaml`)

| Band | Meaning |
|---|---|
| **A** | Strong external evidence: vendor report, documented family, verified IOC/hash. |
| **B** | Strong automated evidence: high detection, family tools agree, multiple indicators. |
| **C** | Ambiguous: low detection, family disagreement, weak evidence, incomplete metadata. |

Policies (both on): `c_requires_review: true`, `no_guess_instead_of_review: true`.

## Label triage (`src/findroid/verification/labels.py`)

### Malicious candidates

`verify_malware_evidence(rec, families)`:

1. Family must be present in the threat catalogue (else fail).
2. `targeting_basis` must be non-empty (financial relevance, else fail).
3. Evidence quality is classified by scanning `evidence` for vendor-documentation
   cues (`cyble`, `vendors`, `provenance`, `documented`).
4. `vt_detection` is compared against the family's expected detection window
   (`vdetect_window_for(fam.vt_band)`):
   - vendor-documented + BD-targeting family + detection in band → **A**
   - detection in band (no vendor doc) → **B**
   - detection outside band or weak evidence → **C**

Design intent: SikkahBot-style low-VT families stay at B when vendor-documented
so low detection alone never sinks well-evidenced families; high-detection but
weakly-evidenced candidates go to review instead.

### Benign candidates

`verify_benign_evidence(rec)`:

- `vt_detection` must be **0** (any positive detection "cannot be clean" → fail).
- `play_verification_date` must be present (Play-listing presence).
- Clean + Play-present evidence yields **B** (mock baseline; a real Play
  round-trip would be A).

`confidence_from_checks`: any `fail`/`unknown`/`warn` check → **C**; fully clean
→ **B**.

## Promotion rule (`verify.py::_promote_or_queue`, Section 60 contract)

A candidate is eligible for the release pool only when:

```
verification_status == VERIFIED  AND  leading_confidence in (A, B)
```

`leading_confidence(checks)` returns the strongest band found in the evidence
check `meta` (A > B > C), default **B** when no evidence check signals a band.
**C never promotes** — `c_requires_review` routes it to the review queue
(`REVIEW_REQUIRED`) instead.

## Review queue

- C-confidence and unresolved candidates land in `review_queue` with `reason`
  and `evidence` (see `src/findroid/models/__init__.py::ReviewRecord`).
- Review status defaults to `REVIEW_REQUIRED`; a human reviewer records
  `final_decision` / `review_notes`.
- **Current default:** reviewed-later benign samples are excluded from
  selection until a reviewer adjudicates them. This is a decision, not a bug —
  recorded in `docs/AGENT_UNDERSTANDING.md` as an open decision (opt-in to
  include).

## Fintech category

`fintech_categories` in `configs/labeling.yaml`: `banking`,
`mobile_financial_service`, `mobile_wallet`, `payment`, `merchant_payment`,
`digital_banking`, `microfinance`, `lending`, `insurance`, `investment`,
`fintech_utility`. Unknown/out-of-list categories are not silently re-labelled;
the candidate carries its evidence to review.

## Label evidence record

For every label, `label_evidence` rows (kind, value, source) and the label's
`evidence_refs` / `source_note` preserve what evidence actually backed the
decision — so a downstream user always knows *why* a label is what it is, and
can drop C or simulated rows if the analysis requires it.