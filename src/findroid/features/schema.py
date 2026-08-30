"""Feature schema + selection.

The feature schema is the declarative contract between the extractor and the
dataset export. Selection reduces the candidate feature set to a stable,
low-redundancy subset used for any downstream modeling (described in the
DATASHEET, not computed here).
"""

from __future__ import annotations

# Ordered feature groups, matching the FinDroid schema contract.
FEATURE_GROUPS = [
    "static_manifest",
    "static_code",
    "static_cert",
    "fintech",
    "dynamic",
]

# Core identity fields every final row must carry (row provenance contract).
ROW_CONTRACT = [
    "sample_id",
    "sha256",
    "source",
    "class_label",
    "label_confidence",
    "family",
    "package_name",
    "app_name",
    "version_code",
    "version_name",
    "fintech_category",
    "country",
    "vt_detection",
]


def feature_count_by_group(features: dict[str, int]) -> int:
    return int(sum(features.values()))


def schema_feature_names(features_db_rows) -> list[str]:
    """Collapse raw feature rows into the export schema column names."""
    names: list[str] = []
    for row in features_db_rows:
        name = row["feature_name"]
        if name not in names:
            names.append(name)
    return names


def select_features(names: list[str], group_order: list[str]) -> list[str]:
    """Stable ordering of feature names by group, then name."""
    by_group: dict[str, list[str]] = {g: [] for g in group_order}
    for n in names:
        prefix = n.split(".", 1)[0]
        key = prefix if prefix in by_group else "static_code"
        by_group[key].append(n)
    out: list[str] = []
    for g in group_order:
        out.extend(sorted(by_group[g]))
    return out
