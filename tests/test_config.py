"""Configuration contract tests."""

from __future__ import annotations

from findroid.config import AppConfig


def test_load_config_reads_all_files(cfg):
    assert cfg.dataset.total == 400
    assert cfg.dataset.benign == 240
    assert cfg.dataset.malicious == 160
    assert cfg.labels.malicious_vt_min == 4
    assert cfg.labels.benign_vt_max == 0
    assert cfg.development.mock_sources is True
    assert "feature_selection" in cfg.features and "fintech_keywords" in cfg.features
    assert cfg.selection["selection"]["method"] == "quota_diversity"
    assert cfg.selection["diversity"]["max_versions_per_package"] == 12


def test_config_hash_is_stable_and_sensitive(cfg):
    h1 = cfg.config_hash()
    h2 = cfg.config_hash()
    assert h1 == h2
    tweaked = cfg.model_copy(deep=True)
    tweaked.labels.malicious_vt_min = 3
    assert tweaked.config_hash() != h1


def test_labeling_policy_no_guess(cfg):
    assert cfg.labeling["policy"]["c_requires_review"] is True
    assert cfg.labeling["policy"]["no_guess_instead_of_review"] is True
    assert cfg.labeling.get("benign_vt_max") == 0
    assert cfg.labeling.get("malicious_vt_min") == 4
    assert cfg.labeling.get("ambiguous_range") == [1, 3]


def test_appconfig_compiles_without_yaml(cfg):
    app = AppConfig()
    assert app.dataset.total == 400
    assert app.labels.malicious_vt_min == 4


def test_env_overrides_switch_mode(cfg, monkeypatch):
    monkeypatch.setenv("FINDROID_MOCK_SOURCES", "0")
    cfg.resolve_env_overrides()
    assert cfg.development.mock_sources is False
    assert "MALWAREBAZAAR_API_KEY" in cfg.missing_credentials()
