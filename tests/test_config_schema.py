"""Tests for the typed config schema layer."""

import pytest

import config_schema
from config_schema import (
    BuildConfig,
    ConfigError,
    FilterEntry,
    FilterPolicy,
    OverrideEntry,
)

SRC = "test-source"


# --- Real files load and parse to expected values -------------------------

def test_build_config_real_file(root):
    cfg = config_schema.load_build_config(root)
    assert cfg.filter_conflict_policy == "exclude_wins"
    assert cfg.required_meta == ["author", "date", "description", "reference", "severity"]
    assert cfg.stale_override_decisions == "overrides/stale_override_decisions.yaml"
    assert cfg.coverage_gap_decisions == "filters/coverage_gap_decisions.yaml"
    # external_variables values are all strings
    assert all(isinstance(v, str) for v in cfg.external_variables.values())


def test_override_manifest_real_file(root):
    entries = config_schema.load_override_manifest(root)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.override_rule == "vendor_override_overridden"
    assert entry.supersedes == ["vendor_override"]


def test_filter_policy_real_file(root):
    policy = config_schema.load_filter_policy(root)
    assert policy.default_mode == "include_all"
    assert policy.on_empty_output == "fail"
    assert policy.min_output_rules == 1
    assert policy.filters == []


# --- BuildConfig error paths ----------------------------------------------

def _valid_build_dict():
    return {
        "output_formats": ["source"],
        "yara_modules": ["pe"],
        "external_variables": {"filename": ""},
        "stale_override_decisions": "a.yaml",
        "coverage_gap_decisions": "b.yaml",
        "filter_conflict_policy": "exclude_wins",
        "required_meta": ["author"],
    }


def test_build_config_missing_required_key():
    data = _valid_build_dict()
    del data["required_meta"]
    with pytest.raises(ConfigError, match="missing required field 'required_meta'"):
        BuildConfig.from_dict(data, SRC)


def test_build_config_wrong_type():
    data = _valid_build_dict()
    data["output_formats"] = "source"  # should be a list
    with pytest.raises(ConfigError, match="must be a list"):
        BuildConfig.from_dict(data, SRC)


def test_build_config_bad_enum():
    data = _valid_build_dict()
    data["filter_conflict_policy"] = "coin_flip"
    with pytest.raises(ConfigError, match="filter_conflict_policy"):
        BuildConfig.from_dict(data, SRC)


def test_build_config_unknown_key():
    data = _valid_build_dict()
    data["surprise"] = 1
    with pytest.raises(ConfigError, match="unknown field"):
        BuildConfig.from_dict(data, SRC)


def test_build_config_external_var_non_string():
    data = _valid_build_dict()
    data["external_variables"] = {"filename": 5}
    with pytest.raises(ConfigError, match="must be a string"):
        BuildConfig.from_dict(data, SRC)


# --- bool-is-not-int guard ------------------------------------------------

def test_bool_rejected_where_int_expected():
    # min_output_rules is an int; True must not sneak through as 1.
    with pytest.raises(ConfigError, match="min_output_rules"):
        FilterPolicy.from_dict({"min_output_rules": True}, SRC)


# --- FilterEntry / scope validation ---------------------------------------

def test_filter_entry_bad_action():
    with pytest.raises(ConfigError, match="action"):
        FilterEntry.from_dict({"action": "nuke"}, SRC, 0)


def test_filter_scope_rule_prefix_without_identifier():
    with pytest.raises(ConfigError, match="no identifier"):
        FilterEntry.from_dict({"action": "exclude", "scope": "rule:"}, SRC, 0)


def test_filter_scope_unknown():
    with pytest.raises(ConfigError, match="scope"):
        FilterEntry.from_dict({"action": "exclude", "scope": "banana"}, SRC, 0)


def test_filter_entry_valid_rule_scope():
    entry = FilterEntry.from_dict(
        {"action": "exclude", "scope": "rule:Foo"}, SRC, 0)
    assert entry.scope == "rule:Foo"
    assert entry.action == "exclude"


# --- OverrideEntry error paths --------------------------------------------

def test_override_entry_empty_supersedes():
    with pytest.raises(ConfigError, match="empty 'supersedes'"):
        OverrideEntry.from_dict(
            {"override_rule": "X", "supersedes": []}, SRC, 0)


def test_override_entry_unknown_key():
    with pytest.raises(ConfigError, match="unknown field"):
        OverrideEntry.from_dict(
            {"override_rule": "X", "supersedes": ["v"], "junk": 1}, SRC, 0)


# --- meta_in normalization -------------------------------------------------

def test_filter_match_meta_in_normalized_to_frozenset():
    entry = FilterEntry.from_dict(
        {"action": "exclude", "match": {"meta_in": {"severity": ["high", 5]}}},
        SRC, 0,
    )
    assert entry.match.meta_in["severity"] == frozenset({"high", "5"})


# --- empty/absent filter policy is valid ----------------------------------

def test_filter_policy_none_is_include_all():
    policy = FilterPolicy.from_dict(None, SRC)
    assert policy.default_mode == "include_all"
    assert policy.filters == []
