"""Tests for the typed config schema layer."""

import pytest
import yaml

import config_schema
from config_schema import (
    BuildConfig,
    ConfigError,
    FilterEntry,
    FilterPolicy,
    OverrideEntry,
)
from datetime import date

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


# --- meta_date range selector ----------------------------------------------

def _meta_date_entry(meta_date):
    return FilterEntry.from_dict(
        {"action": "exclude", "match": {"meta_date": meta_date}}, SRC, 0)


def test_filter_match_meta_date_parses_bounds():
    entry = _meta_date_entry({
        "field": "date",
        "on_or_after": "2026-05-01",
        "before": "2026-07-01",
    })
    md = entry.match.meta_date
    assert md.field == "date"
    assert md.on_or_after == date(2026, 5, 1)
    assert md.before == date(2026, 7, 1)
    assert md.after is None and md.on_or_before is None


def test_filter_match_meta_date_single_bound():
    md = _meta_date_entry({"field": "date", "after": "2026-01-01"}).match.meta_date
    assert md.after == date(2026, 1, 1)


def test_filter_match_meta_date_requires_a_bound():
    with pytest.raises(ConfigError, match="at least one"):
        _meta_date_entry({"field": "date"})


def test_filter_match_meta_date_requires_field():
    with pytest.raises(ConfigError, match="missing required field 'field'"):
        _meta_date_entry({"before": "2026-05-01"})


def test_filter_match_meta_date_unknown_key():
    with pytest.raises(ConfigError, match="unknown field"):
        _meta_date_entry({"field": "date", "betwen": "2026-05-01"})


@pytest.mark.parametrize("bad", ["2026-13-40", "nope", "2026/05/01", "20260501"])
def test_filter_match_meta_date_malformed_bound(bad):
    with pytest.raises(ConfigError, match="must be a YYYY-MM-DD date"):
        _meta_date_entry({"field": "date", "before": bad})


# --- empty/absent filter policy is valid ----------------------------------

def test_filter_policy_none_is_include_all():
    policy = FilterPolicy.from_dict(None, SRC)
    assert policy.default_mode == "include_all"
    assert policy.filters == []


# --- decisions loaders -----------------------------------------------------

def _write(path, key, entries):
    path.write_text(yaml.safe_dump({key: entries}))


def test_load_decisions_absent_file_returns_empty(tmp_path):
    path = tmp_path / "missing.yaml"
    assert config_schema.load_decisions(path, "stale_override_decisions", "missing_vendor_rule") == []
    assert config_schema.load_decisions_map(path, "stale_override_decisions", "missing_vendor_rule") == {}


def test_load_decisions_map_keys_on_override_and_secondary(tmp_path):
    path = tmp_path / "d.yaml"
    _write(path, "stale_override_decisions", [
        {"override_rule": "ov", "missing_vendor_rule": "gone", "decision": "keep"},
        {"override_rule": "ov2", "decision": "discard"},  # wildcard: no secondary
    ])
    m = config_schema.load_decisions_map(path, "stale_override_decisions", "missing_vendor_rule")
    assert m[("ov", "gone")] == "keep"
    assert m[("ov2", None)] == "discard"


def test_lookup_decision_specific_beats_wildcard(tmp_path):
    decisions = {("ov", "gone"): "keep", ("ov", None): "discard"}
    # exact (ov, gone) wins over the wildcard (ov, None)
    assert config_schema.lookup_decision(decisions, "ov", "gone") == "keep"


def test_lookup_decision_falls_back_to_wildcard(tmp_path):
    decisions = {("ov", None): "keep"}
    assert config_schema.lookup_decision(decisions, "ov", "any_missing") == "keep"


def test_lookup_decision_returns_none_when_unrecorded():
    assert config_schema.lookup_decision({}, "ov", "gone") is None


def test_load_decisions_normalizes_decision_case(tmp_path):
    path = tmp_path / "d.yaml"
    _write(path, "stale_override_decisions", [
        {"override_rule": "ov", "missing_vendor_rule": "gone", "decision": "KEEP"},
    ])
    entries = config_schema.load_decisions(path, "stale_override_decisions", "missing_vendor_rule")
    assert entries[0].decision == "keep"


def test_load_decisions_bad_decision_value_errors(tmp_path):
    path = tmp_path / "d.yaml"
    _write(path, "stale_override_decisions", [
        {"override_rule": "ov", "missing_vendor_rule": "gone", "decision": "maybe"},
    ])
    with pytest.raises(ConfigError, match="decision"):
        config_schema.load_decisions(path, "stale_override_decisions", "missing_vendor_rule")
