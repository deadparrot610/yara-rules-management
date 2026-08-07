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


# --- meta_dates config ----------------------------------------------------

def test_meta_dates_absent_defaults_to_disabled():
    cfg = BuildConfig.from_dict(_valid_build_dict(), SRC)
    assert cfg.meta_dates.fields == []
    assert cfg.meta_dates.input_formats == ()
    # 'fail' is the default so an older build.yaml keeps blocking as before.
    assert cfg.meta_dates.on_unparsable == "fail"


def test_meta_dates_parses_and_preserves_order():
    data = _valid_build_dict()
    data["meta_dates"] = {
        "fields": ["date", "first_seen"],
        "input_formats": ["%m/%d/%Y", "%Y%m%d"],
        "on_unparsable": "warn_and_drop",
    }
    cfg = BuildConfig.from_dict(data, SRC)
    assert cfg.meta_dates.fields == ["date", "first_seen"]
    # A tuple, and in the order given — order is the ambiguity tie-break.
    assert cfg.meta_dates.input_formats == ("%m/%d/%Y", "%Y%m%d")
    assert cfg.meta_dates.on_unparsable == "warn_and_drop"


def test_meta_dates_rejects_invalid_on_unparsable():
    data = _valid_build_dict()
    data["meta_dates"] = {"fields": ["date"], "on_unparsable": "ignore"}
    with pytest.raises(ConfigError, match="on_unparsable"):
        BuildConfig.from_dict(data, SRC)


def test_meta_dates_rejects_retired_fuzzy_fallback():
    # The dateutil fallback is gone; a config still carrying the key must fail
    # loudly rather than silently losing its intent.
    data = _valid_build_dict()
    data["meta_dates"] = {"fields": ["date"], "fuzzy_fallback": True}
    with pytest.raises(ConfigError, match="unknown field"):
        BuildConfig.from_dict(data, SRC)


def test_meta_dates_unknown_key():
    data = _valid_build_dict()
    data["meta_dates"] = {"fields": ["date"], "surprise": 1}
    with pytest.raises(ConfigError, match="unknown field"):
        BuildConfig.from_dict(data, SRC)


def test_meta_dates_rejects_iso_in_input_formats():
    data = _valid_build_dict()
    data["meta_dates"] = {"input_formats": ["%Y-%m-%d"]}
    with pytest.raises(ConfigError, match="always accepted first"):
        BuildConfig.from_dict(data, SRC)


def test_meta_dates_rejects_duplicate_format():
    data = _valid_build_dict()
    data["meta_dates"] = {"input_formats": ["%Y%m%d", "%Y%m%d"]}
    with pytest.raises(ConfigError, match="duplicate entry"):
        BuildConfig.from_dict(data, SRC)


def test_meta_dates_rejects_duplicate_field():
    data = _valid_build_dict()
    data["meta_dates"] = {"fields": ["date", "date"]}
    with pytest.raises(ConfigError, match="duplicate entry"):
        BuildConfig.from_dict(data, SRC)


@pytest.mark.parametrize("bad", ["%q", "%Y", "%Y-%m", "not-a-format"])
def test_meta_dates_rejects_format_that_loses_the_date(bad):
    # Anything that doesn't round-trip year+month+day would silently normalize
    # distinct dates onto the same value.
    data = _valid_build_dict()
    data["meta_dates"] = {"input_formats": [bad]}
    with pytest.raises(ConfigError, match="round-trip|usable strptime"):
        BuildConfig.from_dict(data, SRC)


@pytest.mark.parametrize(
    "bad", ["%d-%b-%Y", "%B %d, %Y", "%a %Y-%m-%d", "%Y-%m-%d %Z"])
def test_meta_dates_rejects_locale_dependent_format(bad):
    # strptime month/day/timezone NAMES follow LC_TIME and the platform's tz
    # database, which would make lint results machine-dependent. There is no
    # looser parser to fall back to, so such a value is simply unparsable and
    # on_unparsable decides its fate.
    data = _valid_build_dict()
    data["meta_dates"] = {"input_formats": [bad]}
    with pytest.raises(ConfigError, match="locale-dependent"):
        BuildConfig.from_dict(data, SRC)


@pytest.mark.parametrize("fmt", [
    "%m/%d/%Y %H:%M",
    "%Y%m%d%H%M%S",
    "%Y-%m-%dT%H:%M:%S%z",     # numeric offset: unambiguous, unlike %Z
    "%Y-%m-%dT%H:%M:%S.%f",
])
def test_meta_dates_accepts_time_bearing_format(fmt):
    # The validate_date_format probe is an *aware datetime* precisely so these
    # round-trip; a naive date renders %z as '' and would reject the third case.
    data = _valid_build_dict()
    data["meta_dates"] = {"input_formats": [fmt]}
    cfg = BuildConfig.from_dict(data, SRC)
    assert cfg.meta_dates.input_formats == (fmt,)


def test_build_config_real_file_meta_dates(root):
    cfg = config_schema.load_build_config(root)
    assert cfg.meta_dates.fields == ["date"]


# --- normalize_meta_date ---------------------------------------------------

def _spec(*formats):
    return config_schema.MetaDateConfig(
        fields=["date"], input_formats=tuple(formats))


def test_normalize_iso_passthrough():
    assert config_schema.normalize_meta_date("2026-07-13", _spec("%m/%d/%Y")) == (
        date(2026, 7, 13), "%Y-%m-%d")


def test_normalize_applies_configured_format():
    value, via = config_schema.normalize_meta_date("07/13/2026", _spec("%m/%d/%Y"))
    assert value == date(2026, 7, 13)
    assert via == "%m/%d/%Y"


def test_normalize_format_order_decides_ambiguity():
    # The determinism contract: 05/06/2026 is May 6 or June 5 depending purely
    # on which format the config lists first — never on a guess.
    month_first, _ = config_schema.normalize_meta_date(
        "05/06/2026", _spec("%m/%d/%Y", "%d/%m/%Y"))
    day_first, _ = config_schema.normalize_meta_date(
        "05/06/2026", _spec("%d/%m/%Y", "%m/%d/%Y"))
    assert month_first == date(2026, 5, 6)
    assert day_first == date(2026, 6, 5)


def test_normalize_iso_wins_over_configured_formats():
    # %Y%m%d could never match an ISO string, but ISO is tried first regardless
    # so no config can reinterpret a canonical value.
    _, via = config_schema.normalize_meta_date("2026-07-13", _spec("%Y%m%d"))
    assert via == "%Y-%m-%d"


def test_normalize_coerces_int():
    # plyara yields an unquoted `date = 20260713` as an int.
    assert config_schema.normalize_meta_date(20260713, _spec("%Y%m%d")) == (
        date(2026, 7, 13), "%Y%m%d")


def test_normalize_rejects_bool():
    with pytest.raises(ValueError, match="got bool"):
        config_schema.normalize_meta_date(True, _spec("%Y%m%d"))


def test_normalize_rejects_unrecognized():
    with pytest.raises(ValueError, match="matches none of"):
        config_schema.normalize_meta_date("sometime in July", _spec("%Y%m%d"))


def test_normalize_without_spec_is_iso_only():
    assert config_schema.normalize_meta_date("2026-07-13")[0] == date(2026, 7, 13)
    with pytest.raises(ValueError):
        config_schema.normalize_meta_date("07/13/2026")


# --- strictness: nothing beyond the declared formats parses ----------------

@pytest.mark.parametrize(
    "undeclared",
    [
        "July 29, 2026",   # month name — no locale-independent parser remains
        "29-Jul-2026",
        "July 2026",       # incomplete: a lenient parser would backfill the day
        "2026",
        "2026-W01-1",      # ISO week date: fromisoformat reads it, we don't
        "14:22:01",        # time with no date at all
    ],
)
def test_undeclared_formats_do_not_parse(undeclared):
    # The whole point of dropping the fallback: a value only parses if the config
    # says so (or it is a plain ISO date/datetime). Everything else is
    # unparsable, and on_unparsable decides its fate.
    with pytest.raises(ValueError, match="matches none of"):
        config_schema.normalize_meta_date(undeclared, _spec("%m/%d/%Y", "%Y%m%d"))


def test_error_names_every_format_tried():
    with pytest.raises(ValueError, match=r"%Y-%m-%d.*%m/%d/%Y"):
        config_schema.normalize_meta_date("nope", _spec("%m/%d/%Y"))


def test_describe_accepted_dates_lists_iso_first():
    text = config_schema.describe_accepted_dates(_spec("%m/%d/%Y"))
    assert text == (
        "accepted formats ['%Y-%m-%d', '%m/%d/%Y'], or an ISO 8601 date+time")


# --- ISO 8601 date+time ----------------------------------------------------

@pytest.mark.parametrize("value", [
    "2026-07-13T14:22:01",
    "2026-07-13 14:22:01",       # space separator, as many feeds write it
    "2026-07-13T14:22:01Z",
    "2026-07-13T14:22:01+05:00",
    "2026-07-13T14:22:01.123456",
    "2026-07-13T14:22",
])
def test_iso_datetime_truncates_to_its_date(value):
    # Always accepted, never declared: an ISO datetime is still ISO, so no
    # input_formats entry should have to compete with it.
    parsed, via = config_schema.normalize_meta_date(value, _spec("%m/%d/%Y"))
    assert parsed == date(2026, 7, 13)
    assert via == config_schema.ISO_DATETIME


def test_iso_datetime_offset_is_ignored_not_converted():
    # 22:00 on the 3rd at -06:00 is the 4th in UTC. We report the date as
    # written: converting would move the value to another day based on an offset
    # the rule author chose, which is not what a meta_date bound is asking.
    parsed, _ = config_schema.normalize_meta_date(
        "2026-05-03T22:00:00-06:00", _spec())
    assert parsed == date(2026, 5, 3)


def test_iso_datetime_never_depends_on_machine_timezone(monkeypatch):
    # No astimezone, no localtime — the same string must read the same anywhere.
    results = []
    for tz in ("UTC", "America/Los_Angeles", "Pacific/Kiritimati"):
        monkeypatch.setenv("TZ", tz)
        results.append(
            config_schema.normalize_meta_date("2026-05-03T22:00:00-06:00", _spec()))
    assert results == [(date(2026, 5, 3), config_schema.ISO_DATETIME)] * 3


@pytest.mark.parametrize("value,expected_via", [
    ("2026-07-13", "%Y-%m-%d"),   # plain ISO keeps reporting ISO
    ("20260713", "%Y%m%d"),       # basic-format date belongs to the config entry
])
def test_date_only_values_are_not_annexed_by_the_datetime_path(value, expected_via):
    # date.fromisoformat reads both of these, which is exactly why the datetime
    # step is guarded — otherwise '20260713' would report ISO_DATETIME and the
    # configured '%Y%m%d' entry would be silently dead.
    _, via = config_schema.normalize_meta_date(value, _spec("%Y%m%d"))
    assert via == expected_via


def test_declared_non_iso_datetime_format_truncates():
    parsed, via = config_schema.normalize_meta_date(
        "07/13/2026 14:22", _spec("%m/%d/%Y %H:%M"))
    assert parsed == date(2026, 7, 13)
    assert via == "%m/%d/%Y %H:%M"


def test_policy_bounds_stay_iso_date_only():
    # parse_iso_date backs filter_policy bounds, which we author. A timestamp
    # there is a typo, not a vendor quirk to tolerate.
    with pytest.raises(ValueError):
        config_schema.parse_iso_date("2026-07-13T14:22:01Z")


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


# --- relative durations (meta_date.older_than) -----------------------------

@pytest.mark.parametrize("value,expected", [
    ("5y", (5, "y")),
    ("18m", (18, "m")),
    ("730d", (730, "d")),
    ("1d", (1, "d")),
])
def test_parse_duration_accepts(value, expected):
    assert config_schema.parse_duration(value) == expected


@pytest.mark.parametrize("bad", [
    "5", "y", "", "5w", "5Y", "-1d", "0d", "1y6m", " 5y", "5 y", "5.5y", 5, None,
])
def test_parse_duration_rejects(bad):
    with pytest.raises(ValueError):
        config_schema.parse_duration(bad)


@pytest.mark.parametrize("ref,amount,unit,expected", [
    (date(2026, 8, 7), 30, "d", date(2026, 7, 8)),
    (date(2026, 8, 7), 1, "m", date(2026, 7, 7)),
    (date(2026, 8, 7), 18, "m", date(2025, 2, 7)),
    (date(2026, 8, 7), 5, "y", date(2021, 8, 7)),
    (date(2026, 1, 15), 1, "m", date(2025, 12, 15)),   # year rollover
    (date(2026, 3, 31), 1, "m", date(2026, 2, 28)),    # day clamps to month end
    (date(2024, 2, 29), 1, "y", date(2023, 2, 28)),    # leap day
    (date(2024, 2, 29), 4, "y", date(2020, 2, 29)),    # ...to another leap year
    (date(2026, 3, 1), 1, "d", date(2026, 2, 28)),
])
def test_shift_back(ref, amount, unit, expected):
    assert config_schema.shift_back(ref, amount, unit) == expected


def test_filter_match_meta_date_parses_older_than():
    md = _meta_date_entry({"field": "last_modified", "older_than": "5y"}).match.meta_date
    assert md.field == "last_modified"
    assert md.older_than == (5, "y")
    assert md.before is None


def test_filter_match_older_than_satisfies_the_bound_requirement():
    # older_than is an upper bound like any other; on its own it is enough.
    assert _meta_date_entry({"field": "date", "older_than": "1d"}) is not None


@pytest.mark.parametrize("bad", ["5", "5w", "0d", "yesterday", 5])
def test_filter_match_meta_date_malformed_older_than(bad):
    with pytest.raises(ConfigError, match="older_than"):
        _meta_date_entry({"field": "date", "older_than": bad})


def test_effective_before_resolves_against_as_of():
    md = _meta_date_entry({"field": "date", "older_than": "5y"}).match.meta_date
    assert md.effective_before(date(2026, 8, 7)) == date(2021, 8, 7)


def test_effective_before_takes_the_earlier_of_two_upper_bounds():
    md = _meta_date_entry({
        "field": "date", "older_than": "5y", "before": "2021-01-01",
    }).match.meta_date
    assert md.effective_before(date(2026, 8, 7)) == date(2021, 1, 1)
    assert md.effective_before(date(2020, 1, 1)) == date(2015, 1, 1)


def test_effective_before_without_older_than_needs_no_as_of():
    md = _meta_date_entry({"field": "date", "before": "2026-05-01"}).match.meta_date
    assert md.effective_before(None) == date(2026, 5, 1)


def test_effective_before_requires_as_of_for_a_relative_bound():
    md = _meta_date_entry({"field": "date", "older_than": "5y"}).match.meta_date
    with pytest.raises(ValueError, match="needs a reference date"):
        md.effective_before(None)


# --- policy-level as_of ----------------------------------------------------

def test_filter_policy_parses_as_of():
    assert FilterPolicy.from_dict({"as_of": "2026-01-01"}, SRC).as_of == date(2026, 1, 1)


def test_filter_policy_as_of_defaults_to_none():
    assert FilterPolicy.from_dict({}, SRC).as_of is None


@pytest.mark.parametrize("bad", ["01/01/2026", "nope", date(2026, 1, 1)])
def test_filter_policy_malformed_as_of(bad):
    # A native YAML date (unquoted in the file) is rejected too: bounds are
    # quoted ISO strings everywhere in this policy, and one exception would
    # make the shipped examples wrong.
    with pytest.raises(ConfigError, match="as_of must be a quoted YYYY-MM-DD"):
        FilterPolicy.from_dict({"as_of": bad}, SRC)


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
