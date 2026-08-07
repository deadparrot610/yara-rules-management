"""Tests for the filter policy engine."""

from datetime import date, timedelta

import pytest

import yaml

import apply_filters
from config_schema import (
    BuildConfig,
    ConfigError,
    FilterDateRange,
    FilterEntry,
    FilterMatch,
    FilterPolicy,
    MetaDateConfig,
    OverrideEntry,
)
from corpus import PipelineError
from conftest import make_rule


def _filter(action, scope="global", match=None, fid=None):
    return FilterEntry(action=action, scope=scope, match=match, id=fid)


def _config(coverage_gap_rel="coverage_gap_decisions.yaml",
            meta_dates=None) -> BuildConfig:
    return BuildConfig(
        output_formats=["source"],
        yara_modules=["pe"],
        external_variables={},
        stale_override_decisions="stale_override_decisions.yaml",
        coverage_gap_decisions=coverage_gap_rel,
        required_meta=["author"],
        meta_dates=meta_dates or MetaDateConfig(),
    )


# --- default mode ----------------------------------------------------------

def test_default_include_all_keeps_unmatched():
    rule = make_rule("Foo")
    action, responsible = apply_filters._resolve_rule(rule, [], "include_all")
    assert action == "include"
    assert responsible is None


def test_default_exclude_all_drops_unmatched():
    rule = make_rule("Foo")
    action, responsible = apply_filters._resolve_rule(rule, [], "exclude_all")
    assert action == "exclude"
    assert responsible is None


# --- specificity ordering --------------------------------------------------

def test_rule_scope_beats_ruleset_scope():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("exclude", scope="vendor"),
        _filter("include", scope="rule:Foo"),
    ]
    action, _ = apply_filters._resolve_rule(rule, filters, "include_all")
    assert action == "include"


def test_ruleset_scope_beats_global():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("exclude", scope="global"),
        _filter("include", scope="vendor"),
    ]
    action, _ = apply_filters._resolve_rule(rule, filters, "include_all")
    assert action == "include"


# --- same-specificity tie-break -------------------------------------------

def test_exclude_wins_tie_break():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("include", scope="vendor", fid="inc"),
        _filter("exclude", scope="vendor", fid="exc"),
    ]
    action, responsible = apply_filters._resolve_rule(rule, filters, "include_all")
    assert action == "exclude"
    assert responsible.id == "exc"


def test_exclude_wins_tie_break_regardless_of_order():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("exclude", scope="vendor", fid="exc"),
        _filter("include", scope="vendor", fid="inc"),
    ]
    action, responsible = apply_filters._resolve_rule(rule, filters, "include_all")
    assert action == "exclude"
    assert responsible.id == "exc"


# --- selector matching -----------------------------------------------------

def test_selector_tag_match():
    rule = make_rule("Foo", origin="vendor", tags=["malware"])
    filt = _filter("exclude", scope="global", match=FilterMatch(tags=["malware"]))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all")
    assert action == "exclude"


def test_selector_tag_non_match_falls_through_to_default():
    rule = make_rule("Foo", origin="vendor", tags=["benign"])
    filt = _filter("exclude", scope="global", match=FilterMatch(tags=["malware"]))
    action, responsible = apply_filters._resolve_rule(rule, [filt], "include_all")
    assert action == "include"
    assert responsible is None


# --- selector matching (breadth) -------------------------------------------

def test_selector_name_glob_match():
    rule = make_rule("Trojan_Foo", origin="vendor")
    filt = _filter("exclude", match=FilterMatch(name_glob="Trojan_*"))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all")
    assert action == "exclude"


def test_selector_name_regex_non_match_falls_through():
    rule = make_rule("Benign", origin="vendor")
    filt = _filter("exclude", match=FilterMatch(name_regex=r"^Trojan_"))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all")
    assert action == "include"


def test_selector_meta_exact_match():
    rule = make_rule("Foo", origin="vendor", meta={"severity": "high"})
    filt = _filter("exclude", match=FilterMatch(meta={"severity": "high"}))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all")
    assert action == "exclude"


def test_selector_meta_in_membership():
    # meta_in values are normalized to a frozenset of strings by FilterMatch.
    rule = make_rule("Foo", origin="vendor", meta={"severity": "medium"})
    match = FilterMatch(meta_in={"severity": ["low", "medium"]})
    filt = _filter("exclude", match=match)
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all")
    assert action == "exclude"


def test_selector_meta_in_non_member_falls_through():
    rule = make_rule("Foo", origin="vendor", meta={"severity": "high"})
    match = FilterMatch(meta_in={"severity": ["low", "medium"]})
    filt = _filter("exclude", match=match)
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all")
    assert action == "include"


# --- selector matching: meta_date range ------------------------------------

def _date_filter(**bounds):
    return _filter("exclude", match=FilterMatch(
        meta_date=FilterDateRange(field="date", **bounds)))


def _dated(identifier, value):
    return make_rule(identifier, origin="vendor", meta={"date": value})


def test_meta_date_before_strict_excludes_earlier():
    rule = _dated("Foo", "2026-04-18")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all")
    assert action == "exclude"


def test_meta_date_before_strict_boundary_does_not_match():
    # A rule exactly on the 'before' bound is NOT earlier, so it falls through.
    rule = _dated("Foo", "2026-05-01")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all")
    assert action == "include"


def test_meta_date_after_strict_excludes_later():
    rule = _dated("Foo", "2026-07-13")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(after=date(2026, 7, 1))], "include_all")
    assert action == "exclude"


def test_meta_date_on_or_before_is_inclusive():
    rule = _dated("Foo", "2026-05-01")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(on_or_before=date(2026, 5, 1))], "include_all")
    assert action == "exclude"


def test_meta_date_on_or_after_is_inclusive():
    rule = _dated("Foo", "2026-05-01")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(on_or_after=date(2026, 5, 1))], "include_all")
    assert action == "exclude"


def test_meta_date_between_selects_only_in_range():
    filt = _date_filter(on_or_after=date(2026, 5, 1), before=date(2026, 7, 1))
    in_range = _dated("In", "2026-06-06")
    below = _dated("Below", "2026-04-18")
    above = _dated("Above", "2026-07-13")
    assert apply_filters._resolve_rule(in_range, [filt], "include_all")[0] == "exclude"
    assert apply_filters._resolve_rule(below, [filt], "include_all")[0] == "include"
    assert apply_filters._resolve_rule(above, [filt], "include_all")[0] == "include"


def test_meta_date_missing_field_falls_through():
    rule = make_rule("Foo", origin="vendor", meta={"author": "x"})  # no date
    action, responsible = apply_filters._resolve_rule(
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all")
    assert action == "include"
    assert responsible is None


def test_meta_date_unparseable_value_raises():
    rule = _dated("Foo", "not-a-date")
    with pytest.raises(PipelineError, match="not a recognized date"):
        apply_filters._resolve_rule(
            rule, [_date_filter(before=date(2026, 5, 1))], "include_all")


# --- selector matching: meta_date normalization ----------------------------

def _meta_dates(*formats):
    return MetaDateConfig(fields=["date"], input_formats=tuple(formats))


def test_meta_date_normalizes_non_iso_rule_value():
    rule = _dated("Foo", "04/18/2026")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all",
        _meta_dates("%m/%d/%Y"))
    assert action == "exclude"


def test_meta_date_compares_a_timestamped_value_on_its_date():
    # No input_formats entry needed — an ISO datetime is accepted by the ISO step.
    rule = _dated("Foo", "2026-04-18T22:00:00-06:00")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all", _meta_dates())
    assert action == "exclude"


def test_meta_date_undeclared_format_is_not_guessed_at():
    # No fallback parser: a value the config doesn't declare raises rather than
    # being interpreted. In a real build the unparsable-date gate has already
    # failed or dropped it; this is the filter engine's backstop.
    rule = _dated("Foo", "April 18, 2026")
    with pytest.raises(PipelineError, match="not a recognized date"):
        apply_filters._resolve_rule(
            rule, [_date_filter(before=date(2026, 5, 1))], "include_all",
            _meta_dates("%m/%d/%Y"))


def test_meta_date_without_config_stays_iso_only():
    # The default keeps today's strictness: no config, no leniency.
    rule = _dated("Foo", "04/18/2026")
    with pytest.raises(PipelineError, match="not a recognized date"):
        apply_filters._resolve_rule(
            rule, [_date_filter(before=date(2026, 5, 1))], "include_all")


def test_meta_date_normalization_respects_format_order():
    # 05/06/2026 is May 6 under month-first, June 5 under day-first; a bound
    # between the two shows which reading actually reached the comparison.
    rule = _dated("Foo", "05/06/2026")
    bound = _date_filter(before=date(2026, 6, 1))
    month_first, _ = apply_filters._resolve_rule(
        rule, [bound], "include_all", _meta_dates("%m/%d/%Y", "%d/%m/%Y"))
    day_first, _ = apply_filters._resolve_rule(
        rule, [bound], "include_all", _meta_dates("%d/%m/%Y", "%m/%d/%Y"))
    assert month_first == "exclude"   # 2026-05-06 < 2026-06-01
    assert day_first == "include"     # 2026-06-05 is not


def test_meta_date_error_names_the_accepted_formats():
    rule = _dated("Foo", "13.07.2026")
    with pytest.raises(PipelineError, match=r"%m/%d/%Y"):
        apply_filters._resolve_rule(
            rule, [_date_filter(before=date(2026, 5, 1))], "include_all",
            _meta_dates("%m/%d/%Y"))


# --- selector matching: relative age (older_than) --------------------------

AS_OF = date(2026, 8, 7)


def test_older_than_excludes_a_rule_past_the_cutoff():
    rule = _dated("Foo", "2021-08-06")  # one day past as_of - 5y
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(older_than=(5, "y"))], "include_all", None, AS_OF)
    assert action == "exclude"


def test_older_than_is_strict_at_the_cutoff():
    # as_of - 5y exactly: not *older* than five years, so it falls through.
    rule = _dated("Foo", "2021-08-07")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(older_than=(5, "y"))], "include_all", None, AS_OF)
    assert action == "include"


@pytest.mark.parametrize("duration,cutoff", [
    ((30, "d"), date(2026, 7, 8)),
    ((1, "m"), date(2026, 7, 7)),
    ((18, "m"), date(2025, 2, 7)),
    ((5, "y"), date(2021, 8, 7)),
])
def test_older_than_units_resolve_to_the_expected_cutoff(duration, cutoff):
    # A rule one day below the cutoff is excluded; one on it is not.
    filt = _date_filter(older_than=duration)
    below = _dated("Below", (cutoff - timedelta(days=1)).isoformat())
    on = _dated("On", cutoff.isoformat())
    assert apply_filters._resolve_rule(
        below, [filt], "include_all", None, AS_OF)[0] == "exclude"
    assert apply_filters._resolve_rule(
        on, [filt], "include_all", None, AS_OF)[0] == "include"


def test_older_than_tracks_the_reference_date():
    # The same filter, two reference dates: the window moves, nothing else does.
    rule = _dated("Foo", "2021-06-01")
    filt = _date_filter(older_than=(5, "y"))
    assert apply_filters._resolve_rule(
        rule, [filt], "include_all", None, date(2026, 8, 7))[0] == "exclude"
    assert apply_filters._resolve_rule(
        rule, [filt], "include_all", None, date(2024, 1, 1))[0] == "include"


def test_older_than_and_before_intersect_on_the_earlier_bound():
    # Both are upper bounds and they AND, so only a rule below *both* matches.
    rule = _dated("Foo", "2021-06-01")            # cutoff(5y) = 2021-08-07
    filt = _date_filter(older_than=(5, "y"), before=date(2021, 1, 1))
    assert apply_filters._resolve_rule(
        rule, [filt], "include_all", None, AS_OF)[0] == "include"
    older = _dated("Bar", "2020-12-31")
    assert apply_filters._resolve_rule(
        older, [filt], "include_all", None, AS_OF)[0] == "exclude"


def test_older_than_ignores_a_rule_without_the_field():
    rule = make_rule("Foo", origin="vendor", meta={"author": "x"})
    action, responsible = apply_filters._resolve_rule(
        rule, [_date_filter(older_than=(5, "y"))], "include_all", None, AS_OF)
    assert action == "include"
    assert responsible is None


def test_older_than_without_a_reference_date_raises():
    rule = _dated("Foo", "2000-01-01")
    with pytest.raises(PipelineError, match="needs a reference date"):
        apply_filters._resolve_rule(
            rule, [_date_filter(older_than=(5, "y"))], "include_all")


def test_older_than_normalizes_a_non_iso_rule_value():
    rule = _dated("Foo", "06/01/2021")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(older_than=(5, "y"))], "include_all",
        _meta_dates("%m/%d/%Y"), AS_OF)
    assert action == "exclude"


# --- selector matching: relative recency (newer_than) ----------------------

def test_newer_than_excludes_a_rule_inside_the_window():
    rule = _dated("Foo", "2026-07-09")  # one day after as_of - 30d
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(newer_than=(30, "d"))], "include_all", None, AS_OF)
    assert action == "exclude"


def test_newer_than_is_strict_at_the_cutoff():
    # as_of - 30d exactly: not *newer* than 30 days, so it falls through.
    rule = _dated("Foo", "2026-07-08")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(newer_than=(30, "d"))], "include_all", None, AS_OF)
    assert action == "include"


def test_newer_than_tracks_the_reference_date():
    rule = _dated("Foo", "2026-07-20")
    filt = _date_filter(newer_than=(30, "d"))
    assert apply_filters._resolve_rule(
        rule, [filt], "include_all", None, date(2026, 8, 7))[0] == "exclude"
    assert apply_filters._resolve_rule(
        rule, [filt], "include_all", None, date(2026, 12, 1))[0] == "include"


def test_newer_than_and_after_intersect_on_the_later_bound():
    # Both are lower bounds and they AND, so only a rule above *both* matches.
    rule = _dated("Foo", "2026-07-20")            # cutoff(30d) = 2026-07-08
    filt = _date_filter(newer_than=(30, "d"), after=date(2026, 8, 1))
    assert apply_filters._resolve_rule(
        rule, [filt], "include_all", None, AS_OF)[0] == "include"
    newer = _dated("Bar", "2026-08-02")
    assert apply_filters._resolve_rule(
        newer, [filt], "include_all", None, AS_OF)[0] == "exclude"


def test_newer_than_ignores_a_rule_without_the_field():
    rule = make_rule("Foo", origin="vendor", meta={"author": "x"})
    action, responsible = apply_filters._resolve_rule(
        rule, [_date_filter(newer_than=(30, "d"))], "include_all", None, AS_OF)
    assert action == "include"
    assert responsible is None


def test_newer_than_without_a_reference_date_raises():
    rule = _dated("Foo", "2026-08-01")
    with pytest.raises(PipelineError, match="newer_than needs a reference date"):
        apply_filters._resolve_rule(
            rule, [_date_filter(newer_than=(30, "d"))], "include_all")


def test_rolling_window_selects_only_between_the_two_cutoffs():
    # newer_than 2y (2024-08-07) .. older_than 6m (2026-02-07), both strict.
    filt = _date_filter(newer_than=(2, "y"), older_than=(6, "m"))
    inside = _dated("Inside", "2025-06-01")
    too_old = _dated("TooOld", "2023-01-01")
    too_new = _dated("TooNew", "2026-07-13")
    assert apply_filters._resolve_rule(
        inside, [filt], "include_all", None, AS_OF)[0] == "exclude"
    assert apply_filters._resolve_rule(
        too_old, [filt], "include_all", None, AS_OF)[0] == "include"
    assert apply_filters._resolve_rule(
        too_new, [filt], "include_all", None, AS_OF)[0] == "include"


# --- as_of resolution ------------------------------------------------------

def test_resolve_as_of_precedence():
    pinned = FilterPolicy(as_of=date(2026, 1, 1))
    unpinned = FilterPolicy()
    assert apply_filters.resolve_as_of(pinned, date(2020, 3, 4)) == date(2020, 3, 4)
    assert apply_filters.resolve_as_of(pinned) == date(2026, 1, 1)
    assert apply_filters.resolve_as_of(unpinned) == date.today()


def test_parse_as_of_arg_rejects_a_non_iso_value():
    assert apply_filters.parse_as_of_arg(None) is None
    assert apply_filters.parse_as_of_arg("2026-08-07") == AS_OF
    with pytest.raises(ConfigError, match="--as-of"):
        apply_filters.parse_as_of_arg("08/07/2026")


def test_run_applies_a_relative_bound_end_to_end(tmp_path):
    rules = [_dated("Stale", "2019-02-02"), _dated("Fresh", "2026-07-13")]
    policy = FilterPolicy(
        default_mode="include_all",
        min_output_rules=0,
        filters=[_filter("exclude", scope="vendor", fid="F-retire-stale",
                         match=FilterMatch(meta_date=FilterDateRange(
                             field="date", older_than=(5, "y"))))],
    )
    included, record = apply_filters.run(
        rules, policy, tmp_path, [], _config(meta_dates=_meta_dates()),
        as_of=AS_OF)
    assert [r.identifier for r in included] == ["Fresh"]
    assert record == [{"identifier": "Stale", "filter_id": "F-retire-stale",
                       "reason": ""}]


def test_run_applies_a_rolling_window_end_to_end(tmp_path):
    rules = [_dated("Ancient", "2019-02-02"),
             _dated("Aging", "2025-06-01"),
             _dated("Fresh", "2026-07-13")]
    policy = FilterPolicy(
        default_mode="include_all",
        min_output_rules=0,
        filters=[_filter("exclude", scope="vendor", fid="F-window",
                         match=FilterMatch(meta_date=FilterDateRange(
                             field="date",
                             newer_than=(2, "y"), older_than=(6, "m"))))],
    )
    included, record = apply_filters.run(
        rules, policy, tmp_path, [], _config(meta_dates=_meta_dates()),
        as_of=AS_OF)
    assert [r.identifier for r in included] == ["Ancient", "Fresh"]
    assert [e["identifier"] for e in record] == ["Aging"]


def test_run_falls_back_to_the_policy_pinned_as_of(tmp_path):
    rules = [_dated("Foo", "2019-02-02")]
    policy = FilterPolicy(
        default_mode="include_all",
        min_output_rules=0,
        as_of=date(2020, 1, 1),   # cutoff 2015-01-01 — Foo is newer, so it stays
        filters=[_filter("exclude", scope="vendor",
                         match=FilterMatch(meta_date=FilterDateRange(
                             field="date", older_than=(5, "y"))))],
    )
    included, record = apply_filters.run(
        rules, policy, tmp_path, [], _config(meta_dates=_meta_dates()))
    assert [r.identifier for r in included] == ["Foo"]
    assert record == []


def test_run_threads_meta_dates_from_config(tmp_path):
    # The acceptance path: config -> run -> selector, with nothing normalized in
    # between and no rule source touched.
    rules = [_dated("Old", "04/16/2026"), _dated("New", "20260713")]
    policy = FilterPolicy(
        default_mode="include_all",
        min_output_rules=0,
        filters=[_filter("exclude", scope="vendor", fid="drop-old",
                         match=FilterMatch(meta_date=FilterDateRange(
                             field="date", before=date(2026, 5, 1))))],
    )
    config = _config(meta_dates=_meta_dates("%m/%d/%Y", "%Y%m%d"))
    included, exclusion_record = apply_filters.run(
        rules, policy, tmp_path, [], config)
    assert [r.identifier for r in included] == ["New"]
    assert [r["identifier"] for r in exclusion_record] == ["Old"]
    # Source values are untouched — normalization happens only at comparison.
    assert rules[0].meta["date"] == "04/16/2026"


def test_run_meta_date_exclusion_drops_in_range_rules(tmp_path):
    rules = [_dated("Old", "2026-04-16"), _dated("New", "2026-07-13")]
    policy = FilterPolicy(
        default_mode="include_all",
        min_output_rules=0,
        filters=[_filter("exclude", scope="vendor", fid="drop-old",
                         match=FilterMatch(
                             meta_date=FilterDateRange(field="date", before=date(2026, 5, 1))))],
    )
    included, exclusion_record = apply_filters.run(rules, policy, tmp_path, [], _config())
    assert [r.identifier for r in included] == ["New"]
    assert [r["identifier"] for r in exclusion_record] == ["Old"]
    assert exclusion_record[0]["filter_id"] == "drop-old"


# --- referential integrity -------------------------------------------------

def test_referential_integrity_raises_on_dangling_reference():
    included = [make_rule("Uses", condition_terms=["Dep", "and", "$x"])]
    with pytest.raises(PipelineError, match="referential integrity"):
        apply_filters._referential_integrity_check(included, {"Dep"})


def test_referential_integrity_ok_when_reference_present():
    included = [make_rule("Uses", condition_terms=["Dep"]), make_rule("Dep")]
    # Dep is not excluded, so no error.
    apply_filters._referential_integrity_check(included, set())


# --- floor guard -----------------------------------------------------------

def test_floor_guard_fail_raises():
    policy = FilterPolicy(min_output_rules=5, on_empty_output="fail")
    with pytest.raises(PipelineError, match="below min_output_rules"):
        apply_filters._floor_guard(2, policy)


def test_floor_guard_warn_does_not_raise():
    policy = FilterPolicy(min_output_rules=5, on_empty_output="warn")
    apply_filters._floor_guard(2, policy)  # no raise


def test_floor_guard_passes_when_at_or_above_floor():
    policy = FilterPolicy(min_output_rules=1, on_empty_output="fail")
    apply_filters._floor_guard(1, policy)  # no raise


# --- coverage-gap checkpoint (D-10) ----------------------------------------

def _write_gap_decisions(path, entries):
    path.write_text(yaml.safe_dump({"coverage_gap_decisions": entries}))


def test_coverage_gap_blocks_excluded_override(tmp_path):
    # 'ov' supersedes a vendor rule (already stripped) but is itself excluded by a
    # filter — neither detection remains and no decision is recorded.
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_vendor"])]
    exclusion_record = [{"identifier": "ov", "filter_id": "f1", "reason": ""}]
    with pytest.raises(PipelineError, match="coverage gap checkpoint"):
        apply_filters._coverage_gap_check(exclusion_record, manifest, tmp_path, _config())


def test_coverage_gap_unblocked_by_keep_decision(tmp_path):
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_vendor"])]
    exclusion_record = [{"identifier": "ov", "filter_id": "f1", "reason": ""}]
    _write_gap_decisions(tmp_path / "coverage_gap_decisions.yaml", [
        {"override_rule": "ov", "filter_id": "f1", "decision": "keep"},
    ])
    # no raise
    apply_filters._coverage_gap_check(exclusion_record, manifest, tmp_path, _config())


def test_coverage_gap_ignores_non_override_exclusion(tmp_path):
    # Excluding a rule that supersedes nothing cannot create a coverage gap.
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_vendor"])]
    exclusion_record = [{"identifier": "some_custom_rule", "filter_id": "f1", "reason": ""}]
    apply_filters._coverage_gap_check(exclusion_record, manifest, tmp_path, _config())


# --- integrated run() API --------------------------------------------------

def test_run_records_default_mode_exclusions(tmp_path):
    # exclude_all default with no filters: everything is excluded and each record
    # carries filter_id=None and a default_mode reason.
    rules = [make_rule("A", origin="vendor"), make_rule("B", origin="custom")]
    policy = FilterPolicy(default_mode="exclude_all", min_output_rules=0)
    included, exclusion_record = apply_filters.run(rules, policy, tmp_path, [], _config())
    assert included == []
    assert {r["identifier"] for r in exclusion_record} == {"A", "B"}
    assert all(r["filter_id"] is None for r in exclusion_record)
    assert all(r["reason"] == "default_mode: exclude_all" for r in exclusion_record)


def test_run_filter_exclusion_carries_filter_id(tmp_path):
    rules = [make_rule("Keep", origin="vendor"), make_rule("Drop", origin="vendor")]
    policy = FilterPolicy(
        default_mode="include_all",
        min_output_rules=0,
        filters=[_filter("exclude", scope="rule:Drop", fid="drop-filter")],
    )
    included, exclusion_record = apply_filters.run(rules, policy, tmp_path, [], _config())
    assert [r.identifier for r in included] == ["Keep"]
    assert exclusion_record == [
        {"identifier": "Drop", "filter_id": "drop-filter", "reason": ""}
    ]


# --- pre_excluded (unparsable-date drops) ----------------------------------

def _drop_record(identifier):
    return {"identifier": identifier, "filter_id": None,
            "reason": "unparsable date: date='whenever'"}


def test_pre_excluded_records_reach_the_exclusion_record(tmp_path):
    rules = [make_rule("Keep", origin="vendor")]
    policy = FilterPolicy(default_mode="include_all", min_output_rules=0)
    included, exclusion_record = apply_filters.run(
        rules, policy, tmp_path, [], _config(), pre_excluded=[_drop_record("Dropped")])
    assert [r.identifier for r in included] == ["Keep"]
    assert [r["identifier"] for r in exclusion_record] == ["Dropped"]


def test_pre_excluded_override_trips_the_coverage_gap_checkpoint(tmp_path):
    # The reason drops are threaded through run() at all: removing an override
    # whose superseded vendor rules are already gone leaves neither detection,
    # and that must block regardless of *why* the override went away.
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_vendor"])]
    policy = FilterPolicy(default_mode="include_all", min_output_rules=0)
    with pytest.raises(PipelineError, match="coverage gap checkpoint"):
        apply_filters.run([], policy, tmp_path, manifest, _config(),
                          pre_excluded=[_drop_record("ov")])


def test_pre_excluded_override_unblocked_by_wildcard_decision(tmp_path):
    # A drop has no responsible filter, so its decision key is the (rule, None)
    # wildcard that lookup_decision already supports.
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_vendor"])]
    _write_gap_decisions(tmp_path / "coverage_gap_decisions.yaml", [
        {"override_rule": "ov", "decision": "keep"},
    ])
    policy = FilterPolicy(default_mode="include_all", min_output_rules=0)
    apply_filters.run([], policy, tmp_path, manifest, _config(),
                      pre_excluded=[_drop_record("ov")])  # no raise


def test_pre_excluded_rule_still_referenced_is_an_error(tmp_path):
    included = make_rule("Uses", origin="custom",
                         condition_terms=["Dropped", "and", "$x"])
    policy = FilterPolicy(default_mode="include_all", min_output_rules=0)
    with pytest.raises(PipelineError, match="referential integrity"):
        apply_filters.run([included], policy, tmp_path, [], _config(),
                          pre_excluded=[_drop_record("Dropped")])


def test_pre_excluded_drops_count_against_the_floor(tmp_path):
    rules = [make_rule("Keep", origin="vendor")]
    policy = FilterPolicy(default_mode="include_all", min_output_rules=2,
                          on_empty_output="fail")
    with pytest.raises(PipelineError, match="below min_output_rules"):
        apply_filters.run(rules, policy, tmp_path, [], _config(),
                          pre_excluded=[_drop_record("Dropped")])
