"""Tests for the filter policy engine."""

from datetime import date

import pytest

import yaml

import apply_filters
from config_schema import (
    BuildConfig,
    FilterDateRange,
    FilterEntry,
    FilterMatch,
    FilterPolicy,
    OverrideEntry,
)
from corpus import PipelineError
from conftest import make_rule


def _filter(action, scope="global", match=None, fid=None):
    return FilterEntry(action=action, scope=scope, match=match, id=fid)


def _config(coverage_gap_rel="coverage_gap_decisions.yaml") -> BuildConfig:
    return BuildConfig(
        output_formats=["source"],
        yara_modules=["pe"],
        external_variables={},
        stale_override_decisions="stale_override_decisions.yaml",
        coverage_gap_decisions=coverage_gap_rel,
        filter_conflict_policy="exclude_wins",
        required_meta=["author"],
    )


# --- default mode ----------------------------------------------------------

def test_default_include_all_keeps_unmatched():
    rule = make_rule("Foo")
    action, responsible = apply_filters._resolve_rule(rule, [], "include_all", "exclude_wins")
    assert action == "include"
    assert responsible is None


def test_default_exclude_all_drops_unmatched():
    rule = make_rule("Foo")
    action, responsible = apply_filters._resolve_rule(rule, [], "exclude_all", "exclude_wins")
    assert action == "exclude"
    assert responsible is None


# --- specificity ordering --------------------------------------------------

def test_rule_scope_beats_ruleset_scope():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("exclude", scope="vendor"),
        _filter("include", scope="rule:Foo"),
    ]
    action, _ = apply_filters._resolve_rule(rule, filters, "include_all", "exclude_wins")
    assert action == "include"


def test_ruleset_scope_beats_global():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("exclude", scope="global"),
        _filter("include", scope="vendor"),
    ]
    action, _ = apply_filters._resolve_rule(rule, filters, "include_all", "exclude_wins")
    assert action == "include"


# --- same-specificity tie-break -------------------------------------------

def test_exclude_wins_tie_break():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("include", scope="vendor", fid="inc"),
        _filter("exclude", scope="vendor", fid="exc"),
    ]
    action, responsible = apply_filters._resolve_rule(rule, filters, "include_all", "exclude_wins")
    assert action == "exclude"
    assert responsible.id == "exc"


def test_last_match_wins_tie_break():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("exclude", scope="vendor", fid="exc"),
        _filter("include", scope="vendor", fid="inc"),
    ]
    action, responsible = apply_filters._resolve_rule(rule, filters, "include_all", "last_match_wins")
    assert action == "include"
    assert responsible.id == "inc"


def test_error_policy_raises_on_conflict():
    rule = make_rule("Foo", origin="vendor")
    filters = [
        _filter("include", scope="vendor", fid="inc"),
        _filter("exclude", scope="vendor", fid="exc"),
    ]
    with pytest.raises(PipelineError, match="conflicting same-specificity"):
        apply_filters._resolve_rule(rule, filters, "include_all", "error")


# --- selector matching -----------------------------------------------------

def test_selector_tag_match():
    rule = make_rule("Foo", origin="vendor", tags=["malware"])
    filt = _filter("exclude", scope="global", match=FilterMatch(tags=["malware"]))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all", "exclude_wins")
    assert action == "exclude"


def test_selector_tag_non_match_falls_through_to_default():
    rule = make_rule("Foo", origin="vendor", tags=["benign"])
    filt = _filter("exclude", scope="global", match=FilterMatch(tags=["malware"]))
    action, responsible = apply_filters._resolve_rule(rule, [filt], "include_all", "exclude_wins")
    assert action == "include"
    assert responsible is None


# --- selector matching (breadth) -------------------------------------------

def test_selector_name_glob_match():
    rule = make_rule("Trojan_Foo", origin="vendor")
    filt = _filter("exclude", match=FilterMatch(name_glob="Trojan_*"))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all", "exclude_wins")
    assert action == "exclude"


def test_selector_name_regex_non_match_falls_through():
    rule = make_rule("Benign", origin="vendor")
    filt = _filter("exclude", match=FilterMatch(name_regex=r"^Trojan_"))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all", "exclude_wins")
    assert action == "include"


def test_selector_meta_exact_match():
    rule = make_rule("Foo", origin="vendor", meta={"severity": "high"})
    filt = _filter("exclude", match=FilterMatch(meta={"severity": "high"}))
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all", "exclude_wins")
    assert action == "exclude"


def test_selector_meta_in_membership():
    # meta_in values are normalized to a frozenset of strings by FilterMatch.
    rule = make_rule("Foo", origin="vendor", meta={"severity": "medium"})
    match = FilterMatch(meta_in={"severity": ["low", "medium"]})
    filt = _filter("exclude", match=match)
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all", "exclude_wins")
    assert action == "exclude"


def test_selector_meta_in_non_member_falls_through():
    rule = make_rule("Foo", origin="vendor", meta={"severity": "high"})
    match = FilterMatch(meta_in={"severity": ["low", "medium"]})
    filt = _filter("exclude", match=match)
    action, _ = apply_filters._resolve_rule(rule, [filt], "include_all", "exclude_wins")
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
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all", "exclude_wins")
    assert action == "exclude"


def test_meta_date_before_strict_boundary_does_not_match():
    # A rule exactly on the 'before' bound is NOT earlier, so it falls through.
    rule = _dated("Foo", "2026-05-01")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all", "exclude_wins")
    assert action == "include"


def test_meta_date_after_strict_excludes_later():
    rule = _dated("Foo", "2026-07-13")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(after=date(2026, 7, 1))], "include_all", "exclude_wins")
    assert action == "exclude"


def test_meta_date_on_or_before_is_inclusive():
    rule = _dated("Foo", "2026-05-01")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(on_or_before=date(2026, 5, 1))], "include_all", "exclude_wins")
    assert action == "exclude"


def test_meta_date_on_or_after_is_inclusive():
    rule = _dated("Foo", "2026-05-01")
    action, _ = apply_filters._resolve_rule(
        rule, [_date_filter(on_or_after=date(2026, 5, 1))], "include_all", "exclude_wins")
    assert action == "exclude"


def test_meta_date_between_selects_only_in_range():
    filt = _date_filter(on_or_after=date(2026, 5, 1), before=date(2026, 7, 1))
    in_range = _dated("In", "2026-06-06")
    below = _dated("Below", "2026-04-18")
    above = _dated("Above", "2026-07-13")
    assert apply_filters._resolve_rule(in_range, [filt], "include_all", "exclude_wins")[0] == "exclude"
    assert apply_filters._resolve_rule(below, [filt], "include_all", "exclude_wins")[0] == "include"
    assert apply_filters._resolve_rule(above, [filt], "include_all", "exclude_wins")[0] == "include"


def test_meta_date_missing_field_falls_through():
    rule = make_rule("Foo", origin="vendor", meta={"author": "x"})  # no date
    action, responsible = apply_filters._resolve_rule(
        rule, [_date_filter(before=date(2026, 5, 1))], "include_all", "exclude_wins")
    assert action == "include"
    assert responsible is None


def test_meta_date_unparseable_value_raises():
    rule = _dated("Foo", "not-a-date")
    with pytest.raises(PipelineError, match="not a valid YYYY-MM-DD date"):
        apply_filters._resolve_rule(
            rule, [_date_filter(before=date(2026, 5, 1))], "include_all", "exclude_wins")


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
