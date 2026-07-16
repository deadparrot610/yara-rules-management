"""Tests for the filter policy engine."""

import pytest

import apply_filters
from config_schema import FilterEntry, FilterMatch, FilterPolicy
from corpus import PipelineError
from conftest import make_rule


def _filter(action, scope="global", match=None, fid=None):
    return FilterEntry(action=action, scope=scope, match=match, id=fid)


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
