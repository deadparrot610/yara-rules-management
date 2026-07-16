"""Tests for the override manifest validation + stale-override checkpoint (D-4)."""

import pytest

import check_overrides
from config_schema import BuildConfig, OverrideEntry
from corpus import PipelineError
from conftest import make_rule


def _config(decisions_rel="stale_override_decisions.yaml") -> BuildConfig:
    """A minimal BuildConfig whose stale-decisions path is caller-controlled.

    validate() reads decisions from root / config.stale_override_decisions, so
    tests point this at a tmp_path file to exercise the decision paths without
    touching the repo's real decisions file.
    """
    return BuildConfig(
        output_formats=["source"],
        yara_modules=["pe"],
        external_variables={},
        stale_override_decisions=decisions_rel,
        coverage_gap_decisions="coverage_gap_decisions.yaml",
        filter_conflict_policy="exclude_wins",
        required_meta=["author"],
    )


def _write_decisions(path, entries):
    """Write a stale_override_decisions YAML from a list of dicts."""
    import yaml
    path.write_text(yaml.safe_dump({"stale_override_decisions": entries}))


# --- semantic checks -------------------------------------------------------

def test_override_rule_not_in_corpus_errors(tmp_path):
    manifest = [OverrideEntry(override_rule="ghost_override", supersedes=["v1"])]
    with pytest.raises(PipelineError, match="failed validation"):
        check_overrides.validate(
            [make_rule("v1")], [make_rule("real_override", origin="overrides")],
            manifest, _config(), tmp_path)


def test_supersedes_names_an_override_errors(tmp_path):
    ov = make_rule("ov", origin="overrides")
    other_ov = make_rule("other_ov", origin="overrides")
    manifest = [OverrideEntry(override_rule="ov", supersedes=["other_ov"])]
    with pytest.raises(PipelineError, match="failed validation"):
        check_overrides.validate(
            [], [ov, other_ov], manifest, _config(), tmp_path)


def test_vendor_id_claimed_twice_errors(tmp_path):
    ov1 = make_rule("ov1", origin="overrides")
    ov2 = make_rule("ov2", origin="overrides")
    manifest = [
        OverrideEntry(override_rule="ov1", supersedes=["shared_vendor"]),
        OverrideEntry(override_rule="ov2", supersedes=["shared_vendor"]),
    ]
    with pytest.raises(PipelineError, match="failed validation"):
        check_overrides.validate(
            [make_rule("shared_vendor")], [ov1, ov2], manifest, _config(), tmp_path)


# --- stale checkpoint ------------------------------------------------------

def test_stale_override_blocks_without_decision(tmp_path):
    # 'ov' supersedes a vendor rule that isn't in the corpus, no decision recorded.
    ov = make_rule("ov", origin="overrides")
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_vendor"])]
    with pytest.raises(PipelineError, match="stale override checkpoint"):
        check_overrides.validate([], [ov], manifest, _config(), tmp_path)


def test_stale_override_unblocked_by_specific_keep(tmp_path):
    ov = make_rule("ov", origin="overrides")
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_vendor"])]
    _write_decisions(tmp_path / "stale_override_decisions.yaml", [
        {"override_rule": "ov", "missing_vendor_rule": "gone_vendor", "decision": "keep"},
    ])
    # returns None (no raise)
    assert check_overrides.validate([], [ov], manifest, _config(), tmp_path) is None


def test_stale_override_unblocked_by_wildcard_keep(tmp_path):
    # A decision entry with no missing_vendor_rule is a wildcard covering every
    # missing vendor id for that override rule.
    ov = make_rule("ov", origin="overrides")
    manifest = [OverrideEntry(override_rule="ov", supersedes=["gone_a", "gone_b"])]
    _write_decisions(tmp_path / "stale_override_decisions.yaml", [
        {"override_rule": "ov", "decision": "keep"},
    ])
    assert check_overrides.validate([], [ov], manifest, _config(), tmp_path) is None


# --- clean pass against the real corpus -----------------------------------

def test_real_corpus_and_manifest_pass(root):
    import config_schema
    import corpus
    config = config_schema.load_build_config(root)
    manifest = config_schema.load_override_manifest(root)
    c = corpus.load_corpus(root)
    assert check_overrides.validate(
        c.vendor_rules, c.override_rules, manifest, config, root) is None
