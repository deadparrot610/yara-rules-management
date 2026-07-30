"""End-to-end tests against the built dist/ artifacts.

These validate the emitted artifacts (as CI does: build once, then test), not a
re-build inline. The `built` session fixture performs the single build.
"""

import json

import pytest

import build_ruleset
from conftest import ROOT


@pytest.fixture
def preserve_dist(built):
    """Snapshot dist/ and restore it after a test that runs its own build.

    Tests exercising build() itself overwrite the artifacts the rest of the
    suite must keep validating (CLAUDE.md: test the built artifacts, not a
    rebuild); this puts the originals back.
    """
    merged, manifest = built
    saved = (merged.read_bytes(), manifest.read_bytes())
    yield
    merged.write_bytes(saved[0])
    manifest.write_bytes(saved[1])


def test_merged_source_exists_and_nonempty(built):
    merged, _ = built
    assert merged.exists()
    assert merged.stat().st_size > 0


def test_superseded_vendor_rule_absent_override_present(built):
    merged, _ = built
    text = merged.read_text()
    assert "rule vendor_override_overridden" in text
    # the superseded vendor rule must not appear as a standalone declaration
    assert "rule vendor_override\n" not in text
    assert "rule vendor_override " not in text


def test_manifest_counts_and_removals(built):
    _, manifest_path = built
    manifest = json.loads(manifest_path.read_text())
    assert manifest["rule_counts"]["total"] == 25
    assert manifest["rule_counts"]["vendor"] == 23
    assert manifest["rule_counts"]["overrides"] == 1
    assert manifest["rule_counts"]["custom"] == 1
    assert manifest["removed_vendor_rules"] == ["vendor_override"]


def test_manifest_omits_meta_date_normalizations(built):
    _, manifest_path = built
    manifest = json.loads(manifest_path.read_text())
    # Reinterpreted dates are advisory and go to the build log only — one entry
    # per rule per date field would swamp the manifest for no consumer's benefit.
    assert "meta_date_normalizations" not in manifest


def test_manifest_records_dropped_unparsable_dates(built):
    _, manifest_path = built
    manifest = json.loads(manifest_path.read_text())
    # Also unconditional, and always empty under on_unparsable: fail — that mode
    # raises rather than dropping. The shipped config is 'fail'.
    assert manifest["dropped_unparsable_dates"] == []


def test_manifest_has_provenance(built):
    _, manifest_path = built
    manifest = json.loads(manifest_path.read_text())
    assert manifest["source_hashes"], "expected non-empty source_hashes"
    assert "plyara" in manifest["tool_versions"]
    assert "yara-python" in manifest["tool_versions"]


def test_build_version_defaults_to_dev_sentinel(built, monkeypatch, preserve_dist):
    # Without a release tag in the environment, the manifest carries the dev sentinel.
    monkeypatch.delenv("CI_COMMIT_TAG", raising=False)
    build_ruleset.build(ROOT)
    _, manifest_path = built
    manifest = json.loads(manifest_path.read_text())
    assert manifest["build_version"] == "0.0.0-dev"


def test_build_version_from_tag(built, monkeypatch, preserve_dist):
    # On a release build, build_version reflects the git tag ($CI_COMMIT_TAG).
    monkeypatch.setenv("CI_COMMIT_TAG", "v1.2.3")
    build_ruleset.build(ROOT)
    _, manifest_path = built
    manifest = json.loads(manifest_path.read_text())
    assert manifest["build_version"] == "v1.2.3"


def test_referenced_rule_precedes_dependent_in_output(built):
    # feature_rule_dependency's condition references the private rule
    # base_has_marker; the ordering invariant requires the referenced rule to be
    # emitted first. Same for the chain_level_b → feature_chain_level_c pair.
    merged, _ = built
    text = merged.read_text()
    for dep, dependent in [
        ("base_has_marker", "feature_rule_dependency"),
        ("chain_level_b", "feature_chain_level_c"),
    ]:
        i_dep = text.index(f"rule {dep} ")
        i_dependent = text.index(f"rule {dependent} ")
        assert i_dep < i_dependent, f"{dep} must precede {dependent}"


def test_build_is_deterministic(built):
    # Rebuild and compare byte-for-byte against the fixture's output (NFR-6).
    merged, _ = built
    first = merged.read_bytes()
    build_ruleset.build(ROOT)
    assert merged.read_bytes() == first
