"""End-to-end tests against the built dist/ artifacts.

These validate the emitted artifacts (as CI does: build once, then test), not a
re-build inline. The `built` session fixture performs the single build.
"""

import json

import build_ruleset
from conftest import ROOT


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


def test_manifest_has_provenance(built):
    _, manifest_path = built
    manifest = json.loads(manifest_path.read_text())
    assert manifest["source_hashes"], "expected non-empty source_hashes"
    assert "plyara" in manifest["tool_versions"]
    assert "yara-python" in manifest["tool_versions"]


def test_build_is_deterministic(built):
    # Rebuild and compare byte-for-byte against the fixture's output (NFR-6).
    merged, _ = built
    first = merged.read_bytes()
    build_ruleset._build(ROOT)
    assert merged.read_bytes() == first
