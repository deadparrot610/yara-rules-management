"""Tests for the shared corpus primitives."""

import corpus
from config_schema import OverrideEntry
from conftest import make_rule


def test_discover_sources_finds_three_groups(root):
    vendor_paths, override_path, custom_paths = corpus.discover_sources(root)
    assert any(p.name == "test_vendor.yara" for p in vendor_paths)
    assert override_path.name == "overrides.yara"
    assert any(p.name == "example_malware.yara" for p in custom_paths)


def test_parse_yara_files_flattens_meta_and_keeps_raw(root):
    _, _, custom_paths = corpus.discover_sources(root)
    records = corpus.parse_yara_files(custom_paths, "custom")
    by_id = {r.identifier: r for r in records}
    rule = by_id["Custom_Example_Malware"]
    assert rule.origin == "custom"
    assert rule.meta["author"] == "fritz.s.cheung@gmail.com"
    assert rule.meta["severity"] == "high"
    # raw_text is the verbatim rule block
    assert rule.raw_text.lstrip().startswith("rule Custom_Example_Malware")
    assert "$example" in rule.raw_text


def test_load_corpus_counts(root):
    c = corpus.load_corpus(root)
    assert len(c.vendor_rules) == 24
    assert len(c.override_rules) == 1
    assert len(c.custom_rules) == 1
    assert len(c.all_rules) == 26


def test_strip_superseded_removes_declared_vendor_rule():
    vendor = [make_rule("vendor_override"), make_rule("keep_me")]
    manifest = [OverrideEntry(override_rule="ov", supersedes=["vendor_override"])]
    remaining, removed = corpus.strip_superseded(vendor, manifest)
    assert removed == ["vendor_override"]
    assert [r.identifier for r in remaining] == ["keep_me"]


def test_strip_superseded_ignores_absent_ids():
    # A manifest naming a vendor rule that isn't present leaves `removed` empty;
    # stale detection is check_overrides' job, not strip's.
    vendor = [make_rule("keep_me")]
    manifest = [OverrideEntry(override_rule="ov", supersedes=["ghost_rule"])]
    remaining, removed = corpus.strip_superseded(vendor, manifest)
    assert removed == []
    assert [r.identifier for r in remaining] == ["keep_me"]


def test_find_collision_returns_none_when_unique():
    rules = [make_rule("A"), make_rule("B"), make_rule("C")]
    assert corpus.find_collision(rules) is None


def test_find_collision_returns_prev_and_dup_in_order():
    first = make_rule("Dup", filepath=None)
    second = make_rule("Other")
    third = make_rule("Dup")
    prev, dup = corpus.find_collision([first, second, third])
    assert prev is first and dup is third


def test_module_offenders_flags_unlisted_only():
    from pathlib import Path
    a = make_rule("A", imports=["pe", "dotnet"], filepath=Path("f.yara"))
    offenders = corpus.module_offenders([a], ["pe", "elf", "math"])
    assert offenders == [(Path("f.yara"), "dotnet")]


def test_module_offenders_dedups_per_file_and_module():
    from pathlib import Path
    a = make_rule("A", imports=["dotnet"], filepath=Path("f.yara"))
    b = make_rule("B", imports=["dotnet"], filepath=Path("f.yara"))
    assert corpus.module_offenders([a, b], ["pe"]) == [(Path("f.yara"), "dotnet")]


def test_strip_superseded_against_real_manifest(root):
    c = corpus.load_corpus(root)
    manifest = [OverrideEntry(override_rule="vendor_override_overridden",
                              supersedes=["vendor_override"])]
    remaining, removed = corpus.strip_superseded(c.vendor_rules, manifest)
    assert removed == ["vendor_override"]
    assert "vendor_override" not in {r.identifier for r in remaining}
