"""Tests for the shared corpus primitives."""

import corpus
from config_schema import MetaDateConfig, OverrideEntry
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


# --- meta date findings ----------------------------------------------------

def _meta_dates(*formats, fields=("date",), on_unparsable="fail"):
    return MetaDateConfig(
        fields=list(fields), input_formats=tuple(formats),
        on_unparsable=on_unparsable)


def test_meta_date_findings_records_only_non_iso():
    iso = make_rule("Iso", meta={"date": "2026-07-13"})
    other = make_rule("Other", meta={"date": "07/13/2026"})
    normalizations, offenders = corpus.meta_date_findings(
        [iso, other], _meta_dates("%m/%d/%Y"))
    assert offenders == []
    assert normalizations == [{
        "identifier": "Other", "field": "date", "raw": "07/13/2026",
        "normalized": "2026-07-13", "via": "%m/%d/%Y",
    }]


def test_meta_date_findings_skips_absent_field():
    rule = make_rule("NoDate", meta={"author": "x"})
    assert corpus.meta_date_findings([rule], _meta_dates()) == ([], [])


def test_meta_date_findings_reports_offender():
    rule = make_rule("Bad", meta={"date": "sometime in July"})
    normalizations, offenders = corpus.meta_date_findings([rule], _meta_dates())
    assert normalizations == []
    assert [(r.identifier, f, raw) for r, f, raw in offenders] == [
        ("Bad", "date", "sometime in July")]


def test_meta_date_findings_covers_every_configured_field():
    rule = make_rule("Two", meta={"date": "07/13/2026", "first_seen": "07/01/2026"})
    normalizations, _ = corpus.meta_date_findings(
        [rule], _meta_dates("%m/%d/%Y", fields=("date", "first_seen")))
    assert [n["field"] for n in normalizations] == ["date", "first_seen"]


def test_meta_date_findings_is_order_independent():
    # Identical input must produce identical output regardless of parse order
    # (NFR-6) — the manifest embeds this list.
    rules = [make_rule(i, meta={"date": "07/13/2026"}) for i in ("C", "A", "B")]
    spec = _meta_dates("%m/%d/%Y")
    forward, _ = corpus.meta_date_findings(rules, spec)
    reverse, _ = corpus.meta_date_findings(list(reversed(rules)), spec)
    assert [n["identifier"] for n in forward] == ["A", "B", "C"]
    assert forward == reverse


def test_meta_date_findings_empty_fields_is_a_noop():
    rule = make_rule("Bad", meta={"date": "sometime in July"})
    assert corpus.meta_date_findings([rule], MetaDateConfig()) == ([], [])


# --- drop_unparsable_dates -------------------------------------------------

def test_drop_removes_only_the_offenders_and_keeps_input_order():
    # Order is the caller's emission-order invariant; the drop must not perturb
    # what it leaves behind.
    rules = [
        make_rule("C", meta={"date": "2026-07-13"}),
        make_rule("Bad", meta={"date": "sometime in July"}),
        make_rule("A", meta={"date": "07/13/2026"}),
    ]
    kept, dropped = corpus.drop_unparsable_dates(rules, _meta_dates("%m/%d/%Y"))
    assert [r.identifier for r in kept] == ["C", "A"]
    assert [d["identifier"] for d in dropped] == ["Bad"]


def test_drop_record_matches_the_exclusion_record_shape():
    # Seeded straight into apply_filters' exclusion_record, so the keys must
    # line up exactly; filter_id is None because no filter is responsible.
    rule = make_rule("Bad", meta={"date": "sometime in July"})
    _, dropped = corpus.drop_unparsable_dates([rule], _meta_dates())
    assert set(dropped[0]) == {"identifier", "filter_id", "reason"}
    assert dropped[0]["filter_id"] is None
    assert "sometime in July" in dropped[0]["reason"]


def test_drop_yields_one_record_per_rule_naming_every_bad_field():
    rule = make_rule("Bad", meta={"date": "whenever", "first_seen": "also bad"})
    _, dropped = corpus.drop_unparsable_dates(
        [rule], _meta_dates(fields=("date", "first_seen")))
    assert len(dropped) == 1
    assert "date=" in dropped[0]["reason"]
    assert "first_seen=" in dropped[0]["reason"]


def test_drop_is_deterministic_across_input_order():
    rules = [make_rule(i, meta={"date": "whenever"}) for i in ("C", "A", "B")]
    spec = _meta_dates()
    _, forward = corpus.drop_unparsable_dates(rules, spec)
    _, reverse = corpus.drop_unparsable_dates(list(reversed(rules)), spec)
    assert [d["identifier"] for d in forward] == ["A", "B", "C"]
    assert forward == reverse


def test_drop_with_no_offenders_returns_everything():
    rules = [make_rule("A", meta={"date": "2026-07-13"})]
    kept, dropped = corpus.drop_unparsable_dates(rules, _meta_dates())
    assert [r.identifier for r in kept] == ["A"]
    assert dropped == []


def test_drop_empty_fields_is_a_noop():
    rule = make_rule("Bad", meta={"date": "sometime in July"})
    kept, dropped = corpus.drop_unparsable_dates([rule], MetaDateConfig())
    assert kept == [rule]
    assert dropped == []
