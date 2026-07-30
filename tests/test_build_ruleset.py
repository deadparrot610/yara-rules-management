"""Tests for build ordering, source emission, and error attribution."""

import pytest

import build_ruleset
from config_schema import MetaDateConfig
from corpus import PipelineError
from conftest import make_rule


# --- topological ordering --------------------------------------------------

def test_dependency_precedes_dependent_same_group():
    # A references B, so B must be emitted first.
    a = make_rule("A", origin="vendor", condition_terms=["B"])
    b = make_rule("B", origin="vendor")
    ordered = build_ruleset.topological_order([a, b])
    ids = [r.identifier for r in ordered]
    assert ids.index("B") < ids.index("A")


def test_independent_rules_preserve_input_order():
    a = make_rule("A", origin="vendor")
    b = make_rule("B", origin="vendor")
    ordered = build_ruleset.topological_order([a, b])
    assert [r.identifier for r in ordered] == ["A", "B"]


def test_cross_group_reference_overrides_default_group_order():
    # Default group order is vendor → custom, but the vendor rule references a
    # custom rule, so the custom rule must be reordered ahead of it.
    v = make_rule("V", origin="vendor", condition_terms=["C"])
    c = make_rule("C", origin="custom")
    ordered = build_ruleset.topological_order([v, c])
    ids = [r.identifier for r in ordered]
    assert ids.index("C") < ids.index("V")


def test_cycle_raises():
    a = make_rule("A", origin="vendor", condition_terms=["B"])
    b = make_rule("B", origin="vendor", condition_terms=["A"])
    with pytest.raises(PipelineError, match="cycle detected"):
        build_ruleset.topological_order([a, b])


# --- source emission + error attribution ----------------------------------

def test_build_source_and_locate_rule():
    a = make_rule("A", origin="vendor",
                  raw_text="rule A {\n\tcondition:\n\t\ttrue\n}")
    b = make_rule("B", origin="vendor",
                  raw_text="rule B {\n\tcondition:\n\t\ttrue\n}")
    source, index = build_ruleset.build_source([a, b], set())

    assert source.startswith("rule A")
    # A occupies lines 1-4; a blank line follows; B starts at line 6.
    assert build_ruleset._locate_rule(index, 1).identifier == "A"
    assert build_ruleset._locate_rule(index, 4).identifier == "A"
    assert build_ruleset._locate_rule(index, 6).identifier == "B"


def test_build_source_emits_sorted_imports_once():
    a = make_rule("A", origin="vendor", imports=["pe"],
                  raw_text="rule A {\n\tcondition:\n\t\ttrue\n}")
    source, index = build_ruleset.build_source([a], {"pe", "elf"})
    # imports are sorted and precede rules; each appears once.
    assert source.count('import "pe"') == 1
    assert source.index('import "elf"') < source.index('import "pe"') < source.index("rule A")
    # rule index accounts for the import + blank line offset.
    assert build_ruleset._locate_rule(index, index[0][0]).identifier == "A"


# --- collision check -------------------------------------------------------

def test_check_collisions_raises_on_duplicate():
    a1 = make_rule("Dup", origin="vendor")
    a2 = make_rule("Dup", origin="custom")
    with pytest.raises(PipelineError, match="duplicate identifier"):
        build_ruleset.check_collisions([a1, a2])


# --- config enforcement (module allowlist, output formats) -----------------

def test_check_modules_accepts_allowed_imports():
    r = make_rule("A", origin="vendor", imports=["pe", "math"])
    build_ruleset.check_modules([r], ["pe", "elf", "math"])  # no raise


def test_check_modules_rejects_unlisted_module():
    # yara-python would compile dotnet fine; only the allowlist catches it (D-1).
    r = make_rule("A", origin="custom", imports=["dotnet"])
    with pytest.raises(PipelineError, match="dotnet"):
        build_ruleset.check_modules([r], ["pe", "elf", "math"])


# --- unparsable-date gate --------------------------------------------------

def _dates(*formats, on_unparsable="fail"):
    return MetaDateConfig(fields=["date"], input_formats=tuple(formats),
                          on_unparsable=on_unparsable)


def test_check_dates_fail_mode_raises_naming_every_offender():
    rules = [
        make_rule("Good", origin="vendor", meta={"date": "2026-07-13"}),
        make_rule("Bad1", origin="vendor", meta={"date": "whenever"}),
        make_rule("Bad2", origin="vendor", meta={"date": "July 2026"}),
    ]
    with pytest.raises(PipelineError, match="unreadable rule date") as exc:
        build_ruleset.check_dates(rules, _dates("%m/%d/%Y"))
    assert "Bad1" in str(exc.value)
    assert "Bad2" in str(exc.value)
    # The fix is one line of config, so the message has to name the key.
    assert "meta_dates.input_formats" in str(exc.value)


def test_check_dates_fail_mode_passes_the_corpus_through_unchanged():
    rules = [make_rule("Good", origin="vendor", meta={"date": "07/13/2026"})]
    kept, dropped = build_ruleset.check_dates(rules, _dates("%m/%d/%Y"))
    assert kept == rules
    assert dropped == []


def test_check_dates_warn_and_drop_removes_offenders():
    rules = [
        make_rule("Good", origin="vendor", meta={"date": "2026-07-13"}),
        make_rule("Bad", origin="vendor", meta={"date": "whenever"}),
    ]
    kept, dropped = build_ruleset.check_dates(
        rules, _dates("%m/%d/%Y", on_unparsable="warn_and_drop"))
    assert [r.identifier for r in kept] == ["Good"]
    assert [d["identifier"] for d in dropped] == ["Bad"]


def test_check_dates_warn_and_drop_never_raises():
    rules = [make_rule("Bad", origin="vendor", meta={"date": "whenever"})]
    kept, dropped = build_ruleset.check_dates(
        rules, _dates(on_unparsable="warn_and_drop"))
    assert kept == []
    assert len(dropped) == 1


def test_check_dates_disabled_config_is_a_noop_in_both_modes():
    rules = [make_rule("Bad", origin="vendor", meta={"date": "whenever"})]
    for mode in ("fail", "warn_and_drop"):
        kept, dropped = build_ruleset.check_dates(
            rules, MetaDateConfig(on_unparsable=mode))
        assert kept == rules
        assert dropped == []


def test_check_output_formats_source_only():
    build_ruleset.check_output_formats(["source"])  # no raise
    with pytest.raises(PipelineError, match="unsupported output_formats"):
        build_ruleset.check_output_formats(["source", "compiled"])


# --- compile validation gate + error attribution ---------------------------

def test_compile_rules_accepts_valid_source():
    a = make_rule("Ok", origin="vendor",
                  raw_text="rule Ok {\n\tcondition:\n\t\ttrue\n}")
    source, index = build_ruleset.build_source([a], set())
    build_ruleset.compile_rules(source, {}, index)  # no raise


def test_compile_rules_attributes_error_to_rule_and_file():
    # A rule whose condition references an undefined string fails to compile;
    # the PipelineError should name the offending rule and its source file.
    from pathlib import Path
    bad = make_rule("Broken", origin="vendor",
                    raw_text="rule Broken {\n\tcondition:\n\t\t$undefined\n}",
                    filepath=Path("rules/vendor/bad.yara"))
    source, index = build_ruleset.build_source([bad], set())
    with pytest.raises(PipelineError, match="Broken") as exc:
        build_ruleset.compile_rules(source, {}, index)
    assert "compilation failed" in str(exc.value)
