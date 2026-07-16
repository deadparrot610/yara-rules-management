"""Tests for build ordering, source emission, and error attribution."""

import pytest

import build_ruleset
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
