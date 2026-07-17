"""Tests for the lint stage (Phase 4): syntax, metadata, modules, naming, filter policy."""

from pathlib import Path

import pytest

import config_schema
import lint
from config_schema import FilterEntry, FilterMatch, FilterPolicy
from conftest import make_rule

# Pure metadata/naming checks only format paths; a fixed root keeps them off disk.
REPO = Path("/repo")

REQUIRED_META = ["author", "date", "description", "reference", "severity"]


def _full_meta(**overrides) -> dict:
    meta = {k: "x" for k in REQUIRED_META}
    meta.update(overrides)
    return meta


def _write_corpus(root, *, vendor=None, override=None, custom=None):
    """Materialise a minimal rule tree under `root` for discover_sources()."""
    (root / "rules" / "vendor").mkdir(parents=True)
    (root / "rules" / "overrides").mkdir(parents=True)
    (root / "rules" / "custom" / "malware").mkdir(parents=True)
    for name, text in (vendor or {}).items():
        (root / "rules" / "vendor" / f"{name}.yara").write_text(text)
    (root / "rules" / "overrides" / "overrides.yara").write_text(override or "")
    for name, text in (custom or {}).items():
        (root / "rules" / "custom" / "malware" / f"{name}.yara").write_text(text)


# --- metadata --------------------------------------------------------------

def test_custom_rule_missing_meta_field_errors():
    rule = make_rule("Custom_Rule", origin="custom", meta=_full_meta(severity=None))
    del rule.meta["severity"]
    errors = lint.lint_metadata([rule], REQUIRED_META, REPO)
    assert any("severity" in e for e in errors)


def test_compliant_custom_rule_passes_meta():
    rule = make_rule("Custom_Rule", origin="custom", meta=_full_meta())
    assert lint.lint_metadata([rule], REQUIRED_META, REPO) == []


def test_vendor_rule_exempt_from_meta():
    # A vendor rule with no in-house meta must not fail (vendor is exempt).
    rule = make_rule("vendor_rule", origin="vendor", meta={"description": "x"})
    assert lint.lint_metadata([rule], REQUIRED_META, REPO) == []


def test_override_rule_in_scope_for_meta():
    rule = make_rule("ov_rule", origin="overrides", meta={"description": "x"})
    errors = lint.lint_metadata([rule], REQUIRED_META, REPO)
    assert len(errors) == len(REQUIRED_META) - 1  # every field except description


# --- naming ----------------------------------------------------------------

@pytest.mark.parametrize("ident", ["bad__name", "trailing_", "9leading", "has space"])
def test_bad_identifiers_error(ident):
    rule = make_rule(ident, origin="custom")
    assert lint.lint_naming([rule], REPO) != []


@pytest.mark.parametrize("ident", ["Good_Name", "vendor_override", "Custom_Example_Malware", "a1_b2"])
def test_good_identifiers_pass(ident):
    rule = make_rule(ident, origin="custom")
    assert lint.lint_naming([rule], REPO) == []


# --- module allowlist ------------------------------------------------------

def test_unlisted_module_import_errors():
    rule = make_rule("uses_dotnet", origin="custom", imports=["dotnet"])
    errors = lint.lint_modules([rule], ["pe", "elf", "math"], REPO)
    assert len(errors) == 1
    assert "dotnet" in errors[0]


def test_allowed_module_imports_pass():
    rule = make_rule("uses_pe", origin="vendor", imports=["pe", "math"])
    assert lint.lint_modules([rule], ["pe", "elf", "math"], REPO) == []


def test_unlisted_module_reported_once_per_file():
    # plyara attributes file-level imports to every rule in the file; the error
    # must not repeat per rule.
    a = make_rule("A", origin="custom", imports=["dotnet"], filepath=Path("f.yara"))
    b = make_rule("B", origin="custom", imports=["dotnet"], filepath=Path("f.yara"))
    errors = lint.lint_modules([a, b], ["pe"], REPO)
    assert len(errors) == 1


# --- syntax (per-file compile) --------------------------------------------

def test_syntax_error_attributed_to_file(tmp_path):
    _write_corpus(tmp_path, custom={"broken": "rule broken { condition: }"})
    errors = lint.lint_syntax(tmp_path, corpus_ids=set(), externals={})
    assert len(errors) == 1
    assert "rules/custom/malware/broken.yara" in errors[0]
    assert "compilation failed" in errors[0]


def test_valid_files_have_no_syntax_errors(tmp_path):
    _write_corpus(tmp_path, custom={"ok": 'rule ok { strings: $a = "x" condition: $a }'})
    assert lint.lint_syntax(tmp_path, corpus_ids={"ok"}, externals={}) == []


def test_cross_file_reference_is_skipped(tmp_path):
    # custom rule references a rule defined in the vendor file (another file);
    # an isolated compile would raise 'undefined identifier', but the reference
    # is a real corpus identifier so it must be downgraded to a skip.
    _write_corpus(
        tmp_path,
        vendor={"base": 'rule base_rule { strings: $a = "x" condition: $a }'},
        custom={"dep": "rule dependent { condition: base_rule }"},
    )
    corpus_ids = {"base_rule", "dependent"}
    assert lint.lint_syntax(tmp_path, corpus_ids=corpus_ids, externals={}) == []


def test_unknown_reference_still_errors(tmp_path):
    # A reference to an identifier NOT in the corpus is a genuine error.
    _write_corpus(tmp_path, custom={"dep": "rule dependent { condition: ghost_rule }"})
    corpus_ids = {"dependent"}
    errors = lint.lint_syntax(tmp_path, corpus_ids=corpus_ids, externals={})
    assert len(errors) == 1
    assert "ghost_rule" in errors[0]


# --- filter policy corpus-aware warnings ----------------------------------

def test_rule_scope_absent_identifier_warns():
    policy = FilterPolicy(filters=[FilterEntry(action="exclude", scope="rule:Ghost", id="F-1")])
    warnings = lint.lint_filter_policy(policy, corpus_ids={"RealRule"})
    assert len(warnings) == 1
    assert "Ghost" in warnings[0]


def test_name_selector_absent_identifier_warns():
    policy = FilterPolicy(filters=[
        FilterEntry(action="exclude", scope="global",
                    match=FilterMatch(name="Ghost"), id="F-2"),
    ])
    warnings = lint.lint_filter_policy(policy, corpus_ids={"RealRule"})
    assert len(warnings) == 1
    assert "Ghost" in warnings[0]


def test_present_identifiers_no_warning():
    policy = FilterPolicy(filters=[
        FilterEntry(action="exclude", scope="rule:RealRule", id="F-3"),
        FilterEntry(action="include", scope="global",
                    match=FilterMatch(name="RealRule"), id="F-4"),
    ])
    assert lint.lint_filter_policy(policy, corpus_ids={"RealRule"}) == []


def test_malformed_filter_policy_raises_config_error(tmp_path):
    # A bad enum value is caught at load by config_schema (schema validation).
    (tmp_path / "filters").mkdir()
    (tmp_path / "filters" / "filter_policy.yaml").write_text(
        "default_mode: include_all\nfilters:\n  - action: nope\n"
    )
    with pytest.raises(config_schema.ConfigError, match="action"):
        config_schema.load_filter_policy(tmp_path)


# --- run_lint orchestration ------------------------------------------------

def test_real_corpus_passes(root):
    assert lint.run_lint(root) is None
