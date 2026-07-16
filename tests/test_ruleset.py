"""Scan-based ruleset test harness (Phase 5).

Compiles the built dist/ artifact and scans inert fixtures to prove the compiled
rules match — and don't match — the right files end to end. Unlike the unit tests
that exercise the pipeline scripts, this validates the *emitted ruleset's runtime
behavior*, mirroring CI (build once via the `built` session fixture, then scan).

Covers the Phase 5 done-criteria:
  (a) an overridden vendor rule no longer matches   -> test_expected_matches
  (b) a filtered-out rule no longer matches          -> test_filtered_rule_absent_and_no_match
  false-positive gate                                -> test_false_positive_gate
JUnit XML is emitted via --junitxml in pytest.ini.
"""

from pathlib import Path

import yaml
import pytest
import yara

import build_ruleset
from conftest import ROOT
from corpus import load_corpus, strip_superseded
from fixtures import INFRASTRUCTURE_RULES, write_fixtures
from config_schema import FilterEntry, FilterPolicy

TESTS_DIR = Path(__file__).resolve().parent


def _externals() -> dict:
    """Config-declared externals, coerced None->"" exactly as the build does."""
    ext = build_ruleset.load_config(ROOT).external_variables
    return {k: (v if v is not None else "") for k, v in ext.items()}


def _matches(rules: yara.Rules, path: Path) -> set:
    """Detection rules that fire on `path` (infrastructure globals excluded)."""
    externals = dict(_externals())
    externals.update(filename=path.name, filepath=str(path), filetype="")
    hits = {m.rule for m in rules.match(str(path), externals=externals)}
    return hits - set(INFRASTRUCTURE_RULES)


@pytest.fixture(scope="session")
def fixtures():
    """Materialize the inert fixtures once; yield (samples_dir, clean_dir)."""
    return write_fixtures(TESTS_DIR)


@pytest.fixture(scope="session")
def compiled(built):
    """Compile the built dist/ ruleset with the config-declared externals."""
    merged, _ = built
    return yara.compile(filepath=str(merged), externals=_externals())


def _load_cases() -> list:
    data = yaml.safe_load((TESTS_DIR / "test_cases.yaml").read_text())
    return data["cases"]


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["fixture"])
def test_expected_matches(case, compiled, fixtures):
    """Each case's expect_match must all fire and expect_no_match must all be absent.

    The override case (samples/override_synthetic.bin) is proof (a): the fixture
    carries a string that would match the superseded vendor rule, yet only the
    override fires because the vendor rule was stripped from the corpus.
    """
    path = TESTS_DIR / case["fixture"]
    matched = _matches(compiled, path)

    missing = set(case.get("expect_match", [])) - matched
    assert not missing, f"{case['fixture']}: expected matches absent: {sorted(missing)}"

    unexpected = set(case.get("expect_no_match", [])) & matched
    assert not unexpected, f"{case['fixture']}: forbidden matches present: {sorted(unexpected)}"


def _clean_files() -> list:
    _, clean = write_fixtures(TESTS_DIR)
    return sorted(p for p in clean.iterdir() if p.is_file() and not p.name.startswith("."))


@pytest.mark.parametrize("clean_path", _clean_files(), ids=lambda p: p.name)
def test_false_positive_gate(clean_path, compiled, fixtures):
    """No detection rule may fire on the benign corpus (infrastructure excluded)."""
    matched = _matches(compiled, clean_path)
    assert not matched, f"false-positive gate: {clean_path.name} matched {sorted(matched)}"


def _build_with_policy(policy: FilterPolicy) -> tuple:
    """Compile the corpus under a given filter policy (test-only, in-memory).

    Returns (compiled_rules, included_identifiers). Mirrors the build pipeline's
    strip -> filter -> emit -> compile sequence without touching disk or the
    shipped filter_policy.yaml.
    """
    config = build_ruleset.load_config(ROOT)
    manifest = build_ruleset.load_manifest(ROOT)
    corpus = load_corpus(ROOT)
    vendor_remainder, _ = strip_superseded(corpus.vendor_rules, manifest)
    included, _ = build_ruleset.apply_filters.run(
        vendor_remainder + corpus.override_rules + corpus.custom_rules,
        policy, ROOT, manifest, config,
    )
    imports: set = set()
    for rule in included:
        imports.update(rule.imports)
    source, _ = build_ruleset.build_source(build_ruleset.topological_order(included), imports)
    return yara.compile(source=source, externals=_externals()), {r.identifier for r in included}


def test_filtered_rule_absent_and_no_match(fixtures):
    """Proof (b): an excluded rule is gone from the output and no longer matches.

    Control + treatment against the same fixture: feature_xor fires under the
    default (empty) policy, and is both absent from the corpus and silent once a
    rule:feature_xor exclude filter is applied.
    """
    xor_fixture = TESTS_DIR / "samples" / "xor_synthetic.bin"

    full, full_ids = _build_with_policy(FilterPolicy())
    assert "feature_xor" in full_ids
    assert "feature_xor" in _matches(full, xor_fixture), "control: fixture should trip feature_xor"

    excluded_policy = FilterPolicy(
        filters=[FilterEntry(action="exclude", scope="rule:feature_xor", id="TEST-EXCLUDE")]
    )
    filtered, filtered_ids = _build_with_policy(excluded_policy)
    assert "feature_xor" not in filtered_ids, "filter should remove feature_xor from the corpus"
    assert "feature_xor" not in _matches(filtered, xor_fixture), "excluded rule must not match"
