#!/usr/bin/env python3
"""
Lint stage for the YARA rule pipeline.

Runs before the build as a fast, source-attributed gate (ARCHITECTURE.md §7):
  1. Per-file compile — isolated yara-python compile of each .yara file, so a
     syntax error is reported against its specific source file.
  2. plyara parseability — every file must parse (delegated to corpus.parse).
  3. Required metadata — custom/override rules must carry every field in
     config.required_meta (vendor rules are exempt).
  4. Date meta fields — every field in config.meta_dates.fields, on every rule
     that carries it, must be readable as a date (all origins, vendor included).
     Reported as errors or as warnings per config.meta_dates.on_unparsable, so
     lint never blocks on something the build is configured to drop and continue.
  5. Module allowlist — every module import must appear in config.yara_modules
     (the deployment engine supports fewer modules than the compile gate).
  6. Naming conventions — rule identifiers must be well-formed.
  7. Filter policy — schema validity (via config_schema.load_filter_policy) plus
     a corpus-aware warning when a rule:/name selector names an absent identifier.

Standalone:  python scripts/lint.py
Importable:  lint.run_lint(root)  (raises PipelineError on any error)
"""

import argparse
import re
import sys
from pathlib import Path

import yara
from loguru import logger

import config_schema
import corpus
from config_schema import ConfigError
from corpus import PipelineError
from logging_setup import setup_logging

# Minimal identifier convention (D: minimal built-in check). plyara already
# guarantees a syntactically valid identifier; these rules add house style.
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

# yara-python renders an unresolved rule reference as: undefined identifier "name"
_UNDEFINED_ID_RE = re.compile(r'undefined identifier "([^"]+)"')

# Origins whose rules must satisfy required_meta (vendor rules are committed as
# received and exempt — see CLAUDE.md "Required metadata fields").
_META_ORIGINS = ("custom", "overrides")


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# 1. Per-file compile (source-attributed syntax check)
# ---------------------------------------------------------------------------

def lint_syntax(root: Path, corpus_ids: set, externals: dict) -> list:
    """Compile each .yara file in isolation; return a list of error messages.

    A custom/override rule may legitimately reference a rule defined in another
    file. An isolated compile raises 'undefined identifier' for such a reference;
    when the named identifier exists elsewhere in the corpus we downgrade to a
    skip, since the build's whole-corpus compile is the authoritative gate.
    """
    vendor_paths, override_path, custom_paths = corpus.discover_sources(root)
    coerced = {k: (v if v is not None else "") for k, v in externals.items()}

    errors = []
    for path in [*vendor_paths, override_path, *custom_paths]:
        if not path.exists() or path.stat().st_size == 0:
            continue
        source = path.read_text()
        try:
            yara.compile(source=source, externals=coerced)
        except yara.SyntaxError as exc:
            msg = str(exc)
            m = _UNDEFINED_ID_RE.search(msg)
            if m and m.group(1) in corpus_ids:
                logger.debug(
                    "{}: skipping cross-file reference to {!r} (validated by the "
                    "whole-corpus compile)", _rel(path, root), m.group(1),
                )
                continue
            errors.append(f"{_rel(path, root)}: YARA compilation failed: {msg}")
        except Exception as exc:
            errors.append(f"{_rel(path, root)}: unexpected compilation error: {exc}")
    return errors


# ---------------------------------------------------------------------------
# 2. Required metadata
# ---------------------------------------------------------------------------

def lint_metadata(rules: list, required_meta: list, root: Path) -> list:
    """Report custom/override rules missing any field named in required_meta."""
    errors = []
    for rule in rules:
        if rule.origin not in _META_ORIGINS:
            continue
        for key in required_meta:
            if key not in rule.meta:
                errors.append(
                    f"{_rel(rule.filepath, root)}: rule {rule.identifier!r} "
                    f"missing required meta field {key!r}"
                )
    return errors


# ---------------------------------------------------------------------------
# 3. Date-valued meta fields
# ---------------------------------------------------------------------------

def lint_dates(rules: list, meta_dates, root: Path) -> tuple[list, list]:
    """Report date meta fields that no configured input format can read.

    Returns (errors, warnings): the findings land in exactly one of the two,
    chosen by meta_dates.on_unparsable. Under 'fail' they block, matching the
    build gate; under 'warn_and_drop' they are warnings that also name the
    consequence, since blocking here on a value the build is configured to drop
    would make lint stricter than the policy it reports on.

    ALL origins are in scope, vendor included — deliberately not _META_ORIGINS.
    That exemption is about *completeness*: we cannot demand a feed committed as
    received carry every required_meta field. This check makes no such demand, it
    fires only when the field is PRESENT and unreadable, so exempting vendor
    would exempt the only source the check exists for.

    Catching this here rather than in the filter engine matters: apply_filters
    parses a rule date only when a meta_date selector is active, so with no such
    filter in policy an unreadable date would otherwise go entirely unnoticed
    until the day someone writes one.
    """
    offenders = corpus.meta_date_offenders(rules, meta_dates)
    accepted = config_schema.describe_accepted_dates(meta_dates)
    dropping = meta_dates.on_unparsable == "warn_and_drop"
    consequence = " — the build will drop this rule" if dropping else ""
    findings = []
    for rule, field_name, raw in offenders:
        loc = _rel(rule.filepath, root)
        if not isinstance(raw, (str, int)) or isinstance(raw, bool):
            findings.append(
                f"{loc}: rule {rule.identifier!r} meta field {field_name!r} has "
                f"type {type(raw).__name__}, expected a date string{consequence}"
            )
            continue
        findings.append(
            f"{loc}: rule {rule.identifier!r} meta field {field_name!r} value "
            f"{raw!r} is not a recognized date; {accepted} "
            f"(config/build.yaml meta_dates.input_formats){consequence}"
        )
    return ([], findings) if dropping else (findings, [])


# ---------------------------------------------------------------------------
# 4. Module allowlist
# ---------------------------------------------------------------------------

def lint_modules(rules: list, allowed_modules: list, root: Path) -> list:
    """Report imports of modules absent from config.yara_modules.

    The deployment engine (D-1: Corelight — pe/elf/math) supports fewer modules
    than yara-python compiles, so the compile gate cannot catch these; the
    allowlist in config/build.yaml is authoritative (ARCHITECTURE.md §6). Offender
    detection is shared with the build gate (corpus.module_offenders).
    """
    allowed = sorted(set(allowed_modules))
    return [
        f"{_rel(path, root)}: imports module {mod!r} not in "
        f"config yara_modules {allowed}"
        for path, mod in corpus.module_offenders(rules, allowed_modules)
    ]


# ---------------------------------------------------------------------------
# Identifier collisions
# ---------------------------------------------------------------------------

def lint_collisions(post_strip: list, root: Path) -> list:
    """Report a duplicate identifier in the post-strip corpus (shared with build).

    Run on the post-strip corpus so an override that reuses a superseded vendor
    identifier is not a false positive; catching it here surfaces the defect at
    the fast lint gate instead of only at the slower build compile.
    """
    collision = corpus.find_collision(post_strip)
    if collision is None:
        return []
    prev, dup = collision
    return [
        f"{_rel(dup.filepath, root)}: duplicate identifier {dup.identifier!r} "
        f"(also in {_rel(prev.filepath, root)})"
    ]


# ---------------------------------------------------------------------------
# 6. Naming conventions
# ---------------------------------------------------------------------------

def lint_naming(rules: list, root: Path) -> list:
    """Enforce the minimal identifier convention on every rule."""
    errors = []
    for rule in rules:
        ident = rule.identifier
        loc = _rel(rule.filepath, root)
        if not _NAME_RE.match(ident):
            errors.append(
                f"{loc}: rule {ident!r} is not a valid identifier "
                f"(must match {_NAME_RE.pattern})"
            )
            continue
        if "__" in ident:
            errors.append(
                f"{loc}: rule {ident!r} contains a double underscore"
            )
        if ident.endswith("_"):
            errors.append(
                f"{loc}: rule {ident!r} has a trailing underscore"
            )
    return errors


# ---------------------------------------------------------------------------
# 7. Filter policy corpus-aware warnings (schema itself validated at load)
# ---------------------------------------------------------------------------

def lint_filter_policy(policy, corpus_ids: set) -> list:
    """Return warnings for filters naming an identifier absent from the corpus.

    A rule: scope or an exact name selector that references a rule not present in
    the corpus matches nothing — usually a typo or a rule that was removed. This
    is a warning, not an error (the policy is still well-formed). Schema validity
    is already enforced by config_schema.load_filter_policy.
    """
    warnings = []
    for i, f in enumerate(policy.filters):
        fid = f.id or f"filters[{i}]"
        if f.scope.startswith("rule:"):
            ident = f.scope[len("rule:"):]
            if ident not in corpus_ids:
                warnings.append(
                    f"filter {fid}: scope 'rule:{ident}' names identifier {ident!r} "
                    f"not present in the corpus"
                )
        if f.match is not None and f.match.name is not None:
            if f.match.name not in corpus_ids:
                warnings.append(
                    f"filter {fid}: selector name {f.match.name!r} "
                    f"not present in the corpus"
                )
    return warnings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_lint(root: Path) -> None:
    """Run every lint check. Raises PipelineError if any error is found.

    Warnings (absent filter selectors, and unreadable dates under
    on_unparsable: warn_and_drop) are logged but never block. Config/policy
    schema failures surface as ConfigError from the load_* calls.
    """
    config = config_schema.load_build_config(root)
    policy = config_schema.load_filter_policy(root)
    manifest_entries = config_schema.load_override_manifest(root)
    corpus_data = corpus.load_corpus(root)

    rules = corpus_data.all_rules
    corpus_ids = {r.identifier for r in rules}

    # Collisions are checked on the post-strip corpus (build's collision gate),
    # so an override reusing a superseded vendor identifier is not a false positive.
    vendor_remainder, _ = corpus.strip_superseded(corpus_data.vendor_rules, manifest_entries)
    post_strip = vendor_remainder + corpus_data.override_rules + corpus_data.custom_rules

    date_errors, date_warnings = lint_dates(rules, config.meta_dates, root)

    errors = []
    errors += lint_syntax(root, corpus_ids, config.external_variables)
    errors += lint_metadata(rules, config.required_meta, root)
    errors += date_errors
    errors += lint_modules(rules, config.yara_modules, root)
    errors += lint_collisions(post_strip, root)
    errors += lint_naming(rules, root)

    for w in date_warnings:
        logger.warning(w)
    for w in lint_filter_policy(policy, corpus_ids):
        logger.warning(w)

    if errors:
        for e in errors:
            logger.error(e)
        raise PipelineError(f"lint failed ({len(errors)} error(s))")


def main() -> None:
    argparse.ArgumentParser(
        description="Lint the YARA rule sources and the filter policy."
    ).parse_args()
    setup_logging()

    root = Path(__file__).resolve().parent.parent

    try:
        run_lint(root)
    except (ConfigError, PipelineError) as exc:
        logger.error("Lint failed: {}", exc)
        sys.exit(1)

    logger.success("Lint OK.")


if __name__ == "__main__":
    main()
