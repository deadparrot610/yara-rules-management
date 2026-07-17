#!/usr/bin/env python3
"""
Lint stage for the YARA rule pipeline.

Runs before the build as a fast, source-attributed gate (ARCHITECTURE.md §7):
  1. Per-file compile — isolated yara-python compile of each .yara file, so a
     syntax error is reported against its specific source file.
  2. plyara parseability — every file must parse (delegated to corpus.parse).
  3. Required metadata — custom/override rules must carry every field in
     config.required_meta (vendor rules are exempt).
  4. Module allowlist — every module import must appear in config.yara_modules
     (the deployment engine supports fewer modules than the compile gate).
  5. Naming conventions — rule identifiers must be well-formed.
  6. Filter policy — schema validity (via config_schema.load_filter_policy) plus
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
# 3. Module allowlist
# ---------------------------------------------------------------------------

def lint_modules(rules: list, allowed_modules: list, root: Path) -> list:
    """Report imports of modules absent from config.yara_modules.

    The deployment engine (D-1: Corelight — pe/elf/math) supports fewer modules
    than yara-python compiles, so the compile gate cannot catch these; the
    allowlist in config/build.yaml is authoritative (ARCHITECTURE.md §6).
    """
    allowed = set(allowed_modules)
    errors = []
    seen: set = set()  # (filepath, module) — imports repeat per rule in a file
    for rule in rules:
        for mod in rule.imports:
            key = (rule.filepath, mod)
            if mod in allowed or key in seen:
                continue
            seen.add(key)
            errors.append(
                f"{_rel(rule.filepath, root)}: imports module {mod!r} not in "
                f"config yara_modules {sorted(allowed)}"
            )
    return errors


# ---------------------------------------------------------------------------
# 4. Naming conventions
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
# 5. Filter policy corpus-aware warnings (schema itself validated at load)
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

    Warnings (absent filter selectors) are logged but never block. Config/policy
    schema failures surface as ConfigError from the load_* calls.
    """
    config = config_schema.load_build_config(root)
    policy = config_schema.load_filter_policy(root)
    corpus_data = corpus.load_corpus(root)

    rules = corpus_data.all_rules
    corpus_ids = {r.identifier for r in rules}

    errors = []
    errors += lint_syntax(root, corpus_ids, config.external_variables)
    errors += lint_metadata(rules, config.required_meta, root)
    errors += lint_modules(rules, config.yara_modules, root)
    errors += lint_naming(rules, root)

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
