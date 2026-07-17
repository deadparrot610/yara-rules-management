#!/usr/bin/env python3
"""
Build the merged YARA ruleset.

Build sequence: parse → validate overrides (check_overrides) → strip superseded
vendor rules → collision check → apply filter policy (apply_filters) →
topological order → compile (validation gate) → emit source → write manifest.
"""

import os
import re
import sys
import json
import bisect
import heapq
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path

import plyara
import yara
from loguru import logger

import config_schema
import check_overrides
import apply_filters
from config_schema import ConfigError
from corpus import (
    PipelineError, RuleRecord, strip_superseded, load_corpus,
    find_collision, module_offenders,
)
from logging_setup import setup_logging

ROOT = Path(__file__).resolve().parent.parent

GROUP_ORDER = {"vendor": 0, "overrides": 1, "custom": 2}


# ---------------------------------------------------------------------------
# Config / manifest loading
# ---------------------------------------------------------------------------

def load_config(root: Path):
    """Return the validated BuildConfig (see config_schema)."""
    return config_schema.load_build_config(root)


def load_manifest(root: Path) -> list[config_schema.OverrideEntry]:
    """Return the validated override manifest as a list of OverrideEntry."""
    return config_schema.load_override_manifest(root)


def load_filter_policy(root: Path):
    """Return the validated FilterPolicy (see config_schema)."""
    return config_schema.load_filter_policy(root)


# ---------------------------------------------------------------------------
# Collision check
# ---------------------------------------------------------------------------

def check_collisions(rules: list[RuleRecord]) -> None:
    """Hard-error on duplicate identifiers in the merged corpus.

    Runs on the post-strip corpus *before* filtering: a duplicate identifier is a
    source defect (and makes identifier-keyed filter resolution ambiguous), so it
    must fail even when a filter would exclude one of the copies. Detection logic
    lives in corpus.find_collision so the lint gate shares it.
    """
    collision = find_collision(rules)
    if collision is not None:
        prev, dup = collision
        raise PipelineError(
            f"duplicate identifier {dup.identifier!r} "
            f"in {dup.filepath} and {prev.filepath}"
        )


# ---------------------------------------------------------------------------
# Config enforcement (yara_modules allowlist, output_formats)
# ---------------------------------------------------------------------------

def check_modules(rules: list[RuleRecord], allowed_modules: list[str]) -> None:
    """Hard-error on any module import outside config.yara_modules.

    yara-python compiles more modules than the deployment engine supports
    (D-1: Corelight ships pe/elf/math), so the compile gate cannot catch an
    unsupported import — this allowlist is the only guard. Offender detection
    lives in corpus.module_offenders so the lint gate shares it.
    """
    by_module: dict[str, set[str]] = {}
    for path, mod in module_offenders(rules, allowed_modules):
        by_module.setdefault(mod, set()).add(str(path))
    if by_module:
        details = "; ".join(
            f"module {mod!r} imported in {', '.join(sorted(paths))}"
            for mod, paths in sorted(by_module.items())
        )
        raise PipelineError(
            f"module(s) not in config yara_modules {sorted(allowed_modules)}: {details}"
        )


def check_output_formats(output_formats: list[str]) -> None:
    """Reject output formats the pipeline does not implement (D-2: source only)."""
    unsupported = [f for f in output_formats if f != "source"]
    if unsupported:
        raise PipelineError(
            f"unsupported output_formats {unsupported}: only 'source' is "
            f"implemented (D-2; Corelight compiles internally)"
        )


# ---------------------------------------------------------------------------
# Topological ordering
# ---------------------------------------------------------------------------

def topological_order(rules: list[RuleRecord]) -> list[RuleRecord]:
    """Return rules ordered so every dependency precedes its dependent.

    Default group order: vendor → overrides → custom.
    Within each group, input (filesystem-sorted) order is preserved for
    determinism (NFR-6). Cross-group intra-corpus references trigger
    topological adjustment. A cycle is a hard error.
    """
    known = {r.identifier for r in rules}
    rule_map = {r.identifier: r for r in rules}

    deps = {
        r.identifier: {t for t in r.condition_terms if t in known and t != r.identifier}
        for r in rules
    }

    in_degree = {r.identifier: 0 for r in rules}
    dependents = {r.identifier: [] for r in rules}
    for rid, dep_set in deps.items():
        for dep in dep_set:
            in_degree[rid] += 1
            dependents[dep].append(rid)

    # (group_order, input_position, identifier) — input_position is unique so
    # string comparison is never reached; it only exists to keep heapq safe.
    heap_key = {
        r.identifier: (GROUP_ORDER.get(r.origin, 99), i, r.identifier)
        for i, r in enumerate(rules)
    }

    heap = [heap_key[r.identifier] for r in rules if in_degree[r.identifier] == 0]
    heapq.heapify(heap)

    ordered = []
    while heap:
        *_, rid = heapq.heappop(heap)
        ordered.append(rule_map[rid])
        for dep in dependents[rid]:
            in_degree[dep] -= 1
            if in_degree[dep] == 0:
                heapq.heappush(heap, heap_key[dep])

    if len(ordered) != len(rules):
        processed = {r.identifier for r in ordered}
        cycle_ids = [r.identifier for r in rules if r.identifier not in processed]
        raise PipelineError(f"cycle detected among rules: {cycle_ids}")

    return ordered


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

def build_source(
    rules: list[RuleRecord], all_imports: set[str],
) -> tuple[str, list[tuple[int, RuleRecord]]]:
    """Assemble the merged source as a string (does not touch disk).

    Returns (source_str, rule_index) where rule_index is a list of
    (start_lineno, RuleRecord) pairs used to attribute compile errors back to
    the original source file and rule identifier.
    """
    parts = []
    lineno = 1
    for imp in sorted(all_imports):
        parts.append(f'import "{imp}"\n')
        lineno += 1
    if all_imports:
        parts.append("\n")
        lineno += 1
    index: list[tuple[int, RuleRecord]] = []
    for rule in rules:
        index.append((lineno, rule))
        stripped = rule.raw_text.rstrip()
        parts.append(stripped)
        parts.append("\n\n")
        lineno += stripped.count("\n") + 2  # content lines + \n\n separator
    return "".join(parts), index


def _locate_rule(index: list[tuple[int, RuleRecord]], lineno: int) -> RuleRecord | None:
    """Return the RuleRecord whose block contains lineno, or None."""
    if not index:
        return None
    starts = [s for s, _ in index]
    pos = bisect.bisect_right(starts, lineno) - 1
    return index[pos][1] if pos >= 0 else None


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def compile_rules(
    source: str,
    externals: dict[str, str],
    rule_index: list[tuple[int, RuleRecord]] | None = None,
) -> None:
    """Compile via yara-python as the authoritative validation gate.

    Takes the merged source string directly so no unvalidated file is
    written to disk before this gate passes.  Non-negotiable even when
    only source output is requested.
    """
    # config_schema already forces every external to a string; this None-guard only
    # matters if compile_rules is called directly with a hand-built externals dict.
    coerced = {k: (v if v is not None else "") for k, v in externals.items()}
    try:
        yara.compile(source=source, externals=coerced)
    except yara.SyntaxError as exc:
        msg = str(exc)
        annotation = ""
        if rule_index:
            m = re.search(r"\bline (\d+)", msg)
            if m:
                record = _locate_rule(rule_index, int(m.group(1)))
                if record:
                    try:
                        rel = record.filepath.relative_to(ROOT)
                    except ValueError:
                        rel = record.filepath
                    annotation = f" (rule '{record.identifier}' in {rel})"
        raise PipelineError(f"YARA compilation failed{annotation}: {msg}") from exc
    except Exception as exc:
        raise PipelineError(f"unexpected compilation error: {exc}") from exc


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(
    rules: list[RuleRecord],
    removed_ids: list[str],
    exclusion_record: list[dict],
    source_files: list[Path],
    dest: Path,
) -> None:
    counts = {origin: sum(1 for r in rules if r.origin == origin)
              for origin in ("vendor", "custom", "overrides")}

    manifest = {
        # Releases are versioned by the git tag ($CI_COMMIT_TAG); non-tag builds
        # (branches, MRs, local) carry a dev sentinel so the field is always present.
        "build_version": os.environ.get("CI_COMMIT_TAG") or "0.0.0-dev",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_versions": {
            "plyara": getattr(plyara, "__version__", "unknown"),
            "yara-python": getattr(yara, "__version__", "unknown"),
        },
        "rule_counts": {
            "total": len(rules),
            "vendor": counts["vendor"],
            "custom": counts["custom"],
            "overrides": counts["overrides"],
        },
        "removed_vendor_rules": removed_ids,
        "filtered_rules": exclusion_record,
        "source_hashes": {
            str(p.relative_to(dest.parent.parent)): _sha256(p)
            for p in source_files
            if p.exists() and p.stat().st_size > 0
        },
    }
    dest.parent.mkdir(exist_ok=True)
    with dest.open("w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build(root: Path) -> tuple[list[RuleRecord], list[str], list[dict], Path]:
    """Run the full pipeline. Returns (ordered, removed_ids, exclusion_record, output_path).

    Raises ConfigError / PipelineError on any failure; the CLI boundary (main) turns
    those into an ERROR message and exit 1. Public entry point — the test harness
    uses it as a local fallback when no pre-built dist/ artifacts exist.
    """
    config = load_config(root)
    manifest_entries = load_manifest(root)
    filter_policy = load_filter_policy(root)

    check_output_formats(config.output_formats)

    # --- Parse ---
    corpus_data = load_corpus(root)
    logger.info(
        "Parsed {} rules ({} vendor, {} overrides, {} custom)",
        len(corpus_data.all_rules),
        len(corpus_data.vendor_rules), len(corpus_data.override_rules),
        len(corpus_data.custom_rules),
    )

    # --- Phase 2: stale-override validation ---
    logger.debug("Validating override manifest")
    check_overrides.validate(
        corpus_data.vendor_rules, corpus_data.override_rules,
        manifest_entries, config, root,
    )

    # --- Strip superseded vendor rules ---
    vendor_remainder, removed_ids = strip_superseded(corpus_data.vendor_rules, manifest_entries)

    # --- Collision check (pre-filter: a duplicate is a source defect even if a
    # filter would exclude one copy, and dup identifiers make filter resolution
    # ambiguous) ---
    post_strip = vendor_remainder + corpus_data.override_rules + corpus_data.custom_rules
    check_collisions(post_strip)

    # --- Module allowlist (deployment engine supports fewer modules than the
    # compile gate; checked pre-filter so an unsupported import never lingers) ---
    check_modules(post_strip, config.yara_modules)

    # --- Phase 3: filter policy ---
    included_rules, exclusion_record = apply_filters.run(
        post_strip,
        filter_policy,
        root,
        manifest_entries,
        config,
    )

    # --- Topological order ---
    ordered = topological_order(included_rules)

    # --- Collect imports ---
    all_imports: set[str] = set()
    for rule in ordered:
        all_imports.update(rule.imports)

    # --- Build source string ---
    merged_source, rule_index = build_source(ordered, all_imports)

    # --- Compile (authoritative validation gate) ---
    # Runs against the in-memory string so no unvalidated file is written first.
    logger.debug("Compiling {} rules (validation gate)", len(ordered))
    compile_rules(merged_source, config.external_variables, rule_index)
    logger.info("Compilation succeeded ({} rules)", len(ordered))

    # --- Emit source (only after compilation passes) ---
    dist = root / "dist"
    output_path = dist / "merged_rules.yara"
    dist.mkdir(exist_ok=True)
    output_path.write_text(merged_source)

    # --- Write manifest ---
    write_manifest(ordered, removed_ids, exclusion_record,
                   corpus_data.source_files, dist / "build_manifest.json")

    return ordered, removed_ids, exclusion_record, output_path


def main() -> None:
    argparse.ArgumentParser(description="Build the merged YARA ruleset.").parse_args()
    setup_logging()

    root = ROOT
    logger.info("Starting ruleset build (root: {})", root)
    try:
        ordered, removed_ids, exclusion_record, output_path = build(root)
    except (ConfigError, PipelineError) as exc:
        logger.error("Build failed: {}", exc)
        sys.exit(1)

    vendor_n = sum(1 for r in ordered if r.origin == "vendor")
    override_n = sum(1 for r in ordered if r.origin == "overrides")
    custom_n = sum(1 for r in ordered if r.origin == "custom")
    filtered_n = len(exclusion_record)
    if removed_ids:
        logger.info(
            "Removed {} superseded vendor rule(s): {}",
            len(removed_ids), ", ".join(removed_ids),
        )
    logger.success(
        "Build complete: {} rules ({} vendor, {} overrides, {} custom{}) → {}",
        len(ordered), vendor_n, override_n, custom_n,
        f", {filtered_n} filtered out" if filtered_n else "",
        output_path,
    )


if __name__ == "__main__":
    main()
