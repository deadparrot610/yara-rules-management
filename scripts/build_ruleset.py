#!/usr/bin/env python3
"""
Build the merged YARA ruleset.

Build sequence: parse → validate overrides (check_overrides) → strip superseded
vendor rules → apply filter policy (apply_filters) → collision check →
topological order → emit source → compile (validation gate) → write manifest.
"""

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

import config_schema
import check_overrides
import apply_filters
from config_schema import ConfigError
from corpus import PipelineError, parse_yara_files, strip_superseded, discover_sources

ROOT = Path(__file__).resolve().parent.parent

GROUP_ORDER = {"vendor": 0, "overrides": 1, "custom": 2}


# ---------------------------------------------------------------------------
# Config / manifest loading
# ---------------------------------------------------------------------------

def load_config(root: Path):
    """Return the validated BuildConfig (see config_schema)."""
    return config_schema.load_build_config(root)


def load_manifest(root: Path) -> list:
    """Return the validated override manifest as a list of OverrideEntry."""
    return config_schema.load_override_manifest(root)


def load_filter_policy(root: Path):
    """Return the validated FilterPolicy (see config_schema)."""
    return config_schema.load_filter_policy(root)


# ---------------------------------------------------------------------------
# Collision check
# ---------------------------------------------------------------------------

def check_collisions(rules: list) -> None:
    """Hard-error on duplicate identifiers in the merged corpus."""
    seen = {}
    for rule in rules:
        if rule.identifier in seen:
            prev = seen[rule.identifier]
            raise PipelineError(
                f"duplicate identifier {rule.identifier!r} "
                f"in {rule.filepath} and {prev.filepath}"
            )
        seen[rule.identifier] = rule


# ---------------------------------------------------------------------------
# Topological ordering
# ---------------------------------------------------------------------------

def topological_order(rules: list) -> list:
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

def build_source(rules: list, all_imports: set) -> tuple:
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
    index: list = []
    for rule in rules:
        index.append((lineno, rule))
        stripped = rule.raw_text.rstrip()
        parts.append(stripped)
        parts.append("\n\n")
        lineno += stripped.count("\n") + 2  # content lines + \n\n separator
    return "".join(parts), index


def _locate_rule(index: list, lineno: int):
    """Return the RuleRecord whose block contains lineno, or None."""
    if not index:
        return None
    starts = [s for s, _ in index]
    pos = bisect.bisect_right(starts, lineno) - 1
    return index[pos][1] if pos >= 0 else None


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def compile_rules(source: str, externals: dict, rule_index: list | None = None) -> None:
    """Compile via yara-python as the authoritative validation gate.

    Takes the merged source string directly so no unvalidated file is
    written to disk before this gate passes.  Non-negotiable even when
    only source output is requested.
    """
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
        raise PipelineError(f"YARA compilation failed{annotation}: {msg}")
    except Exception as exc:
        raise PipelineError(f"unexpected compilation error: {exc}")


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(
    rules: list,
    removed_ids: list,
    exclusion_record: list,
    source_files: list,
    dest: Path,
) -> None:
    counts = {origin: sum(1 for r in rules if r.origin == origin)
              for origin in ("vendor", "custom", "overrides")}

    manifest = {
        "build_version": "1",
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

def _build(root: Path) -> tuple:
    """Run the full pipeline. Returns (ordered, removed_ids, exclusion_record, output_path).

    Raises ConfigError / PipelineError on any failure; the CLI boundary (main) turns
    those into an ERROR message and exit 1.
    """
    config = load_config(root)
    manifest_entries = load_manifest(root)
    filter_policy = load_filter_policy(root)

    # --- Parse ---
    vendor_paths, override_path, custom_paths = discover_sources(root)

    vendor_rules = parse_yara_files(vendor_paths, "vendor")
    override_rules = parse_yara_files([override_path], "overrides")
    custom_rules = parse_yara_files(custom_paths, "custom")

    # --- Phase 2: stale-override validation ---
    check_overrides.validate(vendor_rules, override_rules, manifest_entries, config, root)

    # --- Strip superseded vendor rules ---
    vendor_remainder, removed_ids = strip_superseded(vendor_rules, manifest_entries)

    # --- Phase 3: filter policy ---
    included_rules, exclusion_record = apply_filters.run(
        vendor_remainder + override_rules + custom_rules,
        filter_policy,
        root,
        manifest_entries,
        config,
    )

    # --- Collision check ---
    check_collisions(included_rules)

    # --- Topological order ---
    ordered = topological_order(included_rules)

    # --- Collect imports ---
    all_imports: set = set()
    for rule in ordered:
        all_imports.update(rule.imports)

    # --- Build source string ---
    merged_source, rule_index = build_source(ordered, all_imports)

    # --- Compile (authoritative validation gate) ---
    # Runs against the in-memory string so no unvalidated file is written first.
    compile_rules(merged_source, config.external_variables, rule_index)

    # --- Emit source (only after compilation passes) ---
    dist = root / "dist"
    output_path = dist / "merged_rules.yara"
    dist.mkdir(exist_ok=True)
    output_path.write_text(merged_source)

    # --- Write manifest ---
    all_source_files = vendor_paths + [override_path] + custom_paths
    write_manifest(ordered, removed_ids, exclusion_record, all_source_files, dist / "build_manifest.json")

    return ordered, removed_ids, exclusion_record, output_path


def main() -> None:
    argparse.ArgumentParser(description="Build the merged YARA ruleset.").parse_args()

    root = ROOT
    try:
        ordered, removed_ids, exclusion_record, output_path = _build(root)
    except (ConfigError, PipelineError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    vendor_n = sum(1 for r in ordered if r.origin == "vendor")
    override_n = sum(1 for r in ordered if r.origin == "overrides")
    custom_n = sum(1 for r in ordered if r.origin == "custom")
    filtered_n = len(exclusion_record)
    print(
        f"Build complete: {len(ordered)} rules "
        f"({vendor_n} vendor, {override_n} overrides, {custom_n} custom"
        + (f", {filtered_n} filtered out" if filtered_n else "")
        + f") → {output_path}"
    )
    if removed_ids:
        print(f"Removed vendor rules ({len(removed_ids)}): {', '.join(removed_ids)}")


if __name__ == "__main__":
    main()
