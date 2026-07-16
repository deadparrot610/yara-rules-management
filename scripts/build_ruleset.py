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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import plyara
import yara

import config_schema
from config_schema import ConfigError

ROOT = Path(__file__).resolve().parent.parent

GROUP_ORDER = {"vendor": 0, "overrides": 1, "custom": 2}


@dataclass
class RuleRecord:
    identifier: str
    raw_text: str          # verbatim source extracted from the file
    tags: list
    meta: dict             # flattened {key: value}
    condition_terms: list  # plyara tokens; used for dependency detection
    imports: list          # module imports declared in the source file
    origin: str            # 'vendor' | 'custom' | 'overrides'
    filepath: Path


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _extract_raw_by_line(source: str, parsed_rules: list) -> dict:
    """Return {rule_name: raw_text} using plyara's start_line/stop_line."""
    lines = source.splitlines(keepends=True)
    result = {}
    for rule in parsed_rules:
        name = rule["rule_name"]
        start = rule["start_line"] - 1   # plyara is 1-indexed
        stop = rule["stop_line"]          # stop_line is inclusive; slice is [start:stop]
        result[name] = "".join(lines[start:stop])
    return result


def parse_yara_files(paths: list, origin: str) -> list:
    """Parse .yara files; return a list of RuleRecord."""
    records = []
    for path in sorted(Path(p) for p in paths):
        if not path.exists():
            continue
        source = path.read_text()
        parser = plyara.Plyara()
        try:
            parsed = parser.parse_string(source)
        except Exception as exc:
            print(f"ERROR: failed to parse {path}: {exc}", file=sys.stderr)
            sys.exit(1)

        if not parsed:
            continue

        raw_by_name = _extract_raw_by_line(source, parsed)

        for rule in parsed:
            name = rule["rule_name"]
            raw = raw_by_name.get(name)
            if raw is None:
                print(
                    f"ERROR: could not locate raw text for rule {name!r} in {path}",
                    file=sys.stderr,
                )
                sys.exit(1)

            meta = {}
            for entry in rule.get("metadata", []):
                meta.update(entry)

            records.append(RuleRecord(
                identifier=name,
                raw_text=raw,
                tags=rule.get("tags", []),
                meta=meta,
                condition_terms=rule.get("condition_terms", []),
                imports=rule.get("imports", []),
                origin=origin,
                filepath=path,
            ))
    return records


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
# Override strip
# ---------------------------------------------------------------------------

def strip_superseded(vendor_rules: list, manifest: list) -> tuple:
    """Remove vendor rules declared as superseded in the manifest.

    Returns (remaining_vendor_rules, sorted_list_of_removed_identifiers).
    Identifiers listed in the manifest but absent from the vendor corpus are
    silently noted here; Phase 2 (check_overrides.py) will block on them as
    stale entries.
    """
    superseded = set()
    for entry in manifest:
        for vid in entry.supersedes:
            superseded.add(vid)

    vendor_ids = {r.identifier for r in vendor_rules}
    remaining = [r for r in vendor_rules if r.identifier not in superseded]
    removed = sorted(superseded & vendor_ids)
    return remaining, removed


# ---------------------------------------------------------------------------
# Collision check
# ---------------------------------------------------------------------------

def check_collisions(rules: list) -> None:
    """Hard-error on duplicate identifiers in the merged corpus."""
    seen = {}
    for rule in rules:
        if rule.identifier in seen:
            prev = seen[rule.identifier]
            print(
                f"ERROR: duplicate identifier {rule.identifier!r} "
                f"in {rule.filepath} and {prev.filepath}",
                file=sys.stderr,
            )
            sys.exit(1)
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
        print(f"ERROR: cycle detected among rules: {cycle_ids}", file=sys.stderr)
        sys.exit(1)

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
        print(f"ERROR: YARA compilation failed{annotation}: {msg}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: unexpected compilation error: {exc}", file=sys.stderr)
        sys.exit(1)


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

def main() -> None:
    argparse.ArgumentParser(description="Build the merged YARA ruleset.").parse_args()

    root = ROOT
    try:
        config = load_config(root)
        manifest_entries = load_manifest(root)
        filter_policy = load_filter_policy(root)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    # --- Parse ---
    vendor_paths = sorted((root / "rules" / "vendor").glob("*.yara"))
    override_path = root / "rules" / "overrides" / "overrides.yara"
    custom_paths = sorted((root / "rules" / "custom").rglob("*.yara"))

    vendor_rules = parse_yara_files(vendor_paths, "vendor")
    override_rules = parse_yara_files([override_path], "overrides")
    custom_rules = parse_yara_files(custom_paths, "custom")

    # --- Phase 2: stale-override validation ---
    import check_overrides
    check_overrides.validate(vendor_rules, override_rules, manifest_entries, config, root)

    # --- Strip superseded vendor rules ---
    vendor_remainder, removed_ids = strip_superseded(vendor_rules, manifest_entries)

    # --- Phase 3: filter policy ---
    import apply_filters
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
