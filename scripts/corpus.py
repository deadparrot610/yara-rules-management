#!/usr/bin/env python3
"""
Shared corpus primitives for the YARA rule pipeline.

Owns the in-memory rule model, the single YARA parser, source discovery, and the
override-strip step — the pieces the build, override-check, and filter scripts all
need. A dependency-light leaf: imports only plyara and the (yaml-only) config_schema.
"""

from dataclasses import dataclass
from pathlib import Path

import plyara


class PipelineError(Exception):
    """Raised on a build-pipeline failure (parse, collision, cycle, compile, checkpoint).

    Caught at each script's CLI boundary (main) to print a message and exit 1, so
    library functions stay importable and testable instead of calling sys.exit.
    """


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
# Source discovery
# ---------------------------------------------------------------------------

def discover_sources(root: Path) -> tuple:
    """Return (vendor_paths, override_path, custom_paths) for the rule corpus."""
    vendor_paths = sorted((root / "rules" / "vendor").glob("*.yara"))
    override_path = root / "rules" / "overrides" / "overrides.yara"
    custom_paths = sorted((root / "rules" / "custom").rglob("*.yara"))
    return vendor_paths, override_path, custom_paths


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
            raise PipelineError(f"failed to parse {path}: {exc}")

        if not parsed:
            continue

        raw_by_name = _extract_raw_by_line(source, parsed)

        for rule in parsed:
            name = rule["rule_name"]
            raw = raw_by_name.get(name)
            if raw is None:
                raise PipelineError(
                    f"could not locate raw text for rule {name!r} in {path}"
                )

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
# Override strip
# ---------------------------------------------------------------------------

def strip_superseded(vendor_rules: list, manifest: list) -> tuple:
    """Remove vendor rules declared as superseded in the manifest.

    Returns (remaining_vendor_rules, sorted_list_of_removed_identifiers).
    Identifiers listed in the manifest but absent from the vendor corpus are
    silently noted here; check_overrides.validate blocks on them as stale entries.
    """
    superseded = set()
    for entry in manifest:
        for vid in entry.supersedes:
            superseded.add(vid)

    vendor_ids = {r.identifier for r in vendor_rules}
    remaining = [r for r in vendor_rules if r.identifier not in superseded]
    removed = sorted(superseded & vendor_ids)
    return remaining, removed
