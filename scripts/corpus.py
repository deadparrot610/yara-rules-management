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

import config_schema


class PipelineError(Exception):
    """Raised on a build-pipeline failure (parse, collision, cycle, compile, checkpoint).

    Caught at each script's CLI boundary (main) to print a message and exit 1, so
    library functions stay importable and testable instead of calling sys.exit.
    """


@dataclass
class RuleRecord:
    identifier: str
    raw_text: str                # verbatim source extracted from the file
    tags: list[str]
    meta: dict[str, object]      # flattened {key: value}
    condition_terms: list[str]   # plyara tokens; used for dependency detection
    imports: list[str]           # module imports declared in the source file
    origin: str                  # 'vendor' | 'custom' | 'overrides'
    filepath: Path


@dataclass
class Corpus:
    """The parsed rule corpus plus the source paths it came from.

    Bundles what every entrypoint needs after discovery+parse so build,
    override-check, and filter scripts share one loader (see load_corpus).
    """
    vendor_rules: list[RuleRecord]
    override_rules: list[RuleRecord]
    custom_rules: list[RuleRecord]
    vendor_paths: list[Path]
    override_path: Path
    custom_paths: list[Path]

    @property
    def all_rules(self) -> list[RuleRecord]:
        return self.vendor_rules + self.override_rules + self.custom_rules

    @property
    def source_files(self) -> list[Path]:
        return self.vendor_paths + [self.override_path] + self.custom_paths


# ---------------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------------

def discover_sources(root: Path) -> tuple[list[Path], Path, list[Path]]:
    """Return (vendor_paths, override_path, custom_paths) for the rule corpus."""
    vendor_paths = sorted((root / "rules" / "vendor").glob("*.yara"))
    override_path = root / "rules" / "overrides" / "overrides.yara"
    custom_paths = sorted((root / "rules" / "custom").rglob("*.yara"))
    return vendor_paths, override_path, custom_paths


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _extract_raw_by_line(source: str, parsed_rules: list[dict]) -> dict[str, str]:
    """Return {rule_name: raw_text} using plyara's start_line/stop_line."""
    lines = source.splitlines(keepends=True)
    result = {}
    for rule in parsed_rules:
        name = rule["rule_name"]
        start = rule["start_line"] - 1   # plyara is 1-indexed
        stop = rule["stop_line"]          # stop_line is inclusive; slice is [start:stop]
        result[name] = "".join(lines[start:stop])
    return result


def parse_yara_files(paths: list[Path], origin: str) -> list[RuleRecord]:
    """Parse .yara files; return a list of RuleRecord."""
    records: list[RuleRecord] = []
    # Re-sort defensively: callers normally pass sorted paths (discover_sources),
    # but sorting here guarantees deterministic rule order regardless of caller.
    for path in sorted(Path(p) for p in paths):
        if not path.exists():
            continue
        source = path.read_text()
        parser = plyara.Plyara()
        try:
            parsed = parser.parse_string(source)
        except Exception as exc:
            raise PipelineError(f"failed to parse {path}: {exc}") from exc

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
# Corpus loading
# ---------------------------------------------------------------------------

def load_corpus(root: Path) -> Corpus:
    """Discover and parse every rule source into a Corpus.

    The shared load-and-parse preamble for the build, override-check, and filter
    entrypoints — config/manifest/policy loading stays with each caller since it
    differs between them.
    """
    vendor_paths, override_path, custom_paths = discover_sources(root)
    return Corpus(
        vendor_rules=parse_yara_files(vendor_paths, "vendor"),
        override_rules=parse_yara_files([override_path], "overrides"),
        custom_rules=parse_yara_files(custom_paths, "custom"),
        vendor_paths=vendor_paths,
        override_path=override_path,
        custom_paths=custom_paths,
    )


# ---------------------------------------------------------------------------
# Corpus checks (shared by the lint and build gates)
# ---------------------------------------------------------------------------

def find_collision(rules: list[RuleRecord]) -> tuple[RuleRecord, RuleRecord] | None:
    """Return the first (previous, duplicate) pair sharing an identifier, or None.

    YARA rejects duplicate identifiers in one compilation unit, and a duplicate
    also makes identifier-keyed filter resolution ambiguous. The single definition
    of "an identifier collision" shared by the lint gate (scripts/lint.py) and the
    build gate (scripts/build_ruleset.py); run it on the post-strip corpus so an
    override that reuses a superseded vendor identifier is not a false positive.
    """
    seen: dict[str, RuleRecord] = {}
    for rule in rules:
        if rule.identifier in seen:
            return seen[rule.identifier], rule
        seen[rule.identifier] = rule
    return None


def module_offenders(
    rules: list[RuleRecord], allowed_modules: list[str],
) -> list[tuple[Path, str]]:
    """Return the (filepath, module) pairs importing a module outside the allowlist.

    Deduplicated per (filepath, module) — plyara attributes a file's imports to
    every rule in that file — and returned in first-seen (deterministic) order.
    The single definition of "an import outside config.yara_modules" shared by the
    lint gate (scripts/lint.py) and the build gate (scripts/build_ruleset.py); the
    deployment engine supports fewer modules than the compile gate, so this is the
    only guard against an unsupported import.
    """
    allowed = set(allowed_modules)
    offenders: list[tuple[Path, str]] = []
    seen: set[tuple[Path, str]] = set()
    for rule in rules:
        for mod in rule.imports:
            key = (rule.filepath, mod)
            if mod in allowed or key in seen:
                continue
            seen.add(key)
            offenders.append(key)
    return offenders


def meta_date_findings(
    rules: list[RuleRecord], meta_dates,
) -> tuple[list[dict], list[tuple[RuleRecord, str, object]]]:
    """Return (normalizations, offenders) for the configured date meta fields.

    normalizations records values that parsed but were *not* already ISO —
    {"identifier", "field", "raw", "normalized", "via"} — i.e. the audit trail of
    every value the pipeline reinterpreted. This is the only visible record of
    that reinterpretation, since the rule source itself is emitted verbatim.

    offenders are (rule, field, raw_value) triples nothing could parse.

    A rule not carrying a configured field is skipped: absence is not an error
    here (vendor feeds legitimately omit fields, and required_meta already owns
    the completeness question for custom/override rules).

    The single definition of "an unreadable rule date" shared by the lint gate
    (scripts/lint.py) and the build gate (scripts/build_ruleset.py). Results are
    sorted by (identifier, field) so the manifest is byte-identical across runs
    on identical input (NFR-6).
    """
    normalizations: list[dict] = []
    offenders: list[tuple[RuleRecord, str, object]] = []
    if not meta_dates.fields:
        return normalizations, offenders

    for rule in rules:
        for field_name in meta_dates.fields:
            if field_name not in rule.meta:
                continue
            raw = rule.meta[field_name]
            try:
                normalized, via = config_schema.normalize_meta_date(raw, meta_dates)
            except ValueError:
                offenders.append((rule, field_name, raw))
                continue
            if via == config_schema.DATE_FORMAT:
                continue
            normalizations.append({
                "identifier": rule.identifier,
                "field": field_name,
                "raw": str(raw),
                "normalized": normalized.isoformat(),
                "via": via,
            })

    normalizations.sort(key=lambda n: (n["identifier"], n["field"]))
    offenders.sort(key=lambda o: (o[0].identifier, o[1]))
    return normalizations, offenders


# ---------------------------------------------------------------------------
# Override strip
# ---------------------------------------------------------------------------

def strip_superseded(
    vendor_rules: list[RuleRecord], manifest: list,
) -> tuple[list[RuleRecord], list[str]]:
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
