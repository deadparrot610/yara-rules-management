#!/usr/bin/env python3
"""
Manifest validation and stale-override checkpoint for the YARA rule pipeline.

Standalone:   python scripts/check_overrides.py
Importable:   check_overrides.validate(vendor_rules, override_rules,
                                        manifest_entries, config, root)
"""

import sys
from pathlib import Path

import config_schema
import corpus
from config_schema import ConfigError
from corpus import PipelineError


def validate(
    vendor_rules: list,
    override_rules: list,
    manifest_entries: list,   # list[config_schema.OverrideEntry]
    config,                   # config_schema.BuildConfig
    root: Path,
) -> None:
    """Validate the override manifest and enforce the stale-override checkpoint.

    Shape/type of manifest_entries is already guaranteed by config_schema; this
    performs the corpus-dependent semantic checks. Raises PipelineError on
    semantic errors or unresolved stale entries. Prints required cleanup actions
    for 'discard' decisions (non-blocking).
    """
    vendor_ids = {r.identifier for r in vendor_rules}
    override_ids = {r.identifier for r in override_rules}

    # --- Semantic checks (shape/type already enforced at load by config_schema) ---
    errors = []
    seen_claimed: dict = {}  # vendor_id -> override_rule that claimed it

    for entry in manifest_entries:
        override_rule = entry.override_rule
        supersedes = entry.supersedes

        if override_rule not in override_ids:
            errors.append(
                f"override_rule {override_rule!r} not found in overrides corpus"
            )

        for vid in supersedes:
            if vid in override_ids:
                errors.append(
                    f"supersedes entry {vid!r} in {override_rule!r} names an override rule; "
                    f"only vendor rule identifiers may appear in supersedes"
                )
            if vid in seen_claimed:
                errors.append(
                    f"vendor rule {vid!r} is claimed by multiple override entries: "
                    f"{seen_claimed[vid]!r} and {override_rule!r}"
                )
            else:
                seen_claimed[vid] = override_rule

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        raise PipelineError(
            f"override manifest failed validation ({len(errors)} error(s))"
        )

    # --- Load decisions ---
    decisions_path = root / config.stale_override_decisions
    decisions = config_schema.load_decisions_map(
        decisions_path, "stale_override_decisions", "missing_vendor_rule")

    # --- Warn on stale decision records (vendor rule re-introduced) ---
    for (override_rule, missing_vid), _ in decisions.items():
        if missing_vid is not None and missing_vid in vendor_ids:
            print(
                f"WARNING: decision record for missing vendor rule {missing_vid!r} under "
                f"{override_rule!r} is now stale — {missing_vid!r} is back in the vendor "
                f"corpus. Remove or update this entry in "
                f"{config.stale_override_decisions}.",
                file=sys.stderr,
            )

    # --- Stale detection (per missing vendor ID, not per manifest entry) ---
    blocking = []   # (override_rule, vendor_id)
    cleanup = []    # (override_rule, vendor_id)

    for entry in manifest_entries:
        override_rule = entry.override_rule
        for vid in entry.supersedes:
            if vid in vendor_ids:
                continue
            # decision is None (no record), "keep", or "discard" — the value set
            # is validated at load time by config_schema.
            decision = config_schema.lookup_decision(decisions, override_rule, vid)
            if decision is None:
                blocking.append((override_rule, vid))
            elif decision == "discard":
                cleanup.append((override_rule, vid))

    if blocking:
        print("STALE OVERRIDE CHECKPOINT — build blocked.\n", file=sys.stderr)
        print(
            "The following overrides name vendor rules no longer in the vendor corpus.\n"
            f"Record a decision in: {config.stale_override_decisions}\n",
            file=sys.stderr,
        )
        for override_rule, vendor_id in blocking:
            print(f"  override_rule: {override_rule}", file=sys.stderr)
            print(f"    missing vendor rule: {vendor_id}", file=sys.stderr)
            print(f"    → add entry:", file=sys.stderr)
            print(f"        - override_rule: {override_rule}", file=sys.stderr)
            print(f"          missing_vendor_rule: {vendor_id}", file=sys.stderr)
            print(f"          decision: keep    # or: discard", file=sys.stderr)
            print(f"          reviewer: <name>", file=sys.stderr)
            print(f"          date: <YYYY-MM-DD>", file=sys.stderr)
            print(file=sys.stderr)
        raise PipelineError(
            f"stale override checkpoint: {len(blocking)} unresolved entr"
            f"{'y' if len(blocking) == 1 else 'ies'}"
        )

    if cleanup:
        print("REQUIRED CLEANUP — 'discard' decisions pending manual action:\n")
        for override_rule, vendor_id in cleanup:
            print(f"  - Remove rule {override_rule!r} from rules/overrides/overrides.yara")
            print(
                f"    (was superseding {vendor_id!r}, which is no longer in the vendor corpus)"
            )
            print(
                f"  - Remove the manifest entry for {override_rule!r} "
                f"from overrides/override_manifest.yaml"
            )
        print()


def main() -> None:
    import argparse
    argparse.ArgumentParser(
        description="Validate the override manifest and check for stale overrides."
    ).parse_args()

    root = Path(__file__).resolve().parent.parent

    try:
        config = config_schema.load_build_config(root)
        manifest_entries = config_schema.load_override_manifest(root)

        vendor_paths, override_path, _ = corpus.discover_sources(root)
        vendor_rules = corpus.parse_yara_files(vendor_paths, "vendor")
        override_rules = corpus.parse_yara_files([override_path], "overrides")

        validate(vendor_rules, override_rules, manifest_entries, config, root)
    except (ConfigError, PipelineError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Override manifest OK.")


if __name__ == "__main__":
    main()
