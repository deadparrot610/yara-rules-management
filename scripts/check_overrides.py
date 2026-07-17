#!/usr/bin/env python3
"""
Manifest validation and stale-override checkpoint for the YARA rule pipeline.

Standalone:   python scripts/check_overrides.py
Importable:   check_overrides.validate(vendor_rules, override_rules,
                                        manifest_entries, config, root)
"""

import argparse
import sys
from pathlib import Path

from loguru import logger

import config_schema
import corpus
from config_schema import ConfigError
from corpus import PipelineError
from logging_setup import setup_logging


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
            logger.error(e)
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
            logger.warning(
                "Decision record for missing vendor rule {!r} under {!r} is now stale "
                "— {!r} is back in the vendor corpus. Remove or update this entry in {}.",
                missing_vid, override_rule, missing_vid, config.stale_override_decisions,
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
        lines = [
            "STALE OVERRIDE CHECKPOINT — build blocked.",
            "",
            "The following overrides name vendor rules no longer in the vendor corpus.",
            f"Record a decision in: {config.stale_override_decisions}",
            "",
        ]
        for override_rule, vendor_id in blocking:
            lines += [
                f"  override_rule: {override_rule}",
                f"    missing vendor rule: {vendor_id}",
                "    → add entry:",
                f"        - override_rule: {override_rule}",
                f"          missing_vendor_rule: {vendor_id}",
                "          decision: keep    # or: discard",
                "          reviewer: <name>",
                "          date: <YYYY-MM-DD>",
                "",
            ]
        logger.error("\n".join(lines))
        raise PipelineError(
            f"stale override checkpoint: {len(blocking)} unresolved entr"
            f"{'y' if len(blocking) == 1 else 'ies'}"
        )

    if cleanup:
        lines = ["REQUIRED CLEANUP — 'discard' decisions pending manual action:", ""]
        for override_rule, vendor_id in cleanup:
            lines += [
                f"  - Remove rule {override_rule!r} from rules/overrides/overrides.yara",
                f"    (was superseding {vendor_id!r}, which is no longer in the vendor corpus)",
                f"  - Remove the manifest entry for {override_rule!r} "
                f"from overrides/override_manifest.yaml",
            ]
        logger.warning("\n".join(lines))


def main() -> None:
    argparse.ArgumentParser(
        description="Validate the override manifest and check for stale overrides."
    ).parse_args()
    setup_logging()

    root = Path(__file__).resolve().parent.parent

    try:
        config = config_schema.load_build_config(root)
        manifest_entries = config_schema.load_override_manifest(root)

        corpus_data = corpus.load_corpus(root)

        validate(corpus_data.vendor_rules, corpus_data.override_rules,
                 manifest_entries, config, root)
    except (ConfigError, PipelineError) as exc:
        logger.error("Override check failed: {}", exc)
        sys.exit(1)

    logger.success("Override manifest OK.")


if __name__ == "__main__":
    main()
