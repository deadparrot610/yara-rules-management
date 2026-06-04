#!/usr/bin/env python3
"""
Manifest validation and stale-override checkpoint for the YARA rule pipeline.

Standalone:   python scripts/check_overrides.py
Importable:   check_overrides.validate(vendor_rules, override_rules,
                                        manifest_entries, config, root)
"""

import sys
import collections
from pathlib import Path

import yaml

_Rule = collections.namedtuple("_Rule", ["identifier"])


def _parse_rules_standalone(paths: list) -> list:
    """Minimal plyara parse — extracts rule identifiers only."""
    import plyara as plyara_mod
    records = []
    for path in sorted(Path(p) for p in paths):
        if not path.exists():
            continue
        parser = plyara_mod.Plyara()
        try:
            parsed = parser.parse_string(path.read_text())
        except Exception as exc:
            print(f"ERROR: failed to parse {path}: {exc}", file=sys.stderr)
            sys.exit(1)
        for rule in parsed:
            records.append(_Rule(identifier=rule["rule_name"]))
    return records


def _load_decisions(decisions_path: Path) -> dict:
    """Load stale_override_decisions.yaml.

    Returns a dict keyed by (override_rule, missing_vendor_rule) -> decision_str.
    When an entry omits missing_vendor_rule, the key is (override_rule, None),
    acting as a wildcard that covers all missing vendor IDs under that override rule.
    Returns empty dict if the file does not exist.
    """
    if not decisions_path.exists():
        return {}
    try:
        with decisions_path.open() as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        print(f"ERROR: could not read {decisions_path}: {exc}", file=sys.stderr)
        sys.exit(1)
    result = {}
    for entry in (data.get("stale_override_decisions") or []):
        override_rule = entry.get("override_rule")
        missing_vendor_rule = entry.get("missing_vendor_rule")  # None when absent
        decision = (entry.get("decision") or "").strip().lower()
        if override_rule:
            result[(override_rule, missing_vendor_rule)] = decision
    return result


def _lookup_decision(decisions: dict, override_rule: str, vendor_id: str):
    """Return the recorded decision for a stale (override_rule, vendor_id) pair.

    Checks the specific (override_rule, vendor_id) key first, then falls back
    to the wildcard (override_rule, None). Returns None if no decision is recorded.
    """
    specific = decisions.get((override_rule, vendor_id))
    if specific is not None:
        return specific
    return decisions.get((override_rule, None))


def validate(
    vendor_rules: list,
    override_rules: list,
    manifest_entries: list,
    config: dict,
    root: Path,
) -> None:
    """Validate the override manifest and enforce the stale-override checkpoint.

    Exits with sys.exit(1) on structural errors or unresolved stale entries.
    Prints required cleanup actions for 'discard' decisions (non-blocking).
    """
    vendor_ids = {r.identifier for r in vendor_rules}
    override_ids = {r.identifier for r in override_rules}

    # --- Structural checks ---
    errors = []
    seen_claimed: dict = {}  # vendor_id -> override_rule (or sentinel) that claimed it

    for i, entry in enumerate(manifest_entries):
        override_rule = entry.get("override_rule")
        supersedes = entry.get("supersedes")

        if not override_rule:
            errors.append(f"manifest entry {i} is missing 'override_rule'")
            # Still record claims so duplicate-claim errors are reported even for
            # malformed entries.
            for vid in (supersedes or []):
                if vid in seen_claimed:
                    errors.append(
                        f"vendor rule {vid!r} is claimed by multiple override entries: "
                        f"{seen_claimed[vid]!r} and entry {i} (missing 'override_rule')"
                    )
                else:
                    seen_claimed[vid] = f"<entry {i}>"
            continue

        if override_rule not in override_ids:
            errors.append(
                f"override_rule {override_rule!r} not found in overrides corpus"
            )

        if not supersedes:
            errors.append(
                f"manifest entry for {override_rule!r} has an empty or missing 'supersedes' list"
            )
            continue

        for vid in supersedes:
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
        sys.exit(1)

    # --- Load decisions ---
    decisions_path = root / config["stale_override_decisions"]
    decisions = _load_decisions(decisions_path)

    # --- Warn on stale decision records (vendor rule re-introduced) ---
    for (override_rule, missing_vid), _ in decisions.items():
        if missing_vid is not None and missing_vid in vendor_ids:
            print(
                f"WARNING: decision record for missing vendor rule {missing_vid!r} under "
                f"{override_rule!r} is now stale — {missing_vid!r} is back in the vendor "
                f"corpus. Remove or update this entry in "
                f"{config['stale_override_decisions']}.",
                file=sys.stderr,
            )

    # --- Stale detection (per missing vendor ID, not per manifest entry) ---
    blocking = []   # (override_rule, vendor_id)
    cleanup = []    # (override_rule, vendor_id)

    for entry in manifest_entries:
        override_rule = entry["override_rule"]
        for vid in entry.get("supersedes", []):
            if vid in vendor_ids:
                continue
            decision = _lookup_decision(decisions, override_rule, vid)
            if decision is None:
                blocking.append((override_rule, vid))
            elif decision == "keep":
                pass
            elif decision == "discard":
                cleanup.append((override_rule, vid))
            else:
                print(
                    f"WARNING: unrecognized decision {decision!r} for "
                    f"{override_rule!r}/{vid!r} — treating as no decision (blocked)",
                    file=sys.stderr,
                )
                blocking.append((override_rule, vid))

    if blocking:
        print("STALE OVERRIDE CHECKPOINT — build blocked.\n", file=sys.stderr)
        print(
            "The following overrides name vendor rules no longer in the vendor corpus.\n"
            f"Record a decision in: {config['stale_override_decisions']}\n",
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
        sys.exit(1)

    if cleanup:
        print("REQUIRED CLEANUP — 'discard' decisions pending manual action:\n")
        for override_rule, vendor_id in cleanup:
            print(f"  - Remove rule {override_rule!r} from rules/overrides/overrides.yara")
            print(
                f"    (was superseding {vendor_id!r}, which is no longer in the vendor corpus)"
            )
            print(
                f"  - Remove the manifest entry for {override_rule!r} "
                f"from rules/overrides/override_manifest.yaml"
            )
        print()


def main() -> None:
    import argparse
    argparse.ArgumentParser(
        description="Validate the override manifest and check for stale overrides."
    ).parse_args()

    root = Path(__file__).resolve().parent.parent

    with (root / "config" / "build.yaml").open() as f:
        config = yaml.safe_load(f)

    with (root / "rules" / "overrides" / "override_manifest.yaml").open() as f:
        data = yaml.safe_load(f) or {}
    manifest_entries = data.get("overrides", [])

    vendor_paths = sorted((root / "rules" / "vendor").glob("*.yara"))
    vendor_rules = _parse_rules_standalone(vendor_paths)

    override_path = root / "rules" / "overrides" / "overrides.yara"
    override_rules = _parse_rules_standalone([override_path])

    validate(vendor_rules, override_rules, manifest_entries, config, root)
    print("Override manifest OK.")


if __name__ == "__main__":
    main()
