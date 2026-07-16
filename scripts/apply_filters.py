#!/usr/bin/env python3
"""
Filter policy engine for the YARA rule pipeline.

Standalone:  python scripts/apply_filters.py [--preview]
Importable:  apply_filters.run(rules, policy, root, manifest_entries, config)
             -> (included_rules, exclusion_record)
"""

import fnmatch
import re
import sys
from pathlib import Path

import config_schema
from check_overrides import _lookup_decision as _lookup_gap_decision


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------

def _scope_specificity(scope: str) -> int:
    if scope.startswith("rule:"):
        return 0
    if scope in {"vendor", "custom", "overrides"}:
        return 1
    return 2  # "global" or anything unrecognised


def _scope_applies(scope: str, rule) -> bool:
    if scope.startswith("rule:"):
        return rule.identifier == scope[5:]
    if scope == "global":
        return True
    return rule.origin == scope


# ---------------------------------------------------------------------------
# Selector matching
# ---------------------------------------------------------------------------

def _selector_matches(filter_entry, rule, rule_tags=None) -> bool:
    match = filter_entry.match
    if match is None:
        return True

    if match.name is not None and rule.identifier != match.name:
        return False

    if match.name_glob is not None and not fnmatch.fnmatch(rule.identifier, match.name_glob):
        return False

    if match.name_regex is not None and not re.search(match.name_regex, rule.identifier):
        return False

    if match.tags is not None:
        if rule_tags is None:
            rule_tags = frozenset(rule.tags)
        if not all(t in rule_tags for t in match.tags):
            return False

    if match.meta is not None:
        for k, v in match.meta.items():
            if str(rule.meta.get(k)) != str(v):
                return False

    if match.meta_in is not None:
        for k, vs in match.meta_in.items():
            if str(rule.meta.get(k)) not in vs:  # vs is a frozenset (FilterMatch.__post_init__)
                return False

    return True


# ---------------------------------------------------------------------------
# Per-rule resolution
# ---------------------------------------------------------------------------

def _resolve_rule(rule, filters: list, default_mode: str, conflict_policy: str) -> tuple:
    """Return (action, responsible_filter | None)."""
    applicable = [
        f for f in filters
        if _scope_applies(f.scope, rule)
        and _selector_matches(f, rule)
    ]

    if not applicable:
        return ("include" if default_mode == "include_all" else "exclude"), None

    by_spec: dict = {}
    for f in applicable:
        spec = _scope_specificity(f.scope)
        by_spec.setdefault(spec, []).append(f)

    best_spec = min(by_spec)
    best = by_spec[best_spec]

    actions = {f.action for f in best}
    if len(actions) == 1:
        return next(iter(actions)), best[-1]

    # Conflict at the same specificity level — apply tie-break policy.
    # action values are validated at load (include|exclude), so exclude_wins
    # always finds an 'exclude' when actions disagree.
    if conflict_policy == "exclude_wins":
        for f in reversed(best):
            if f.action == "exclude":
                return "exclude", f
        return best[-1].action, best[-1]
    elif conflict_policy == "last_match_wins":
        return best[-1].action, best[-1]
    else:  # "error"
        ids = [f.id or "<no-id>" for f in best]
        print(
            f"ERROR: conflicting same-specificity filters for rule {rule.identifier!r}: "
            f"{ids}. Resolve the conflict or set filter_conflict_policy to exclude_wins "
            f"or last_match_wins.",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Coverage-gap checkpoint
# ---------------------------------------------------------------------------

def _load_gap_decisions(decisions_path: Path) -> dict:
    """Load coverage_gap_decisions.yaml; returns {(override_rule, filter_id | None): decision}."""
    entries = config_schema.load_decisions(
        decisions_path, "coverage_gap_decisions", "filter_id")
    return {(e.override_rule, e.secondary): e.decision for e in entries}


def _coverage_gap_check(
    exclusion_record: list,
    manifest_entries: list,
    root: Path,
    config: dict,
) -> None:
    # After strip_superseded, every superseded vendor rule is absent from the corpus —
    # either stripped in this build or already gone from a prior vendor update. Any
    # excluded override that has supersedes entries therefore creates a detection gap,
    # whether the vendor removal happened in this run or an earlier one.
    override_supersedes: dict = {}
    for entry in manifest_entries:
        if entry.supersedes:
            override_supersedes[entry.override_rule] = set(entry.supersedes)

    if not override_supersedes:
        return

    decisions_path = root / config.coverage_gap_decisions
    decisions = _load_gap_decisions(decisions_path)

    blocking = []   # (override_rule, filter_id)
    cleanup = []    # (override_rule, filter_id)

    for rec in exclusion_record:
        identifier = rec["identifier"]
        if identifier not in override_supersedes:
            continue
        filter_id = rec.get("filter_id")
        # decision is None, "keep", or "discard" — validated at load by config_schema.
        decision = _lookup_gap_decision(decisions, identifier, filter_id)
        if decision is None:
            blocking.append((identifier, filter_id))
        elif decision == "discard":
            cleanup.append((identifier, filter_id))

    if cleanup:
        print("REQUIRED ACTION — coverage-gap 'discard' decisions pending manual revision:\n")
        for override_rule, filter_id in cleanup:
            print(f"  - Revise the filter policy so {override_rule!r} is no longer excluded")
            if filter_id:
                print(f"    (responsible filter: {filter_id})")
        print()

    if blocking:
        print("COVERAGE GAP CHECKPOINT — build blocked.\n", file=sys.stderr)
        print(
            "The following override rules are excluded by a filter, but the vendor rules\n"
            f"they superseded have already been removed. Record a decision in:\n"
            f"  {config.coverage_gap_decisions}\n",
            file=sys.stderr,
        )
        for override_rule, filter_id in blocking:
            print(f"  override_rule: {override_rule}", file=sys.stderr)
            if filter_id:
                print(f"    responsible filter: {filter_id}", file=sys.stderr)
            print(f"    → add entry:", file=sys.stderr)
            print(f"        - override_rule: {override_rule}", file=sys.stderr)
            if filter_id:
                # Include filter_id to scope this decision to one filter.
                # Omit it to create a wildcard that covers all filters for this override.
                print(f"          filter_id: {filter_id}", file=sys.stderr)
            print(f"          decision: keep    # or: discard", file=sys.stderr)
            print(f"          reviewer: <name>", file=sys.stderr)
            print(f"          date: <YYYY-MM-DD>", file=sys.stderr)
            print(file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Referential integrity
# ---------------------------------------------------------------------------

def _referential_integrity_check(included_rules: list, excluded_ids: set) -> None:
    errors = []
    for rule in included_rules:
        for term in rule.condition_terms:
            if term in excluded_ids:
                errors.append(
                    f"included rule {rule.identifier!r} references "
                    f"excluded rule {term!r}"
                )
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Floor guard
# ---------------------------------------------------------------------------

def _floor_guard(included_count: int, policy) -> None:
    min_rules = policy.min_output_rules
    if included_count < min_rules:
        msg = (
            f"Filter policy produced {included_count} rules, "
            f"below min_output_rules={min_rules}."
        )
        on_empty = policy.on_empty_output
        if on_empty == "warn":
            print(f"WARNING: {msg}")
        else:
            print(f"ERROR: {msg}", file=sys.stderr)
            sys.exit(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    rules: list,
    policy,
    root: Path,
    manifest_entries: list,
    config,
) -> tuple:
    """Apply the filter policy to the post-strip corpus.

    policy is a config_schema.FilterPolicy; config is a config_schema.BuildConfig.
    Returns (included_rules, exclusion_record).
    exclusion_record: list of {identifier, filter_id, reason}.
    """
    conflict_policy = config.filter_conflict_policy
    default_mode = policy.default_mode
    filters = policy.filters

    included = []
    exclusion_record = []

    for rule in rules:
        action, responsible = _resolve_rule(rule, filters, default_mode, conflict_policy)
        if action == "include":
            included.append(rule)
        else:
            exclusion_record.append({
                "identifier": rule.identifier,
                "filter_id": responsible.id if responsible else None,
                "reason": (
                    (responsible.reason or "") if responsible
                    else f"default_mode: {default_mode}"
                ),
            })

    excluded_ids = {e["identifier"] for e in exclusion_record}
    _coverage_gap_check(exclusion_record, manifest_entries, root, config)
    _referential_integrity_check(included, excluded_ids)
    _floor_guard(len(included), policy)

    return included, exclusion_record


# ---------------------------------------------------------------------------
# Standalone preview mode
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Preview filter policy effects without building."
    )
    parser.add_argument(
        "--preview", action="store_true",
        help="Preview what the current filter policy would include/exclude (default behavior).",
    )
    parser.parse_args()

    root = Path(__file__).resolve().parent.parent

    # Lazy imports avoid circular dependency at module-init time and reuse
    # the production parse, strip, and config-load logic rather than duplicating it.
    from build_ruleset import (
        parse_yara_files,
        strip_superseded,
        load_config,
        load_manifest,
        load_filter_policy,
    )
    from config_schema import ConfigError

    try:
        config = load_config(root)
        manifest_entries = load_manifest(root)
        policy = load_filter_policy(root)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    vendor_paths = sorted((root / "rules" / "vendor").glob("*.yara"))
    override_path = root / "rules" / "overrides" / "overrides.yara"
    custom_paths = sorted((root / "rules" / "custom").rglob("*.yara"))

    vendor_rules = parse_yara_files(vendor_paths, "vendor")
    override_rules = parse_yara_files([override_path], "overrides")
    custom_rules = parse_yara_files(custom_paths, "custom")

    # Run override validation so preview faithfully reflects build behaviour,
    # including blocking on unresolved stale overrides before showing filter effects.
    import check_overrides
    check_overrides.validate(vendor_rules, override_rules, manifest_entries, config, root)

    vendor_remainder, _ = strip_superseded(vendor_rules, manifest_entries)
    corpus = vendor_remainder + override_rules + custom_rules

    included, exclusion_record = run(corpus, policy, root, manifest_entries, config)

    print(f"PREVIEW — filter policy: {root / 'filters' / 'filter_policy.yaml'}")
    print(f"  default_mode : {policy.default_mode}")
    print(f"  active filters: {len(policy.filters)}")
    print(f"  corpus (post-strip): {len(corpus)} rules")
    print(f"  included : {len(included)}")
    print(f"  excluded : {len(exclusion_record)}")
    if exclusion_record:
        print()
        for rec in exclusion_record:
            fid = rec['filter_id'] or 'default_mode'
            print(f"  EXCLUDE  {rec['identifier']}  (filter: {fid}, reason: {rec['reason']})")


if __name__ == "__main__":
    main()
