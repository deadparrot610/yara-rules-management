#!/usr/bin/env python3
"""
Filter policy engine for the YARA rule pipeline.

Standalone:  python scripts/apply_filters.py [--preview]
Importable:  apply_filters.run(rules, policy, root, manifest_entries, config)
             -> (included_rules, exclusion_record)
"""

import argparse
import fnmatch
import re
import sys
from pathlib import Path

from loguru import logger

import config_schema
import corpus
from corpus import PipelineError
from logging_setup import setup_logging


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------

def _scope_specificity(scope: str) -> int:
    if scope.startswith("rule:"):
        return 0
    if scope in config_schema.ORIGIN_SCOPES:
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
        raise PipelineError(
            f"conflicting same-specificity filters for rule {rule.identifier!r}: "
            f"{ids}. Resolve the conflict or set filter_conflict_policy to exclude_wins "
            f"or last_match_wins."
        )


# ---------------------------------------------------------------------------
# Coverage-gap checkpoint
# ---------------------------------------------------------------------------

def _coverage_gap_check(
    exclusion_record: list,
    manifest_entries: list,
    root: Path,
    config,  # config_schema.BuildConfig
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
    decisions = config_schema.load_decisions_map(
        decisions_path, "coverage_gap_decisions", "filter_id")

    blocking = []   # (override_rule, filter_id)
    cleanup = []    # (override_rule, filter_id)

    for rec in exclusion_record:
        identifier = rec["identifier"]
        if identifier not in override_supersedes:
            continue
        filter_id = rec.get("filter_id")
        # decision is None, "keep", or "discard" — validated at load by config_schema.
        decision = config_schema.lookup_decision(decisions, identifier, filter_id)
        if decision is None:
            blocking.append((identifier, filter_id))
        elif decision == "discard":
            cleanup.append((identifier, filter_id))

    if cleanup:
        lines = [
            "REQUIRED ACTION — coverage-gap 'discard' decisions pending manual revision:",
            "",
        ]
        for override_rule, filter_id in cleanup:
            lines.append(
                f"  - Revise the filter policy so {override_rule!r} is no longer excluded"
            )
            if filter_id:
                lines.append(f"    (responsible filter: {filter_id})")
        logger.warning("\n".join(lines))

    if blocking:
        lines = [
            "COVERAGE GAP CHECKPOINT — build blocked.",
            "",
            "The following override rules are excluded by a filter, but the vendor rules",
            "they superseded have already been removed. Record a decision in:",
            f"  {config.coverage_gap_decisions}",
            "",
        ]
        for override_rule, filter_id in blocking:
            lines.append(f"  override_rule: {override_rule}")
            if filter_id:
                lines.append(f"    responsible filter: {filter_id}")
            lines.append(f"    → add entry:")
            lines.append(f"        - override_rule: {override_rule}")
            if filter_id:
                # Include filter_id to scope this decision to one filter.
                # Omit it to create a wildcard that covers all filters for this override.
                lines.append(f"          filter_id: {filter_id}")
            lines += [
                f"          decision: keep    # or: discard",
                f"          reviewer: <name>",
                f"          date: <YYYY-MM-DD>",
                "",
            ]
        logger.error("\n".join(lines))
        raise PipelineError(
            f"coverage gap checkpoint: {len(blocking)} unresolved entr"
            f"{'y' if len(blocking) == 1 else 'ies'}"
        )


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
            logger.error(e)
        raise PipelineError(
            f"referential integrity: {len(errors)} included rule(s) reference "
            f"excluded rules"
        )


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
            logger.warning(msg)
        else:
            raise PipelineError(msg)


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
    parser = argparse.ArgumentParser(
        description="Preview filter policy effects without building."
    )
    parser.add_argument(
        "--preview", action="store_true",
        help="Preview what the current filter policy would include/exclude (default behavior).",
    )
    parser.parse_args()
    setup_logging()

    root = Path(__file__).resolve().parent.parent

    # check_overrides is imported here (not at module level) because it is only
    # needed for the standalone preview, not by the importable run() API.
    import check_overrides
    from config_schema import ConfigError

    try:
        config = config_schema.load_build_config(root)
        manifest_entries = config_schema.load_override_manifest(root)
        policy = config_schema.load_filter_policy(root)

        corpus_data = corpus.load_corpus(root)

        # Run override validation so preview faithfully reflects build behaviour,
        # including blocking on unresolved stale overrides before showing filter effects.
        check_overrides.validate(corpus_data.vendor_rules, corpus_data.override_rules,
                                 manifest_entries, config, root)

        vendor_remainder, _ = corpus.strip_superseded(corpus_data.vendor_rules, manifest_entries)
        post_strip = vendor_remainder + corpus_data.override_rules + corpus_data.custom_rules

        included, exclusion_record = run(post_strip, policy, root, manifest_entries, config)
    except (ConfigError, PipelineError) as exc:
        logger.error("Filter preview failed: {}", exc)
        sys.exit(1)

    lines = [
        f"PREVIEW — filter policy: {root / 'filters' / 'filter_policy.yaml'}",
        f"  default_mode : {policy.default_mode}",
        f"  active filters: {len(policy.filters)}",
        f"  corpus (post-strip): {len(post_strip)} rules",
        f"  included : {len(included)}",
        f"  excluded : {len(exclusion_record)}",
    ]
    for rec in exclusion_record:
        fid = rec['filter_id'] or 'default_mode'
        lines.append(
            f"  EXCLUDE  {rec['identifier']}  (filter: {fid}, reason: {rec['reason']})"
        )
    logger.info("\n".join(lines))


if __name__ == "__main__":
    main()
