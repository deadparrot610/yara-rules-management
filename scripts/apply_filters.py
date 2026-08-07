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
from datetime import date
from pathlib import Path

from loguru import logger

import config_schema
import corpus
from corpus import PipelineError
from logging_setup import setup_logging


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------

def resolve_as_of(policy, override: date | None = None) -> date:
    """The reference date relative bounds (meta_date.older_than) resolve against.

    Precedence: an explicit override (--as-of) > `as_of:` pinned in the policy
    file > today. The single place this chain is spelled out — build and preview
    both come through here, so a build and its preview agree.
    """
    return override or policy.as_of or date.today()


def parse_as_of_arg(value: str | None) -> date | None:
    """Parse an --as-of CLI value. Shared by the build and the preview so both
    accept exactly what the policy file's `as_of` accepts."""
    if value is None:
        return None
    try:
        return config_schema.parse_iso_date(value)
    except ValueError as exc:
        raise config_schema.ConfigError(
            f"--as-of must be a YYYY-MM-DD date, got {value!r}"
        ) from exc


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

def _selector_matches(filter_entry, rule, rule_tags=None, meta_dates=None,
                      as_of=None) -> bool:
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

    if match.meta_date is not None and not _meta_date_matches(
        match.meta_date, rule, meta_dates, as_of
    ):
        return False

    return True


def _meta_date_matches(spec, rule, meta_dates=None, as_of=None) -> bool:
    """Evaluate a FilterDateRange against a rule.

    The rule's raw meta value is normalized per config.meta_dates before the
    comparison, so a vendor rule dated '04/18/2026' still answers a
    `before: 2026-05-01` bound correctly. Normalization happens here, at
    comparison time, and never touches rule.raw_text — that string is emitted
    verbatim into dist/, and vendor files are committed as received.

    The relative bounds (`older_than: 5y`, `newer_than: 30d`) resolve against
    `as_of` into the same strict bounds `before` and `after` express; each ANDs
    with its absolute counterpart, so the tighter of the two wins. Both together
    are a rolling window.

    A rule missing the field is simply not selected (returns False) — an
    undated rule is never aged out. A field that is present but unreadable is a
    hard error — a typo'd rule date must not silently escape the filter.
    lint.lint_dates catches these earlier and lists them all at once; this stays
    as the backstop for a build run without lint.
    """
    try:
        before = spec.effective_before(as_of)
        after = spec.effective_after(as_of)
    except ValueError as exc:
        raise PipelineError(str(exc)) from exc
    raw = rule.meta.get(spec.field)
    if raw is None:
        return False
    try:
        value, _ = config_schema.normalize_meta_date(raw, meta_dates)
    except ValueError as exc:
        raise PipelineError(
            f"rule {rule.identifier!r}: meta field {spec.field!r} value {raw!r} "
            f"is not a recognized date; "
            f"{config_schema.describe_accepted_dates(meta_dates)}; "
            f"run scripts/lint.py for the full list of offenders"
        ) from exc
    if after is not None and not value > after:
        return False
    if before is not None and not value < before:
        return False
    if spec.on_or_after is not None and not value >= spec.on_or_after:
        return False
    if spec.on_or_before is not None and not value <= spec.on_or_before:
        return False
    return True


# ---------------------------------------------------------------------------
# Per-rule resolution
# ---------------------------------------------------------------------------

def _resolve_rule(
    rule, filters: list, default_mode: str, meta_dates=None, as_of=None,
) -> tuple[str, object]:
    """Return (action, responsible_filter | None)."""
    applicable = [
        f for f in filters
        if _scope_applies(f.scope, rule)
        and _selector_matches(f, rule, None, meta_dates, as_of)
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

    # Conflict at the same specificity level — exclude always wins (D-8).
    # action values are validated at load (include|exclude), so a disagreement
    # guarantees at least one 'exclude' here.
    for f in reversed(best):
        if f.action == "exclude":
            return "exclude", f
    raise AssertionError(
        "unreachable: conflicting same-specificity filters with no 'exclude' action"
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
                f"  - Restore {override_rule!r} to the output"
            )
            if filter_id:
                lines.append(
                    f"    (revise the filter policy; responsible filter: {filter_id})")
            else:
                lines.append(
                    "    (no responsible filter — check for an unreadable rule date)")
        logger.warning("\n".join(lines))

    if blocking:
        lines = [
            "COVERAGE GAP CHECKPOINT — build blocked.",
            "",
            "The following override rules are not in the output (excluded by a filter,",
            "or dropped for an unreadable date), but the vendor rules they superseded",
            "have already been removed. Record a decision in:",
            f"  {config.coverage_gap_decisions}",
            "",
        ]
        for override_rule, filter_id in blocking:
            lines.append(f"  override_rule: {override_rule}")
            if filter_id:
                lines.append(f"    responsible filter: {filter_id}")
            lines.append("    → add entry:")
            lines.append(f"        - override_rule: {override_rule}")
            if filter_id:
                # Include filter_id to scope this decision to one filter.
                # Omit it to create a wildcard that covers all filters for this override.
                lines.append(f"          filter_id: {filter_id}")
            lines += [
                "          decision: keep    # or: discard",
                "          reviewer: <name>",
                "          date: <YYYY-MM-DD>",
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
    pre_excluded: list[dict] | None = None,
    as_of: date | None = None,
) -> tuple[list, list[dict]]:
    """Apply the filter policy to the post-strip corpus.

    policy is a config_schema.FilterPolicy; config is a config_schema.BuildConfig.
    Returns (included_rules, exclusion_record).
    exclusion_record: list of {identifier, filter_id, reason}.

    as_of is the reference date for relative bounds (meta_date.older_than),
    resolved once here via resolve_as_of so every rule in one run answers the
    same window — a build that straddles midnight must not filter two ways.

    pre_excluded carries rules already removed from `rules` before this call —
    today, only the unparsable-date drops (corpus.drop_unparsable_dates). They
    are seeded into exclusion_record so the three cross-checks below treat them
    exactly like a filter exclusion: dropping an override rule whose superseded
    vendor rules are gone still trips the coverage-gap checkpoint, a dropped rule
    still referenced by an included condition is still an error, and drops count
    against the output floor. Their filter_id is None, which the coverage-gap
    lookup already handles as the wildcard key.
    """
    default_mode = policy.default_mode
    filters = policy.filters
    as_of = resolve_as_of(policy, as_of)

    included = []
    exclusion_record = list(pre_excluded or [])

    for rule in rules:
        action, responsible = _resolve_rule(
            rule, filters, default_mode, config.meta_dates, as_of)
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
    parser.add_argument(
        "--as-of", metavar="YYYY-MM-DD",
        help="Reference date for relative bounds (meta_date.older_than). "
             "Defaults to the policy's as_of, else today.",
    )
    args = parser.parse_args()
    setup_logging()

    root = Path(__file__).resolve().parent.parent

    # check_overrides is imported here (not at module level) because it is only
    # needed for the standalone preview, not by the importable run() API.
    import check_overrides
    from config_schema import ConfigError

    try:
        as_of_override = parse_as_of_arg(args.as_of)
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

        effective_as_of = resolve_as_of(policy, as_of_override)
        included, exclusion_record = run(post_strip, policy, root, manifest_entries,
                                         config, as_of=effective_as_of)
    except (ConfigError, PipelineError) as exc:
        logger.error("Filter preview failed: {}", exc)
        sys.exit(1)

    lines = [
        f"PREVIEW — filter policy: {root / 'filters' / 'filter_policy.yaml'}",
        f"  default_mode : {policy.default_mode}",
        f"  active filters: {len(policy.filters)}",
        f"  as_of : {effective_as_of.isoformat()}",
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
