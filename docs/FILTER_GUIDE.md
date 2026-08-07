# Filter Authoring Guide

| | |
|---|---|
| **Audience** | Ruleset maintainers who add, edit, or remove filters |
| **Companion docs** | [ARCHITECTURE.md](ARCHITECTURE.md) §4 (design reference), [DECISIONS.md](DECISIONS.md) D-8/D-9 |
| **The file you edit** | `filters/filter_policy.yaml` |
| **The tool you run** | `python scripts/apply_filters.py --preview` |

This is the how-to for writing filters. For the full design rationale, read
[ARCHITECTURE.md §4](ARCHITECTURE.md); this guide is the day-to-day reference for getting a
filter right and confirming its effect before you commit.

---

## 1. What a filter is (and is not)

A filter is an entry in `filters/filter_policy.yaml` that selects **which rules from the merged
corpus reach the final output**. It is a *selection layer*, not an editor:

- A filter **never edits or deletes a source rule.** A filtered-out rule stays in the repo and
  is re-included the moment you change the policy — no rule text is touched.
- Filters run **after** the override strip. A filter therefore **cannot resurrect a superseded
  vendor rule** — that identifier is already gone from the corpus by the time filters run.
- Filters key on rule metadata (identifier, tags, `meta`), so the quality of your filtering is
  only as good as the `meta` your rules carry.

---

## 2. The policy file at a glance

```yaml
# filters/filter_policy.yaml
version: 1
default_mode: include_all   # include_all = denylist (default) | exclude_all = allowlist
on_empty_output: fail       # fail | warn  — what to do if output falls below the floor
min_output_rules: 1         # the floor: fewer included rules than this trips on_empty_output
filters: []                 # your list of filter entries (see §3)
```

| Field | Values | Meaning |
|---|---|---|
| `default_mode` | `include_all` / `exclude_all` | The state of a rule that no filter matches. `include_all` = ship everything except what you `exclude` (denylist). `exclude_all` = ship nothing except what you `include` (allowlist). |
| `on_empty_output` | `fail` / `warn` | Action when the included count is below `min_output_rules`. |
| `min_output_rules` | integer (default `1`) | Below-floor guard — protects against an over-narrow allowlist shipping almost nothing. |
| `filters` | list | The filter entries. Empty list = pure `default_mode`. |

An empty or absent policy file is valid and means "include everything."

---

## 3. Anatomy of a filter entry

```yaml
filters:
  - id: F-001                      # audit id — appears in preview + build manifest
    description: "Drop vendor experimental rules"
    scope: vendor                  # global (default) | vendor | custom | overrides | rule:<Id>
    action: exclude                # include | exclude   (required)
    match:                         # selector; omit to match every rule in scope
      meta:
        status: experimental
    reason: "Not production-ready" # shows up in the exclusion record
    ticket: SEC-2001
    author: a.analyst
```

| Field | Required | Notes |
|---|---|---|
| `action` | **yes** | `include` or `exclude`. |
| `scope` | no (default `global`) | See §5. |
| `match` | no | The selector (§4). Omitting it matches **every** rule in scope. |
| `id` | no, but **set it** | Identifies the filter in `--preview` output and the build manifest. |
| `description` | no | Human summary. |
| `reason` | no, but **set it** | Recorded against every rule this filter excludes. |
| `ticket` | no | Traceability. |
| `author` | no | Traceability. |

Always give a filter an `id` and a `reason`: they are what a future maintainer sees in the
preview and in `build_manifest.json` when they ask "why was this rule dropped?"

---

## 4. Selectors (`match`)

All present conditions in a `match` block **AND together** — a rule must satisfy every one to
match. A `rule:<Identifier>` scope already names its target, so it needs no `match`.

### `name` — exact identifier
```yaml
match:
  name: Vendor_Emotet_Generic
```

### `name_glob` — shell-style wildcard on the identifier
```yaml
match:
  name_glob: "Vendor_Test_*"
```

### `name_regex` — regex search on the identifier
```yaml
match:
  name_regex: "_v[0-9]+$"
```

### `tags` — rule carries **all** listed tags
```yaml
match:
  tags: [experimental, windows]
```

### `meta` — exact key/value on a meta field (compared as strings)
```yaml
match:
  meta:
    status: experimental
```

### `meta_in` — meta value is one of a list
```yaml
match:
  meta_in:
    severity: [high, critical]
```

### `meta_date` — a date-valued meta field within a range
Compares a `YYYY-MM-DD` meta field against up to four bounds, all AND-ed. `before`/`after` are
**strict** (`<` / `>`); `on_or_before`/`on_or_after` are **inclusive** (`<=` / `>=`).
Supply a lower and an upper bound together to express "between two dates."

```yaml
match:
  meta_date:
    field: date              # the meta field to read (normalized before comparison)
    on_or_after: "2026-05-01"
    on_or_before: "2026-06-30"
```

**Bounds are always strict ISO**, and a malformed bound in the policy fails at load. Leniency
applies to rule input we don't control, never to policy we author.

**Rule values are normalized first.** A vendor feed that writes `date = "04/18/2026"` still
answers a `before: "2026-05-01"` bound correctly. Normalization is driven by `meta_dates` in
`config/build.yaml`: `%Y-%m-%d` is tried first, then any ISO 8601 date+time, then each
`input_formats` entry **in the order listed** (that order is the tie-break for ambiguous values
like `03/04/2026` — the shipped config reads month-first). Beyond ISO that list is the complete
accepted set; there is no fallback parser, so nothing is guessed at. Normalization happens at
comparison time only; the rule's source text is emitted verbatim and is never rewritten.

**A timestamped date answers on its date part.** `date = "2026-04-18T22:00:00-06:00"` is
compared as `2026-04-18` — the time is truncated and the offset ignored, never converted to
another day. Non-ISO timestamps work too once declared (`"%m/%d/%Y %H:%M"`). Bounds in this
policy stay strict ISO **date**-only: a bound with a time in it is a `ConfigError` at load.

### `older_than` / `newer_than` — relative bounds

These two live inside `meta_date` and are the same strict bounds as `before` and `after`,
written relative to a reference date instead of as fixed calendar days:

| Relative | Equivalent to | Reads as |
|---|---|---|
| `older_than: 5y` | `before: <as_of − 5y>` | dated more than five years ago |
| `newer_than: 30d` | `after: <as_of − 30d>` | dated within the last 30 days |

They express an intent — "retire anything not touched in five years" — once, instead of an
absolute bound that has to be edited on a schedule.

```yaml
match:
  meta_date:
    field: last_modified
    older_than: 5y
```

Together they are a **rolling window**. `newer_than: 2y` with `older_than: 6m` selects rules
aged between six months and two years, and keeps meaning that next quarter:

```yaml
match:
  meta_date:
    field: date
    newer_than: 2y      # lower bound: not older than two years
    older_than: 6m      # upper bound: at least six months old
```

The duration is an integer followed by `d`, `m`, or `y` — `730d`, `18m`, `5y`. No signs, no
compound forms (`1y6m`), no other units, and zero is rejected. Months and years are **calendar**
arithmetic, not a fixed day count: one year before 2024-02-29 is 2023-02-28, and one month
before 2026-03-31 is 2026-02-28.

A relative bound may be given alongside its absolute counterpart; like every other selector key
they AND, so the **tighter** one wins — the earlier of `older_than`/`before`, the later of
`newer_than`/`after`. Either relative bound on its own satisfies the "at least one bound" rule.

**The reference date** (`as_of`) resolves in this order:

1. `--as-of YYYY-MM-DD` on `scripts/build_ruleset.py` or `scripts/apply_filters.py --preview`
2. `as_of: "YYYY-MM-DD"` at the top level of this policy file — pins the window so the same
   commit filters identically on any day
3. today

It is resolved **once per run**, so every rule answers the same window even if the build
straddles midnight, and the resolved value is written to `build_manifest.json` as `as_of`.

> **Determinism (NFR-6).** With a relative bound in play, "identical inputs produce identical
> output" reads *identical inputs **and identical `as_of`***. The manifest records the `as_of`
> a build used, and passing it back with `--as-of` reproduces that build exactly. A policy with
> no relative bound is unaffected — nothing reads the reference date.

A rule that **lacks** the named field is simply not selected — an undated rule is never aged
out. (Vendor rules are exempt from `required_meta`, so a vendor feed without
dates passes an age cutoff untouched; use a `name_glob` or `meta` selector if you need to reach
those.) A rule whose field is **present
but unreadable** never reaches the filter engine: the build's unparsable-date gate runs first
and, per `meta_dates.on_unparsable`, either fails the build or drops the rule. Drops are seeded
into the exclusion record, so the manifest lists them in `filtered_rules` with a null
`filter_id` and an `unparsable date:` reason — that is how a recurring vendor format earns
a pinned entry in `input_formats`. `scripts/lint.py`
reports the same offenders earlier and lists them all at once.

---

## 5. Scope and precedence

Every rule's fate is decided by the **most specific** filter that matches it:

```
rule:<Identifier>   (most specific)
      ▲
   vendor / custom / overrides   (ruleset scope)
      ▲
   global            (least specific)
```

The highest-specificity level with a matching filter wins; a more specific filter overrides a
less specific one. So a `global` include-only allowlist can still be punched through by a
`rule:` exclude for one bad rule.

**Same-specificity tie-break.** If two filters at the *same* specificity match one rule and
disagree (`include` vs `exclude`), **exclude wins** — always, and regardless of the order the two
filters appear in. This is not configurable. If you need the rule shipped, either remove the
`exclude` filter or give the `include` a more specific scope (a `rule:` include beats a ruleset
`exclude`).

---

## 6. Recipes

**Suppress one noisy rule (denylist):**
```yaml
- id: F-noisy
  scope: rule:Custom_Noisy_Rule
  action: exclude
  reason: "FP storm — suppressed pending tuning"
  ticket: SEC-2002
```

**Ship only high/critical severity (allowlist):**
```yaml
default_mode: exclude_all
filters:
  - id: F-sev
    scope: global
    action: include
    match:
      meta_in:
        severity: [high, critical]
    reason: "Endpoint engine capacity"
```

**Retire vendor rules authored before a refresh date:**
```yaml
- id: F-retire-old-vendor
  scope: vendor
  action: exclude
  match:
    meta_date:
      field: date
      before: "2026-05-01"
  reason: "Superseded by refreshed vendor feed"
```

**Retire vendor rules not touched in five years (relative, no upkeep):**
```yaml
- id: F-retire-stale
  scope: vendor
  action: exclude
  match:
    meta_date:
      field: last_modified
      older_than: 5y
  reason: "Not refreshed in five years"
```

**Ship only rules from the last quarter (rolling allowlist):**
```yaml
default_mode: exclude_all
filters:
  - id: F-recent-only
    scope: global
    action: include
    match:
      meta_date:
        field: date
        newer_than: 90d
    reason: "Pilot profile — recent detections only"
```

**Quarantine the middle of the window (aged but not ancient):**
```yaml
- id: F-quarantine-aging
  scope: vendor
  action: exclude
  match:
    meta_date:
      field: date
      newer_than: 2y     # not older than two years
      older_than: 6m     # but at least six months old
  reason: "Aging vendor rules pending review"
```

**Drop a whole naming family:**
```yaml
- id: F-drop-test-family
  scope: vendor
  action: exclude
  match:
    name_glob: "Vendor_Test_*"
  reason: "Vendor test rules not for production"
```

**Drop everything carrying a tag:**
```yaml
- id: F-drop-experimental
  scope: global
  action: exclude
  match:
    tags: [experimental]
  reason: "Experimental rules excluded from the shipped profile"
```

---

## 7. Preview before you commit

Never commit a policy change without previewing its effect:

```bash
python scripts/apply_filters.py --preview
```

Sample output:

```
PREVIEW — filter policy: .../filters/filter_policy.yaml
  default_mode : include_all
  active filters: 3
  as_of : 2026-08-07
  corpus (post-strip): 214 rules
  included : 209
  excluded : 5
  EXCLUDE  Custom_Noisy_Rule  (filter: F-noisy, reason: FP storm — suppressed pending tuning)
  ...
```

Read it top-down: confirm the **included** count is what you expect, then scan the `EXCLUDE`
lines to confirm each dropped rule is dropped by the filter (and for the reason) you intended.

The `as_of` line is the reference date any relative bound was measured from. To see what a
policy will do on a future date — or to reproduce what an earlier build shipped — pass it
explicitly:

```bash
python scripts/apply_filters.py --preview --as-of 2027-01-01
```

The preview runs the same override validation the build does, so an unresolved **stale
override** will block the preview too — resolve that first (see ARCHITECTURE.md §3.3) before you
can see filter effects.

---

## 8. Checkpoints a filter can trigger

Filters run three cross-checks after the include set is computed. Any of them can block the
build:

**Coverage gap.** You excluded an override rule whose superseded vendor rules were already
removed — the corpus now has neither the vendor detection nor its replacement. The build blocks
until a reviewer records a decision in `filters/coverage_gap_decisions.yaml`:

```yaml
coverage_gap_decisions:
  - override_rule: Custom_Override_Emotet
    filter_id: F-001
    decision: keep        # keep = accept the gap consciously | discard = revise the filter
    reason: "Emotet campaign ended; neither detection needed in current profile"
    reviewer: a.analyst
    date: 2026-06-02
    ticket: SEC-2005
```
Omit `filter_id` to make the decision a wildcard covering all filters for that override rule.
A `discard` decision means: change the policy so the override is no longer excluded, then re-run.

**Referential integrity.** An included rule's condition references a rule your filter excluded.
Fix it by including the dependency, or by also excluding the referring rule.

**Empty / below-floor.** The final included count is below `min_output_rules`. Handled per
`on_empty_output` (`fail` blocks; `warn` proceeds). Usually a sign an allowlist is too narrow.

---

## 9. Gotchas & checklist

- **Lint validates the policy schema** — malformed scopes, unknown fields, bad enum values, and
  malformed `meta_date` bounds fail fast with a sourced message.
- **Lint also validates rule dates** — every field in `meta_dates.fields`, on every rule that
  carries it (vendor included), must be readable. This runs whether or not any `meta_date`
  filter exists, so a bad vendor date can't lie dormant until the day you write one. It is an
  error under `on_unparsable: fail` and a warning under `warn_and_drop`.
- **A dropped date still faces the cross-checks** — under `warn_and_drop` the removed rules are
  seeded into the exclusion record, so dropping an override rule whose superseded vendor rules
  are gone blocks on the coverage-gap checkpoint exactly as an `exclude` filter would.
- **`exclude` of an already-superseded vendor identifier is a harmless no-op** — the rule is
  already gone; it's recorded but not an error.
- **`include` naming an identifier absent from the corpus matches nothing** — lint warns that
  the named rule isn't present. A filter cannot resurrect a stripped rule.
- **Set `id` and `reason` on every filter** — they are the audit trail in preview and manifest.
- **Preview every change** with `apply_filters.py --preview` before committing.

Before you open the MR:

- [ ] `python scripts/apply_filters.py --preview` shows the expected included/excluded counts.
- [ ] Every new filter has an `id` and a `reason`.
- [ ] No coverage-gap / referential-integrity block (or a recorded decision resolves it).
- [ ] Allowlist changes keep the included count above `min_output_rules`.
