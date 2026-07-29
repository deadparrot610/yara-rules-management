# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

**Built through Phase 7** (scaffold, merge engine, override validation, filter engine, lint, test harness, GitLab CI/CD, packaging/releases). Phase 8 (PCAP testing job) is deferred pending D-3; D-6 (sample sourcing) is also still open. See `docs/IMPLEMENTATION_PLAN.md` for the phase definitions.

## Commands

```bash
pip install -r requirements.txt          # plyara, yara-python, pytest, pyyaml, python-dateutil

python scripts/build_ruleset.py          # build dist/ artifacts
python scripts/lint.py                   # lint all rule files + filter policy
ruff check scripts/ tests/               # lint the pipeline's Python (also runs in CI)
python scripts/check_overrides.py        # validate override manifest standalone
python scripts/apply_filters.py --preview  # preview filter effect without building
pytest tests/                            # run test suite against built ruleset
```

Build outputs land in `dist/` (gitignored): `merged_rules.yara`, `build_manifest.json`.

## Architecture

### Three rule classes
- **Vendor** — `rules/vendor/*.yara`, one or more files committed as received; every update (add, replace, or remove) is an MR so the diff and stale-override check run before merge.
- **Custom** — `rules/custom/` subdirectories (malware/, apt/, tooling/), in-house authored.
- **Overrides** — `rules/overrides/overrides.yara`, in-house rules that *replace* specific vendor rules.

### Override = removal, not coexistence
YARA rejects duplicate identifiers in a single compilation unit. Overriding a vendor rule means **removing that vendor rule from the corpus** before compilation. Which vendor identifiers each override supersedes is declared in `overrides/override_manifest.yaml`. A stale override (override names a vendor rule that no longer exists) blocks the pipeline and requires a reviewer to record a keep/discard decision in `overrides/stale_override_decisions.yaml`; subsequent runs apply recorded decisions automatically. An unresolved stale override with no recorded decision is always a hard block.

### Filter policy
`filters/filter_policy.yaml` is a **selection layer** on the post-merge corpus. It never edits or deletes source rules — a filtered-out rule stays in the repo. Filters run **after** the override strip; a filter cannot resurrect a superseded rule.

**Resolution:** `rule:<Identifier>` scope > ruleset scope (`vendor`/`custom`/`overrides`) > `global`. Same-specificity conflicts are always resolved exclude-wins (D-8) — a fixed invariant of the filter engine, not a setting. Default mode is `include_all` (D-9).

**Cross-checks that must run after the include set is computed:**
1. **Coverage-gap guard** — excluding an override rule whose superseded vendor rules were already removed leaves neither detection. Blocks and requires a reviewer keep/discard decision recorded in `filters/coverage_gap_decisions.yaml`; unresolved gaps are always a hard block.
2. **Referential integrity** — an excluded rule still referenced in an included rule's condition is an error.
3. **Empty/below-floor guard** — output below `min_output_rules` triggers `on_empty_output` policy.

### Build sequence (`scripts/build_ruleset.py`)
Parse → load manifest + policy + config → validate overrides → strip superseded vendor rules → collision check → module-allowlist check → apply filter policy → run cross-checks → topological order → compile (authoritative validation gate) → emit source → write manifest.

**The compile step is the validation authority.** It runs against the in-memory merged source *before* anything is written to `dist/` — never emit an artifact that hasn't compiled. The compile is non-negotiable even when only source output is requested. The compile gate cannot catch modules the deployment engine lacks (yara-python supports more than Corelight), so every import must also pass the `yara_modules` allowlist from `config/build.yaml` (enforced in lint and build).

### Rule ordering invariant
A referenced rule must precede the rule that references it. Default emission order: vendor-remainder → overrides → custom. Intra-corpus references trigger topological reordering; a cycle is a compile error.

### Config is the single source of truth
`config/build.yaml` holds `output_formats`, `yara_modules`, `external_variables`, `stale_override_decisions`, `coverage_gap_decisions`, `required_meta`, and `meta_dates`. All scripts (build, lint, test harness) read it — never hardcode these values.

## Open decisions (implement as configurable defaults)

| ID | Topic | Default |
|---|---|---|
| D-1 | Rule consumer / YARA engine target | **RESOLVED:** Corelight Fleet Manager — modules `pe`, `elf`, `math` (verify `dotnet` before use) |
| D-5 | Vendor file granularity | **RESOLVED:** multiple `.yara` files in `rules/vendor/`; each update via MR |
| D-4 | Stale-override policy | **RESOLVED:** manual checkpoint; reviewer keep/discard decision recorded in `overrides/stale_override_decisions.yaml` |
| D-8 | Same-specificity filter tie-break | **RESOLVED:** exclude wins — fixed in the filter engine, not configurable |
| D-9 | Filter default mode | **RESOLVED:** `include_all` (denylist) |
| D-10 | Coverage-gap policy | **RESOLVED:** manual checkpoint; reviewer keep/discard decision recorded in `filters/coverage_gap_decisions.yaml` |
| D-11 | Single vs. multiple output profiles | **RESOLVED:** single output file; filter engine takes policy as an argument to allow future profiles |

Implement D-9 as a read from `filters/filter_policy.yaml` — not hardcoded — so it can be changed without a code edit. D-8 is deliberately the exception: exclude-wins is hardcoded in `scripts/apply_filters.py`, since any other tie-break either makes output depend on filter list order or blocks the pipeline on a conflict the policy already knows how to resolve.

## Key constraints

- **No live malware.** Tests use synthetic/inert fixtures in `tests/samples/` or hash-referenced samples fetched from a secured store. Never commit malicious payloads.
- **Rule output order must be deterministic** (NFR-6) — identical inputs must produce identical output on every run.
- **Output is source (`.yara`) only** (D-2 resolved). Corelight Fleet Manager handles its own compilation internally; `.yarc` is not emitted as an artifact. The CI compile step still runs as the validation gate.
- The filter engine should accept a policy as an argument (not read a global) to keep the door open for multiple output profiles later (D-11) without a rewrite.
- All tests must validate the *built* `dist/` artifacts, not re-build inline — this is what CI does (build artifacts are passed to the test stage).

## Required metadata fields for custom/override rules

Every **custom and override** rule must carry: `author`, `date`, `description`, `reference`, `severity`. Lint rejects rules missing any of these (`required_meta` in `config/build.yaml`). Vendor rules are exempt — they are committed as received.

## Rule date normalization

`meta_dates` in `config/build.yaml` declares which meta fields hold dates (`fields`), which non-ISO formats to accept (`input_formats`, tried **in the listed order** after ISO — order is the ambiguity tie-break, and the shipped config is month-first), and whether to fall back to `dateutil` (`fuzzy_fallback`).

Two separate concerns, deliberately not merged: `required_meta` is about **completeness** and exempts vendor; `lint_dates` is about **readability** and applies to every origin, firing only when a configured field is present and unparseable. Vendor is the reason it exists.

Normalization happens at comparison time in `apply_filters` and never rewrites rule source — vendor files stay committed as received. Reinterpreted values are recorded in the build manifest under `meta_date_normalizations`, which is how a recurring vendor format gets promoted out of the fallback and pinned in `input_formats`. `parse_iso_date` remains ISO-only for policy files: leniency applies to input we don't control, never to config we author.
