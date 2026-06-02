# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

**Initial development.** Design documents are complete; code does not yet exist. Build scripts, configs, vendor file, and test fixtures must be created per the implementation plan. See `docs/IMPLEMENTATION_PLAN.md` for the phased build order and definition of done per phase.

## Commands

```bash
pip install -r requirements.txt          # plyara, yara-python, pytest, pyyaml

python build/build_ruleset.py            # build dist/ artifacts
python scripts/lint.py                   # lint all rule files + filter policy
python scripts/check_overrides.py        # validate override manifest standalone
python scripts/apply_filters.py --preview  # preview filter effect without building
pytest tests/                            # run test suite against built ruleset
```

Build outputs land in `dist/` (gitignored): `merged_rules.yara`, `merged_rules.yarc`, `build_manifest.json`.

## Architecture

### Three rule classes
- **Vendor** — `vendor/vendor_rules.yara`, committed as received; updates are commits/MRs.
- **Custom** — `custom/` subdirectories (malware/, apt/, tooling/), in-house authored.
- **Overrides** — `overrides/overrides.yara`, in-house rules that *replace* specific vendor rules.

### Override = removal, not coexistence
YARA rejects duplicate identifiers in a single compilation unit. Overriding a vendor rule means **removing that vendor rule from the corpus** before compilation. Which vendor identifiers each override supersedes is declared in `overrides/override_manifest.yaml`. A stale override (override names a vendor rule that no longer exists) is a hard failure by default — it means a suppressed detection may have silently re-enabled.

### Filter policy
`filters/filter_policy.yaml` is a **selection layer** on the post-merge corpus. It never edits or deletes source rules — a filtered-out rule stays in the repo. Filters run **after** the override strip; a filter cannot resurrect a superseded rule.

**Resolution:** `rule:<Identifier>` scope > ruleset scope (`vendor`/`custom`/`overrides`) > `global`. Same-specificity tie-break is `exclude_wins` by default (D-8). Default mode is `include_all` (D-9).

**Cross-checks that must run after the include set is computed:**
1. **Coverage-gap guard** — excluding an override rule whose superseded vendor rules were already removed leaves neither detection. Hard fail by default (D-10).
2. **Referential integrity** — an excluded rule still referenced in an included rule's condition is an error.
3. **Empty/below-floor guard** — output below `min_output_rules` triggers `on_empty_output` policy.

### Build sequence (`build/build_ruleset.py`)
Parse → load manifest + policy + config → validate overrides → strip superseded vendor rules → apply filter policy → run cross-checks → collision check → topological order → emit source → compile (authoritative validation gate) → write manifest.

**The compile step is the validation authority.** Never emit an artifact that hasn't compiled. The compile is non-negotiable even when only source output is requested.

### Rule ordering invariant
A referenced rule must precede the rule that references it. Default emission order: vendor-remainder → overrides → custom. Intra-corpus references trigger topological reordering; a cycle is a compile error.

### Config is the single source of truth
`config/build.yaml` holds `output_formats`, `yara_modules`, `external_variables`, `override_policy`, `filter_conflict_policy`, and `required_meta`. All scripts (build, lint, test harness) read it — never hardcode these values.

## Open decisions (implement as configurable defaults)

| ID | Topic | Default |
|---|---|---|
| D-1 | Rule consumer / YARA engine target | **RESOLVED:** Corelight Fleet Manager — modules `pe`, `elf`, `math` (verify `dotnet` before use) |
| D-4 | Stale-override policy | hard fail |
| D-8 | Same-specificity filter tie-break | `exclude_wins` |
| D-9 | Filter default mode | `include_all` |
| D-10 | Coverage-gap policy | hard fail |
| D-11 | Single vs. multiple output profiles | single policy / single output in v1 |

Implement D-8 and D-9 as reads from `config/build.yaml` and `filters/filter_policy.yaml` respectively — not hardcoded — so they can be changed without a code edit.

## Key constraints

- **No live malware.** Tests use synthetic/inert fixtures in `tests/samples/` or hash-referenced samples fetched from a secured store. Never commit malicious payloads.
- **Rule output order must be deterministic** (NFR-6) — identical inputs must produce identical output on every run.
- **Output is source (`.yara`) only** (D-2 resolved). Corelight Fleet Manager handles its own compilation internally; `.yarc` is not emitted as an artifact. The CI compile step still runs as the validation gate.
- The filter engine should accept a policy as an argument (not read a global) to keep the door open for multiple output profiles later (D-11) without a rewrite.
- All tests must validate the *built* `dist/` artifacts, not re-build inline — this is what CI does (build artifacts are passed to the test stage).

## Required metadata fields for custom/override rules

Every rule must carry: `author`, `date`, `description`, `reference`, `severity`. Lint rejects rules missing any of these (`required_meta` in `config/build.yaml`).
