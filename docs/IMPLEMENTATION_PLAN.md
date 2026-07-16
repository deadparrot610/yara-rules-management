# Implementation Plan — YARA Rule Pipeline

| | |
|---|---|
| **Status** | Approved v1.0 |
| **Audience** | Claude Code + maintainers |
| **Last updated** | 2026-06-02 |

This is the build order. It is sequenced so the riskiest, most load-bearing components — the merge engine, then the filter engine that sits on top of it — are proven before anything depends on them. Each phase has a definition of done you can verify before moving on.

**Changelog**
- v1.1 — Reordered final phases: packaging & releases brought forward to Phase 7; PCAP testing deferred to Phase 8 pending scoping.
- v1.0 — Approved; consistency review complete; phases 2 and 3 updated to reflect D-4 and D-10 resolutions.
- v0.2 — Inserted Phase 3 (filter policy engine); renumbered later phases; updated sequencing notes.
- v0.1 — Initial draft.

---

## Phase 0 — Scaffold
**Build:** repository tree from ARCHITECTURE.md §2; `config/build.yaml` with defaults from DECISIONS.md; `requirements.txt` (`plyara`, `yara-python`, `pytest`, `pyyaml`); `.gitignore` (ignore `dist/`); one placeholder `.yara` file in `rules/vendor/`, one sample `rules/custom/` rule, an empty `rules/overrides/` set, empty `override_manifest.yaml`, and an empty `filters/filter_policy.yaml` (`default_mode: include_all`, no filters).
**Done when:** `pip install -r requirements.txt` succeeds and the tree matches the design.

## Phase 1 — Merge engine (core; build first)
**Build:** `scripts/build_ruleset.py` doing parse → load manifest → strip superseded → collision check → order → emit → compile → write `build_manifest.json`, per ARCHITECTURE.md §5 (filter step stubbed/pass-through for now).
**Done when:** given a real vendor file plus at least one override, it produces `dist/merged_rules.yara`, the superseded vendor rule is absent from the output, the merged corpus compiles via yara-python, and the manifest lists what was removed. **Validate this against an actual vendor file before proceeding** — everything else hangs off it.

## Phase 2 — Override validation & stale detection
**Build:** `scripts/check_overrides.py` implementing the manifest rules (override_rule exists, supersedes exists in vendor, no duplicate claims), wired into the build and runnable standalone. Implement the stale-override checkpoint from ARCHITECTURE.md §3.3: block on any stale entry with no recorded decision in `overrides/stale_override_decisions.yaml`; apply recorded decisions automatically; report required cleanup actions for `discard` decisions.
**Done when:** an override naming a nonexistent vendor rule blocks with a clear checkpoint prompt; a reviewer-recorded `keep` decision causes a subsequent run to pass; a reviewer-recorded `discard` decision is reported as a required cleanup action; an override naming a duplicate-claimed vendor rule errors; and a stale entry with no recorded decision is always a hard block.

## Phase 3 — Filter policy engine
**Build:** `scripts/apply_filters.py` implementing ARCHITECTURE.md §4 — selector matching (name/glob/regex, tags, meta/meta_in), scope specificity resolution (rule > ruleset > global), tie-break per `filter_conflict_policy` (`exclude_wins`; D-8), and the three cross-checks: coverage-gap (excluded override that removed vendor rules → checkpoint per ARCHITECTURE.md §4.5; reads `filters/coverage_gap_decisions.yaml`, blocks on unresolved gaps), referential integrity (excluded rule referenced by an included rule → error), and empty/below-floor guard. Wire it into the build between strip and order (§5 steps 5–6). Extend `build_manifest.json` to record filtered-out rules with the responsible filter id and reason. Provide a standalone preview mode (show what a policy would include/exclude without building).
**Done when:** an `exclude` filter removes matching rules from the output but not from source; `default_mode: include_none` (allowlist mode) ships only explicitly included rules; a more-specific `rule:` filter overrides a conflicting `global` filter; excluding an override that removed vendor rules triggers the coverage-gap checkpoint (blocks with no recorded decision, passes with a recorded `keep` decision); excluding a rule referenced by a surviving rule errors; and an empty result triggers the guard.

## Phase 4 — Linting & metadata + filter-policy schema
**Build:** `scripts/lint.py` — per-file compile, `plyara` parseability, required-meta validation against `required_meta`, naming conventions, and **filter policy schema validation** (valid scopes/actions/selectors; warn when a `rule:`/exact-`name` selector names an identifier absent from the corpus).
**Done when:** a syntax error is reported against its specific source file, a rule missing a required meta field fails lint, and a malformed filter policy fails lint.

## Phase 5 — Test harness
**Build:** `tests/test_ruleset.py` (pytest, JUnit output), `tests/test_cases.yaml` schema, a few synthetic/inert fixtures, and a `clean/` corpus for the false-positive gate. Include cases that prove (a) a superseded vendor rule no longer matches and (b) a filtered-out rule no longer matches — end-to-end evidence the override and filter both took effect.
**Done when:** `pytest` validates expected match/no-match against the built ruleset, the false-positive gate fails on any clean-corpus match, and JUnit XML is produced.

## Phase 6 — GitLab CI/CD (lint → build → test)
**Build:** pinned Docker image (YARA + Python deps); `.gitlab-ci.yml` with lint, build, test stages; `dist/` passed build→test as artifacts; JUnit results surfaced in MRs.
**Done when:** a pushed branch runs all three stages, a broken rule or bad filter policy fails the pipeline, and test results render in the merge request.

## Phase 7 — Packaging & releases
**Build:** `package` stage on tags publishing the versioned ruleset + manifest to the GitLab Package Registry; finalize `README.md` (author workflow, how to add an override, how to write a filter, how to update the vendor file).
**Done when:** a tag produces a downloadable, versioned release artifact tied to its input hashes via the manifest.

## Phase 8 — PCAP testing job _(deferred — approach TBD)_
**Build:** `pcap-test` stage, `when: manual`; ingest per D-3 default (CI file variable); scan raw and/or carved files; write a match-report artifact.
**Done when:** a maintainer triggers the job with a test capture and downloads a match report. _(Deferred pending scoping; depends on D-3.)_

---

## Sequencing notes for Claude Code
- **D-1 (consumer), D-8 (tie-break), D-9 (default mode)** are all resolved — see DECISIONS.md §3. Implement directly from their resolutions: Corelight Fleet Manager; `exclude_wins`; `include_all`. Both D-8 and D-9 must be read from `config/build.yaml`/`filter_policy.yaml`, not hardcoded, so they can be changed without a code edit.
- Build the filter engine (Phase 3) so it takes a policy as an input argument — this keeps the door open to multiple output profiles later (D-11) without a rewrite.
- Keep `config/build.yaml` and `filters/filter_policy.yaml` the single sources for modules, externals, formats, and selection policy; have the build, lint, and tests all read them rather than hardcoding.
- Treat the Phase 1/§5 compile step as the validation authority throughout — never emit an artifact that hasn't compiled, and rely on it as the backstop for any dependency break a filter might introduce.
- Commit a representative (sanitized) vendor file early so Phases 1 and 3 are tested against reality, not a toy.
