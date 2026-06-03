# Technical Design — YARA Rule Management & Build Pipeline

| | |
|---|---|
| **Status** | Draft v0.2 |
| **Companion docs** | PRD.md, DECISIONS.md, IMPLEMENTATION_PLAN.md |
| **Last updated** | 2026-06-02 |

This document describes how the system in the PRD is built. It assumes the reader has read the PRD's Section 2 (the duplicate-identifier constraint), which is the foundation for everything here.

**Changelog**
- v0.3 — Resolved D-4: stale-override policy is now a manual checkpoint with a persistent decisions file (`overrides/stale_override_decisions.yaml`); updated §2, §3.2, added §3.3, updated §5 and §7.
- v0.2 — Added §4 Filter policy model; updated §2 (filters/ tree), §5 build sequence (filter stage + cross-checks), §7 components (apply_filters.py), §10 CI, and the build manifest contents.
- v0.1 — Initial draft.

---

## 1. System overview

The system is a Git repository plus a CI/CD pipeline. Authors commit rules into one of three trees (vendor, custom, overrides), declare overrides in a manifest, and declare a filter policy. On every change the pipeline lints the inputs, parses and merges them into one corpus while removing superseded vendor rules, applies the filter policy to select which rules reach the output, compiles the result as the validation gate, runs scan-based tests, and — on a release — publishes a versioned artifact with a manifest. An optional manual job validates rules against an uploaded PCAP.

```
 author commit ─▶ lint ─▶ build (parse→strip→merge→filter→compile) ─▶ test ─▶ [pcap-test, manual] ─▶ package (on tag)
                              │                                          │                              │
                              ▼                                          ▼                              ▼
                     dist/merged_rules.yara                   JUnit results + match report     versioned release artifact
                     dist/merged_rules.yarc                   false-positive gate              + build manifest
                     build_manifest.json
```

## 2. Repository structure

```
yara-rules/
├── .gitlab-ci.yml
├── README.md
├── PRD.md
├── ARCHITECTURE.md
├── DECISIONS.md
├── IMPLEMENTATION_PLAN.md
├── requirements.txt
├── config/
│   └── build.yaml              # output formats, YARA modules, external vars, policy flags
├── vendor/
│   └── *.yara                  # one or more vendor files; committed as received; updates via MR
├── custom/                     # net-new in-house rules, grouped by category
│   ├── malware/
│   ├── apt/
│   └── tooling/
├── overrides/
│   ├── overrides.yara                  # the replacement rules
│   ├── override_manifest.yaml          # which vendor rules each override supersedes + why
│   └── stale_override_decisions.yaml   # reviewer keep/discard decisions for stale overrides
├── filters/
│   └── filter_policy.yaml      # declarative include/exclude selection layer
├── build/
│   └── build_ruleset.py        # parse → strip → merge → filter → order → compile → manifest
├── scripts/
│   ├── lint.py                 # per-file syntax + metadata schema + filter-policy validation
│   ├── check_overrides.py      # stale-override / conflict detection
│   └── apply_filters.py        # filter resolution + cross-checks (usable standalone)
├── tests/
│   ├── samples/                # INERT/synthetic fixtures only (see §9)
│   ├── clean/                  # benign corpus for the false-positive gate
│   ├── test_cases.yaml         # rule -> expected match / no-match
│   └── test_ruleset.py         # pytest harness, emits JUnit XML
└── dist/                       # build output (gitignored; produced in CI)
```

## 3. The override model

### 3.1 Why removal, not coexistence
A single deployable file is a single compilation unit, and YARA rejects duplicate identifiers within it. Therefore overriding a vendor rule means **deleting that vendor rule from the corpus** before compilation and inserting the in-house replacement in its place. An override may supersede more than one vendor rule (e.g. a tightened rule that replaces two noisy vendor variants).

### 3.2 The override manifest
The manifest is the authoritative, reviewable declaration that drives removal and provides the audit trail:

```yaml
overrides:
  - override_rule: Custom_Override_Emotet      # identifier defined in overrides.yara
    supersedes:                                # vendor identifiers to remove
      - Vendor_Emotet_Generic
      - Vendor_Emotet_v2
    reason: "Vendor rule fires on internal packer; condition tightened."
    ticket: SEC-1234
    author: a.analyst
    date: 2026-05-30
```

Validation rules the build enforces on the manifest:
- Every `override_rule` must be a real identifier defined in `overrides/`.
- Every entry in `supersedes` must currently exist in the vendor corpus. A miss is a **stale override** (FR-6) — handled via the checkpoint mechanism in §3.3.
- No two override entries may claim the same vendor identifier (ambiguous removal).

### 3.3 Stale-override checkpoint and decisions file

A stale override (a `supersedes` entry that names a vendor rule no longer present in the corpus) means a detection the team believed was suppressed may have silently returned. Rather than hard-failing or silently continuing, the pipeline **blocks and requires a reviewer decision** for each stale entry.

**Checkpoint flow:**
1. `check_overrides.py` detects one or more stale entries and prints a clear prompt per entry, listing the override rule, the missing vendor identifier, and the two options.
2. The reviewer decides for each stale entry:
   - **keep** — the override rule is still valuable (e.g. it catches variants not covered by the now-absent vendor rule); retain it in the corpus without a supersession claim for this identifier.
   - **discard** — the override rule is no longer needed now that the vendor rule is gone; remove it from the override manifest and `overrides.yara`.
3. The reviewer records the decision in `overrides/stale_override_decisions.yaml` and commits it. On the next pipeline run the checkpoint reads this file, applies recorded decisions automatically, and only blocks for entries that still have no recorded decision.

**Decisions file format:**

```yaml
stale_override_decisions:
  - override_rule: Custom_Override_Emotet
    missing_vendor_rule: Vendor_Emotet_v3
    decision: keep                  # keep | discard
    reason: "Still catches Emotet loaders not covered by v3"
    reviewer: a.analyst
    date: 2026-06-02
    ticket: SEC-1234
```

**Invariants:**
- A stale entry with no recorded decision is always a hard block — there is no silent pass-through.
- A `discard` decision signals that the override rule and its manifest entry should be removed; `check_overrides.py` reports this as a required cleanup action rather than applying it automatically (a human removes the rule and entry via MR).
- The decisions file is committed to the repo and version-controlled, providing a full audit trail of every stale-override resolution.
- When a vendor update re-introduces a previously absent identifier, the corresponding decision record becomes stale itself; `check_overrides.py` warns and the reviewer removes or supersedes the old decision.

## 4. Filter policy model (rule selection layer)

The filter policy decides **which rules from the post-merge corpus appear in the final output**. It never edits or deletes source rules — it is a selection layer, so a filtered-out rule remains in the repository and can be re-included by changing policy. Filters are called "filters" (not "rules") throughout to avoid confusion with YARA rules.

### 4.1 The filter policy file

```yaml
# filters/filter_policy.yaml
version: 1
default_mode: include_all        # include_all (denylist) | include_none (allowlist)   [D-9]
on_empty_output: fail            # fail | warn
min_output_rules: 1              # below-floor guard
filters:
  - id: F-001
    description: "Drop vendor experimental rules"
    scope: vendor                # global | vendor | custom | overrides | rule:<Identifier>
    action: exclude              # include | exclude
    match:                       # selector; conditions AND together
      meta:
        status: experimental
    reason: "Not production-ready"
    ticket: SEC-2001
    author: a.analyst

  - id: F-002
    description: "Globally keep only high/critical severity"
    scope: global
    action: include
    match:
      meta_in:
        severity: [high, critical]
    reason: "Endpoint engine capacity"

  - id: F-003
    description: "Suppress one noisy custom rule pending tuning"
    scope: rule:Custom_Noisy_Rule
    action: exclude
    reason: "FP storm"
    ticket: SEC-2002
```

**Selector dimensions** (all present conditions must match): `name` (exact), `name_glob`, `name_regex`, `tags` (rule has all listed tags), `meta` (exact key/value), `meta_in` (meta value is in a list). The selector is omitted for a `rule:<Identifier>` scope, which already names its target.

### 4.2 Resolution algorithm
For each YARA rule `R` in the post-merge corpus:
1. `state = default_mode` (included if `include_all`, excluded if `include_none`).
2. Collect all filters whose scope applies to `R` and whose selector matches `R`.
3. Decide by **scope specificity**: `rule:` (most specific) > ruleset (`vendor`/`custom`/`overrides`) > `global`. The highest-specificity level that has a matching filter determines `R`'s state via that filter's `action`. A more specific filter therefore overrides a less specific one.
4. **Tie-break** at the same specificity, if both `include` and `exclude` match: apply the configured policy — **exclude-wins** (default), `last_match_wins`, or `error` (fail and require human resolution). [D-8]

### 4.3 Cross-checks (run after the include set is computed)
- **Coverage-gap guard (FR-22).** If `R` is an override rule, `R` is excluded by the policy, and `R` superseded vendor rules that the merge removed, the corpus now has neither the vendor detection nor its replacement. This is reported and, per policy (default fail, D-10), blocks the build. Mirrors the stale-override guard.
- **Referential integrity (FR-23).** For every included rule, all rule identifiers referenced in its condition (including private rules) must also be included. An excluded-but-referenced rule is an error, reported by name and referrer. (The compile step in §5 is the backstop, but this check produces a clear, source-attributed message.)
- **Empty/below-floor guard (FR-23).** If the final included count is `0` or below `min_output_rules`, act per `on_empty_output`. Protects against an over-narrow allowlist shipping almost nothing.

### 4.4 Interaction notes
- Filtering runs **after** the override strip, so an `include` filter naming an already-superseded vendor identifier matches nothing; lint warns that the named rule is absent (it cannot be resurrected by a filter — that identifier no longer exists in the corpus).
- Excluding a vendor rule that an override already removed is a harmless no-op (already gone); it is recorded but not an error.

## 5. Build logic (`build/build_ruleset.py`)

Sequence:
1. **Parse** the vendor file(s), `overrides/`, and `custom/` with `plyara`, producing per-rule structures keyed by identifier (with tags and meta retained for filtering).
2. **Load** `override_manifest.yaml`, `filters/filter_policy.yaml`, and `config/build.yaml`.
3. **Validate overrides** via the manifest rules in §3.2–§3.3 (delegates to `check_overrides.py`). Block on any stale entry with no recorded decision in `stale_override_decisions.yaml`; apply recorded decisions automatically.
4. **Strip** every superseded identifier from the parsed vendor set (override merge).
5. **Apply the filter policy** via `apply_filters.py` (§4.2), producing the included set and the exclusion record.
6. **Run filter cross-checks** (§4.3): coverage-gap, referential integrity, empty/floor guards.
7. **Detect residual collisions** — any identifier appearing in more than one source after stripping/filtering is an error (e.g. a custom rule accidentally reusing a vendor name without an override declaration).
8. **Order** the emitted rules so dependencies resolve (see §6): vendor-remainder → overrides → custom, with topological adjustment if intra-set references exist.
9. **Emit** `dist/merged_rules.yara` (source) and/or compile to `dist/merged_rules.yarc` per configured formats.
10. **Compile** the merged-and-filtered corpus with `yara-python` as the authoritative validation gate (FR-7). Compilation here is non-negotiable even when only source output is requested — it is how "the ruleset is valid" is proven.
11. **Write** `dist/build_manifest.json`: rule counts by source, overridden/removed vendor identifiers, **filtered-out rules with responsible filter id and reason**, per-source-file SHA-256, tool/engine versions, and build version.

## 6. Rule ordering, modules, and external variables

**Ordering.** YARA conditions may reference other rules (including private rules), and a referenced rule must be defined earlier in the unit. The default emission order assumes custom/override rules may reference vendor rules but not vice versa. Where intra-corpus references exist, the build orders topologically; a cycle or unresolved reference surfaces as a compile error in §5 step 10, which is the backstop.

**Modules.** Any `import "pe"`, `import "dotnet"`, `import "math"`, etc. must be supported by both the CI build image and the deployment engine, or compilation/scan fails. The authoritative module list lives in `config/build.yaml` and the CI image is built to satisfy it.

**External variables.** Rules using externals (`filename`, `filepath`, `filetype`, custom externals) require those declared at compile time and supplied at scan time. They are declared once in `config/build.yaml` and consumed by the build, the test harness, and documented for the deployment target.

```yaml
# config/build.yaml (illustrative)
output_formats: [source, compiled]   # source | compiled | both
yara_modules: [pe, math]
external_variables:
  filename: ""
  filepath: ""
  filetype: ""
stale_override_decisions: overrides/stale_override_decisions.yaml
filter_conflict_policy: exclude_wins   # exclude_wins | last_match_wins | error
required_meta: [author, date, description, reference, severity]
```

## 7. Components

**`scripts/lint.py`** compiles each `.yara` file individually (fast, source-attributed syntax failure), confirms `plyara` can parse it, validates that every rule carries the metadata named in `required_meta` plus naming conventions, and validates the **filter policy schema** (well-formed scopes/actions/selectors; warns when a `rule:` scope or exact `name` selector references an identifier not present in the corpus). Runs in the lint stage.

**`scripts/check_overrides.py`** implements the manifest validation in §3.2–§3.3: detects stale and ambiguous override entries, reads `stale_override_decisions.yaml` to apply recorded reviewer decisions, and blocks on any unresolved stale entry. Runnable standalone (useful immediately after a vendor file update, before merging).

**`scripts/apply_filters.py`** implements the resolution algorithm and cross-checks in §4.2–§4.3. Runnable standalone against a parsed corpus to preview what a policy change would include/exclude before committing.

**`build/build_ruleset.py`** is the merge-and-filter engine described in §5.

**`tests/test_ruleset.py`** loads the built ruleset, reads `tests/test_cases.yaml`, scans each fixture, asserts expected match/no-match, scans the `clean/` corpus to enforce the false-positive gate, and emits JUnit XML.

## 8. Tooling choices and rationale

| Concern | Choice | Why |
|---|---|---|
| Parse / manipulate rules | `plyara` | Pure-Python YARA parser; lets the build extract identifiers, tags, and meta, remove rules, and reorder programmatically — the surgery the override and filter models require. |
| Compile / scan | `yara-python` (or `yara` CLI) | The authoritative engine; only it can confirm the merged-and-filtered corpus truly compiles and matches as expected. |
| Policy/config | YAML (`pyyaml`) | Declarative, reviewable override manifest, filter policy, and build config. |
| Test runner | `pytest` + JUnit output | Native GitLab MR integration for test results. |
| Artifacts / releases | GitLab artifacts + Package Registry | Downloadable build outputs and durable versioned releases. |

## 9. Test fixtures and sample safety

Live malware is never committed (NFR-3). Three patterns, in order of preference:
1. **Synthetic/inert fixtures** — small files containing only the byte patterns or strings a rule keys on, with no functional payload. Ideal for deterministic unit tests of in-house rules.
2. **Hash-referenced samples** — retrieved at test time from a separately secured store (e.g. authenticated MinIO/S3) using a hash recorded in the test spec; never stored in Git.
3. **EICAR-style** smoke tests for end-to-end sanity.

`tests/test_cases.yaml` is declarative and should include cases that prove both the override and the filter behaved:

```yaml
cases:
  - fixture: samples/emotet_synthetic.bin
    expect_match: [Custom_Override_Emotet]
    expect_no_match: [Vendor_Emotet_Generic]   # proves the override removed it
  - fixture: samples/experimental_trigger.bin
    expect_no_match: [Vendor_Experimental_X]    # proves filter F-001 excluded it
  - fixture: clean/normal_pe.bin
    expect_match: []
```

## 10. CI/CD pipeline

A pinned Docker image carrying YARA, `yara-python`, `plyara`, `pyyaml`, and `pytest`. Stages:

| Stage | Trigger | Does | Output |
|---|---|---|---|
| **lint** | every push/MR | per-file compile + metadata schema + filter-policy schema (`lint.py`) | fast pass/fail |
| **build** | every push/MR | `build_ruleset.py`: validate overrides, merge, apply filters + cross-checks, compile, manifest | `dist/` artifacts |
| **test** | every push/MR | `pytest` against built ruleset; false-positive gate | JUnit XML, match logs |
| **pcap-test** | `when: manual` | scan uploaded/keyed PCAP (or carved files) with built ruleset | match report artifact |
| **package** | on tags | publish versioned ruleset + manifest to Package Registry | release artifact |

Built `dist/` artifacts are passed forward from build to test (and package) as job artifacts so the test stage validates exactly what was built and filtered.

## 11. PCAP testing design

GitLab has no native "drop a file into a running job" control, so the capture reaches the job one of two ways:
- **CI/CD file variable** — small captures passed (base64 for binary) as a manual-pipeline variable. Subject to variable size limits; fine for targeted test captures.
- **Object storage key** — larger captures uploaded to a bucket out of band; the job receives the object key as a variable and pulls it.

The job then either scans the raw PCAP with YARA directly, or — usually more useful for file-detection rules — carves files/streams first (Zeek, `tcpflow`, or Suricata file extraction) and scans the extracted artifacts. Matches are written to a downloadable report artifact. Default mechanism and carve-vs-raw choice are open (DECISIONS.md D-3).

## 12. Output and versioning strategy

Default emits both `merged_rules.yara` (source) and `merged_rules.yarc` (compiled). Compiled output loads faster but is bound to the exact YARA engine version and does not move reliably across versions (NFR-5); it is only safe to consume where the target version is pinned. Source output is version-independent and compiled at the destination. Releases are tagged (semantic version recommended) and the build manifest ties an artifact to its exact inputs via source hashes and records what was overridden and filtered.
