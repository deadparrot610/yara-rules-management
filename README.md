# YARA Rule Management & Build Pipeline

A version-controlled home and CI/CD pipeline for the organization's YARA detection rules. It manages vendor-supplied, in-house custom, and override rules; applies a declarative filter policy; and compiles everything into a single validated, deployable ruleset on every change.

> The build, lint, filter, override, test, and packaging pipeline is implemented end to end; the commands and paths below work today. The PCAP-testing job (Phase 8) is deferred pending scoping ([IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)). This README is the contributor entry point.

---

## What this repository does

Detection engineers commit rules into one of three trees, declare overrides in a manifest, and declare a filter policy. On every change the pipeline:

1. **Lints** each rule file (syntax, required metadata) and validates the filter policy.
2. **Builds** a single ruleset — merging the three sources, removing overridden vendor rules, applying the filter policy, and **compiling the result as the validation gate**.
3. **Tests** the built ruleset against inert fixtures, asserting expected matches and non-matches, with a false-positive gate.
4. Optionally **scans an uploaded PCAP** (manual job).
5. **Packages** a versioned, downloadable artifact on release tags.

The pipeline produces artifacts; deploying them to the detection platform is a separate, out-of-scope process.

## Core concepts

**Three rule classes.** *Vendor* rules arrive as one or more `.yara` files from a third party and are committed as received. *Custom* rules are written in-house. *Overrides* are in-house rules that replace specific vendor rules.

**Override means removal.** YARA rejects two rules with the same identifier in one compilation unit, and the deployable output is a single unit. So overriding a vendor rule does not mean shipping yours alongside it — it means the build **removes** the named vendor rule(s) and substitutes your replacement. Which vendor rules each override supersedes is declared explicitly in `overrides/override_manifest.yaml`, both to make removal deterministic and to keep an audit trail. The build fails if an override points at a vendor rule that no longer exists (a *stale override*).

**Filters are a selection layer.** The filter policy (`filters/filter_policy.yaml`) decides which rules from the merged corpus reach the output — globally, per source ruleset, or per individual rule. It never deletes source rules; a filtered-out rule stays in the repo and can be re-included by editing policy. The build guards against the subtle failure modes (filtering out an override leaves a coverage gap; excluding a rule that a surviving rule references breaks compilation; an over-narrow allowlist shipping almost nothing).

> **No live malware.** This repository never stores live malicious samples. Tests use small inert/synthetic fixtures, or samples referenced by hash and fetched at test time from a separately secured store.

## Repository layout

```
.
├── docs/                        # design documents (PRD, ARCHITECTURE, DECISIONS, IMPLEMENTATION_PLAN)
├── config/build.yaml            # output formats, YARA modules, external vars, policy flags
├── rules/
│   ├── vendor/*.yara            # vendor rules (one or more files), committed as received
│   ├── custom/                  # in-house rules, grouped by category
│   └── overrides/
│       └── overrides.yara       # replacement rules
├── overrides/                   # override metadata (kept out of rules/)
│   ├── override_manifest.yaml   # which vendor rules each override supersedes + why
│   └── stale_override_decisions.yaml  # reviewer keep/discard decisions for stale overrides
├── filters/filter_policy.yaml   # include/exclude selection layer
├── scripts/
│   ├── build_ruleset.py         # parse → strip → merge → filter → order → compile → manifest
│   ├── lint.py                  # per-file syntax + metadata + filter-policy validation
│   ├── check_overrides.py       # stale-override / conflict detection
│   └── apply_filters.py         # filter resolution + cross-checks (+ preview mode)
├── tests/                       # pytest harness, declarative cases, inert fixtures
└── dist/                        # build output (gitignored; produced by the build)
```

## Getting started

Requires Python 3 and a local YARA install.

```bash
pip install -r requirements.txt    # plyara, yara-python, pytest, pyyaml

python scripts/build_ruleset.py    # build dist/merged_rules.yara and the manifest
pytest tests/                      # run the test suite against the built ruleset
```

Build outputs land in `dist/`: `merged_rules.yara` (source) and `build_manifest.json` (rule counts by source, what was overridden, what was filtered out and by which filter, and input hashes).

## Common tasks

**Add a custom rule.** Drop a `.yara` file under the appropriate `rules/custom/` subdirectory. Include the required metadata (author, date, description, reference, severity) or lint will reject it.

**Override a vendor rule.** Add your replacement to `rules/overrides/overrides.yara`, then declare what it supersedes in `overrides/override_manifest.yaml`:

```yaml
overrides:
  - override_rule: Custom_Override_Emotet
    supersedes: [Vendor_Emotet_Generic, Vendor_Emotet_v2]
    reason: "Vendor rule fires on internal packer; condition tightened."
    ticket: SEC-1234
    author: a.analyst
    date: 2026-05-30
```

**Update the vendor file.** Add, replace, or remove files under `rules/vendor/` and open a merge request so the diff and the stale-override check run before merge. A vendor update that drops a rule you were overriding will surface as a stale override.

**Filter a rule out of the output.** Add an entry to `filters/filter_policy.yaml`. Scope it `global`, to a ruleset (`vendor`/`custom`/`overrides`), or to a single `rule:<Identifier>`:

```yaml
filters:
  - id: F-003
    scope: rule:Custom_Noisy_Rule
    action: exclude
    reason: "FP storm pending tuning"
    ticket: SEC-2002
```

Preview what a policy change would include or exclude before committing:

```bash
python scripts/apply_filters.py --preview
```

## CI/CD pipeline

Runs on a pinned Docker image carrying YARA and the Python dependencies.

| Stage | Trigger | Purpose |
|---|---|---|
| `lint` | every push / MR | per-file compile, metadata schema, filter-policy schema |
| `build` | every push / MR | merge, apply filters, compile, write manifest → `dist/` artifacts |
| `test` | every push / MR | scan fixtures, assert matches/non-matches, false-positive gate (JUnit) |
| `pcap-test` | manual | scan an uploaded/keyed PCAP (or carved files) with the built ruleset |
| `package` | on tags | publish the versioned ruleset + manifest to the Package Registry |

A broken rule, a stale override, a coverage-gap-inducing filter, or a false-positive match all fail the pipeline.

### Cutting a release

Releases are cut by pushing a git tag. Use a semantic version:

```bash
git tag v1.4.0
git push origin v1.4.0
```

The tag runs the full pipeline (lint → build → test) and then, only on success, the `package` and `release` stages:

- **`package`** uploads the built `merged_rules.yara` and `build_manifest.json` to the project's generic **Package Registry** under `yara-ruleset/<tag>/`. Download a specific version from *Deploy → Package Registry*, or via the API:

  ```bash
  curl --header "PRIVATE-TOKEN: <token>" \
    "https://<gitlab-host>/api/v4/projects/<id>/packages/generic/yara-ruleset/v1.4.0/merged_rules.yara"
  ```

- **`release`** creates a **GitLab Release** for the tag (visible under *Deploy → Releases*) whose assets link both package files.

The manifest ties the artifact to its exact inputs: `build_version` records the tag, and `source_hashes` records the SHA-256 of every source file that went into the build — so a downloaded ruleset can be verified against the rules it was built from.

## Design documents

| Document | Purpose |
|---|---|
| [PRD.md](docs/PRD.md) | Requirements (functional FR-1…FR-24, non-functional NFR-1…7), scope, acceptance criteria. |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical design: override model, filter policy model, build sequence, CI design, tooling. |
| [DECISIONS.md](docs/DECISIONS.md) | Decisions (D-1…D-11) with the decision log; open items are D-3 and D-6. |
| [IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | Phased build order with a definition of done per phase. |

## Notes for maintainers

- `config/build.yaml` and `filters/filter_policy.yaml` are the single sources for modules, external variables, output formats, and selection policy — code reads them rather than hardcoding.
- The compile step is the authoritative validation gate; nothing is emitted that hasn't compiled.
- All major decisions are resolved — see [docs/DECISIONS.md](docs/DECISIONS.md) §3 for the full log. Two items remain open: PCAP delivery mechanism (D-3) and sample sourcing for tests (D-6), both with working defaults.
