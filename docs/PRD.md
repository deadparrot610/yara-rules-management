# Product Requirements Document — YARA Rule Management & Build Pipeline

| | |
|---|---|
| **Status** | Draft v0.2 |
| **Last updated** | 2026-06-02 |
| **Repository** | GitLab fclabs-group/yara-rules |

**Changelog**
- v0.2 — Added filter policy (rule selection layer): FR-17…FR-24, related open questions, decisions D-8…D-11.
- v0.1 — Initial draft.

---

## 1. Overview

This project provides a version-controlled home and an automated build/test pipeline for the organization's YARA detection rules. It manages three distinct classes of rules — vendor-supplied, in-house custom, and in-house overrides of vendor rules — and compiles them into a single, validated, deployable ruleset on every change.

The system exists to replace ad-hoc rule handling (manually edited files, untracked vendor drops, no compilation gate before deployment) with a reviewable, reproducible, and testable workflow that fails fast when a rule is broken, a vendor update conflicts with an override, or a change introduces a false positive. A configurable filter policy further selects which rules from the merged corpus reach the deployable output — globally or scoped to a ruleset or individual rule — without deleting them from source.

## 2. Background and the central design constraint

YARA does not permit two rules with the same identifier within a single compilation unit; a duplicate identifier is a hard compile error. Because the deployable artifact is a single ruleset, an "override" of a vendor rule cannot mean shipping a custom rule beside the vendor one. It must mean **removing the targeted vendor rule(s) from the corpus and substituting the in-house replacement.**

This constraint is the primary driver of the requirements below. It means the build cannot treat the vendor file as an opaque blob — it must parse it, identify rules by name, remove the superseded ones deterministically, and detect when an override no longer corresponds to any rule in the current vendor file (a stale override, which silently re-enables a detection the team believed it had suppressed).

The filter policy (Section 5, FR-17 onward) operates as a selection layer on the merged corpus. It interacts with the override model in a subtle way that the system must guard against: excluding an override rule via a filter leaves the corpus with neither the superseded vendor rule (already removed by the merge) nor the replacement (removed by the filter) — a silent coverage gap.

## 3. Goals and non-goals

### Goals
- Provide a single source of truth, under version control, for all YARA rules the organization maintains or deploys.
- Cleanly separate vendor, custom, and override rules so each can be reviewed and reasoned about independently.
- Guarantee that the deployable ruleset always compiles and has passed automated tests before it can be released.
- Make overrides explicit, reviewable, and auditable, with deterministic removal of superseded vendor rules.
- Detect stale overrides and conflicts introduced by vendor updates before they reach deployment.
- Allow the deployable ruleset to be filtered by a declarative policy — globally or per ruleset/rule — without deleting rules from source, with deterministic, auditable selection.
- Produce versioned, downloadable build artifacts with a manifest describing their contents and what was overridden or filtered out.
- Support optional validation of rules against network capture (PCAP) data.

### Non-goals
- This project does not deploy rules to the detection platform; it produces a validated artifact that a separate deployment process consumes.
- It does not author or tune rules automatically; humans write rules, the pipeline validates them.
- It is not a malware sample repository; live malicious samples are explicitly out of scope (see NFR-3).
- Filters select rules; they do not rewrite or transform rule contents (no condition editing) in v1.
- It does not manage Sigma, Snort/Suricata, or other non-YARA detection formats in v1.

## 4. Users

**Detection engineers / rule authors** write custom rules and overrides, define filters, open merge requests, and rely on the pipeline to tell them quickly whether a rule compiles, passes tests, and conflicts with anything.

**Reviewers / approvers** read merge requests and use the override manifest, filter policy, and CI output to understand and approve changes, particularly the security-sensitive decisions to suppress a vendor detection or filter a rule out of deployment.

**Rule consumers / deployment operators** (or an automated deployment job) pull the released artifact and load it into the detection platform. They depend on the artifact being valid for their YARA engine version and module set.

## 5. Functional requirements

| ID | Requirement |
|---|---|
| **FR-1** | The repository SHALL store the vendor-provided `.yara` file(s) under version control, updated by committing the new vendor file so changes are diffable and auditable. |
| **FR-2** | The repository SHALL store in-house custom rules, organized by category, separate from vendor and override rules. |
| **FR-3** | The repository SHALL store override rules separate from custom and vendor rules. |
| **FR-4** | Each override SHALL be accompanied by a machine-readable declaration of which vendor rule identifier(s) it supersedes, plus a human-readable reason and change reference (e.g. ticket ID and author). |
| **FR-5** | The build SHALL parse the vendor corpus, remove every vendor rule named in the override declarations, and produce a merged corpus containing the vendor remainder, the overrides, and the custom rules. |
| **FR-6** | The build SHALL fail (or emit a blocking warning, per policy) if any override references a vendor rule identifier that does not exist in the current vendor file (stale override detection). |
| **FR-7** | The pipeline SHALL verify the entire corpus by compiling the merged-and-filtered ruleset with the YARA engine; a compilation failure SHALL fail the pipeline. |
| **FR-8** | The pipeline SHALL also lint each rule file individually so that a syntax error is attributed to its source file, and SHALL validate that each rule carries required metadata (e.g. author, date, description, reference, severity) per a defined schema. |
| **FR-9** | The build SHALL emit a single deployable output ruleset. Output format (source `.yara`, compiled `.yarc`, or both) is configurable; default is both. |
| **FR-10** | The build SHALL emit a build manifest recording rule counts by source, the list of vendor rules that were overridden/removed, source file hashes, and the build version. |
| **FR-11** | The pipeline SHALL run automated tests that scan a set of fixtures with the built ruleset and assert expected matches and expected non-matches per a declarative test specification. |
| **FR-12** | The test suite SHALL include a clean/benign corpus and SHALL fail the pipeline if any rule matches it (false-positive gate). |
| **FR-13** | The pipeline SHALL support an optional, on-demand job that accepts an uploaded PCAP and scans it (or files/streams carved from it) with the built ruleset, reporting matches as an artifact. |
| **FR-14** | The pipeline SHALL store build and test artifacts so they are downloadable from the GitLab UI/API; released versions SHALL be published as durable, versioned artifacts. |
| **FR-15** | Test results SHALL be published in a format GitLab renders natively in merge requests (JUnit XML). |
| **FR-16** | The configuration of YARA modules in use (e.g. `pe`, `dotnet`, `math`) and any required external variables SHALL be declared centrally so the build, the test harness, and the deployment target agree. |
| **FR-17** | The repository SHALL store a declarative, version-controlled **filter policy** that selects which rules from the merged corpus appear in the final output, without removing them from source. |
| **FR-18** | A filter SHALL be scopeable **globally**, to a **source ruleset** (vendor, custom, or overrides), or to an **individual rule identifier**. |
| **FR-19** | A filter SHALL support **include** and **exclude** actions, with selectors matching on rule **name** (exact/glob/regex), **tags**, and **metadata** fields. |
| **FR-20** | Filter resolution SHALL be deterministic: a more-specific scope SHALL take precedence over a less-specific one (rule > ruleset > global), and the same-specificity tie-break policy SHALL be defined and documented. |
| **FR-21** | The baseline selection mode SHALL be configurable between **include-all** (exclusions remove rules from a fully-included corpus) and **include-none** (only explicitly included rules are kept). |
| **FR-22** | The build SHALL detect and block (or warn, per policy) any filter that excludes an **override** rule whose superseded vendor rules were already removed, because this leaves a detection **coverage gap**. |
| **FR-23** | After filtering, the build SHALL enforce **referential integrity** (an excluded rule still referenced in the condition of an included rule is an error) and SHALL guard against an **empty or below-floor** output. |
| **FR-24** | The build manifest SHALL record each rule excluded by filtering, the filter responsible (by id), and its reason. |

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| **NFR-1 — Reproducibility** | A given commit SHALL produce a functionally identical ruleset on any run; the CI build image and tool versions SHALL be pinned. |
| **NFR-2 — Auditability** | Every change to rules, overrides, and filters SHALL be attributable through version control and merge-request history; the override manifest and filter policy SHALL preserve the rationale for each suppression or exclusion. |
| **NFR-3 — Safety** | The repository SHALL NOT contain live malware. Tests SHALL use inert/synthetic fixtures committed to the repo, or samples referenced by hash and retrieved from a separately secured store at test time. |
| **NFR-4 — Fast feedback** | Lint and compile feedback on a merge request SHOULD complete within a few minutes so authors get quick signal. |
| **NFR-5 — Portability** | The artifact strategy SHALL account for YARA engine version sensitivity: compiled `.yarc` is tied to the engine version and SHALL only be relied upon where the consumer's version is pinned; source output SHALL remain available for version-independent compilation at the destination. |
| **NFR-6 — Determinism of output** | Rule emission order SHALL be deterministic and SHALL satisfy YARA's requirement that a referenced rule appears before any rule that references it. |
| **NFR-7 — Least privilege** | Pipeline credentials (package registry, sample store, object storage) SHALL be scoped to only what each job needs. |

## 7. Acceptance criteria

The project meets its v1 bar when: a vendor file, at least one custom rule, and at least one override can be committed; the pipeline merges, applies the filter policy, compiles the result, and blocks on any compile error; a stale override fails the pipeline; a filter excluding an override that removed vendor rules is detected as a coverage gap; a filter excluding a rule referenced by a surviving rule is rejected; automated tests assert both matches and non-matches and the false-positive gate is enforced; a tagged release produces a downloadable, versioned artifact plus a manifest listing what was overridden and filtered; and a maintainer can run the PCAP job on demand and retrieve a match report.

## 8. Assumptions and dependencies

- The deployment/consumption target and its YARA engine version are determined externally; this pipeline produces artifacts but does not push to that target. _(Open — see DECISIONS.md.)_
- Vendor rules arrive as one or more `.yara` text files and are syntactically valid as received.
- `plyara` is suitable for parsing the vendor and in-house rule sets (rule-name/tag/meta extraction, removal, reordering); `yara-python`/`yara` is the authority for compilation and scanning.
- GitLab CI/CD with Docker executors and the GitLab Package Registry are available to the project.

## 9. Out of scope (v1)

Automated deployment to the detection platform; non-YARA detection formats; a hosted web UI for rule authoring; automatic rule generation or tuning; long-term storage of malware samples in the repo; filter actions that rewrite rule contents (selection only); multiple simultaneous output profiles (single active filter policy in v1 — see DECISIONS.md D-11).

## 10. Open questions

These are tracked with proposed defaults in `DECISIONS.md`. The most consequential is the **rule consumer**, because it determines required module support and output format.

1. What system consumes the final ruleset (SIEM, EDR, ClamAV, custom scanner), and is its YARA engine version pinned? _(D-1)_
2. Output format: source, compiled, or both? _(D-2; default both)_
3. PCAP delivery mechanism (CI file variable vs object storage) and whether to scan raw captures or carve files first. _(D-3)_
4. Override-on-stale policy: hard fail vs. warn. _(D-4)_
5. Filter conflict tie-break at equal specificity: exclude-wins, last-match-wins, or hard-error? _(D-8; default exclude-wins)_
6. Filter default mode: include-all (denylist) vs include-none (allowlist)? _(D-9; default include-all)_
7. Filter-induced coverage-gap policy: fail vs warn? _(D-10; default fail)_
8. One filter policy now, or multiple output profiles later? _(D-11; default single policy)_
