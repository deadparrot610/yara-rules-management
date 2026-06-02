# Decisions & Assumptions Register — YARA Rule Pipeline

| | |
|---|---|
| **Status** | Draft v0.2 |
| **Last updated** | 2026-06-02 |

This document tracks decisions that shape the implementation. Open items have a **proposed default** so building can proceed; confirm or change them before or during the relevant phase. Resolved items move to Section 3 as a lightweight decision record.

**Changelog**
- v0.2 — Added D-8…D-11 for the filter policy.
- v0.1 — Initial draft (D-1…D-7).

---

## 1. Open decisions

### D-1 — What consumes the final ruleset? **(highest impact)**
The deployment/scan target (SIEM, EDR, ClamAV, a custom yara-python scanner, etc.) determines which YARA modules must be supported and which output format is usable. ClamAV, for example, supports only a subset of YARA features; an EDR may pin a specific engine version.
- **Why it matters:** drives `yara_modules` in `config/build.yaml`, the CI image contents, and the source-vs-compiled output choice.
- **Status:** **RESOLVED — see Section 3.**

### D-2 — Output format
Source `.yara`, compiled `.yarc`, or both.
- **Trade-off:** compiled loads faster but is engine-version-bound and non-portable; source is portable but compiled at the destination.
- **Status:** **RESOLVED — see Section 3.** (Corelight Fleet Manager manages its own compilation; ship source only.)

### D-3 — PCAP delivery + scanning approach
How a capture reaches the manual job, and whether to scan raw or carve files first.
- **Options:** CI/CD file variable (small captures) vs. object-storage key (large captures); raw-PCAP scan vs. carve-then-scan (Zeek/`tcpflow`/Suricata).
- **Proposed default:** CI file variable for v1 with raw + carved scan of small test captures; revisit object storage if captures exceed variable limits.
- **Status:** _open; lowest priority (manual job, build last)._

### D-4 — Stale-override policy
When an override names a vendor rule that no longer exists in the vendor file.
- **Options:** hard fail the pipeline vs. emit a blocking warning for review.
- **Proposed default:** **hard fail** — a stale override means a suppressed detection may have silently returned; surface it loudly.
- **Status:** _open; default recommended._

### D-5 — Vendor file granularity and update cadence
One `vendor_rules.yara` vs. multiple vendor files; how often updates arrive and who commits them.
- **Status:** **RESOLVED — see Section 3.**

### D-6 — Sample sourcing for tests
Synthetic fixtures only (in-repo) vs. also hash-referenced samples from a secured store.
- **Proposed default:** synthetic/inert fixtures in-repo for v1 CI; add a hash-referenced secured store later if broader validation is needed.
- **Status:** _open; default usable now (NFR-3 satisfied either way)._

### D-7 — Versioning scheme
How releases are numbered.
- **Status:** **RESOLVED — see Section 3.**

### D-8 — Filter conflict tie-break (same specificity)
When two filters at the same scope specificity match a rule with opposing actions (one include, one exclude).
- **Status:** **RESOLVED — see Section 3.**

### D-9 — Filter default mode
The baseline before any filter matches.
- **Status:** **RESOLVED — see Section 3.**

### D-10 — Filter-induced coverage-gap policy
When a filter excludes an override rule whose superseded vendor rules were already removed (neither vendor detection nor replacement remains).
- **Options:** hard fail vs. blocking warning.
- **Proposed default:** **hard fail** — mirrors the stale-override stance (D-4); a silent coverage gap is exactly what the pipeline exists to prevent.
- **Status:** _open; default recommended._

### D-11 — Single policy vs. multiple output profiles
Whether the build emits one filtered ruleset or several (e.g. an endpoint profile and a network profile from the same corpus).
- **Proposed default:** **single active filter policy → single output** for v1 (matches the original single-file requirement). Multiple profiles are a natural later extension: the same engine run per-profile policy to emit several artifacts. Designing the filter engine to take a policy as input keeps that door open.
- **Status:** _open; v1 stays single._

## 2. Standing assumptions (carried into the design)

- Vendor rules arrive as valid YARA text files.
- The pipeline produces artifacts only; deployment to the live platform is a separate, out-of-scope process.
- `plyara` handles parsing/manipulation; `yara-python`/`yara` is the compilation and scan authority.
- GitLab CI/CD with Docker executors and the Package Registry are available.
- No live malware enters the repository (NFR-3).
- Single output file ⇒ single namespace ⇒ override means removal (the design's load-bearing assumption; revisiting it implies a multi-namespace deployment model and a different build).
- Filters select rules only; they never rewrite rule contents. A filtered-out rule stays in source.
- Filtering runs after the override strip; a filter cannot resurrect a rule an override removed.

## 3. Resolved decisions (decision log)

| ID | Decision | Date | Rationale |
|---|---|---|---|
| D-1 | **Consumer: Corelight Fleet Manager** — modules: `pe`, `elf`, `math`; YARA engine version pinned to what Corelight embeds | 2026-06-02 | Corelight Fleet Manager is the deployment target; it scans files extracted from network traffic via Zeek. Supports a well-defined YARA module set; does not support all modules (e.g. `dotnet` support should be verified before use). |
| D-2 | **Output: source (`.yara`) only** | 2026-06-02 | Corelight Fleet Manager ingests source rules and handles its own compilation internally; `.yarc` is neither needed nor useful. CI compile step still runs as the validation gate but `.yarc` is not emitted as an artifact. |
| D-5 | **Multiple vendor files allowed; each update via MR** | 2026-06-02 | The `vendor/` directory may contain more than one `.yara` file (e.g. one per vendor feed). Every update — adding, replacing, or removing a vendor file — is committed through a merge request so the diff and stale-override check run before the change reaches the corpus. |
| D-7 | **Semantic version tags (e.g. `v1.4.0`)** | 2026-06-02 | Releases are tagged with semantic version strings; the build manifest records exact input hashes regardless of the version tag. |
| D-8 | **Filter tie-break: `exclude_wins`** | 2026-06-02 | When two same-specificity filters conflict, the exclude action wins. Fail-safe toward a smaller, more deliberate deployment. |
| D-9 | **Filter default mode: `include_all` (denylist)** | 2026-06-02 | Everything ships unless explicitly excluded. Vendor corpora are large; allowlisting from scratch risks shipping almost nothing. |
