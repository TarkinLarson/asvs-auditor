# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Since these are prompt-based agents (not compiled software), versioning reflects meaningful changes to agent behavior, accuracy, or coverage.

## [Unreleased]

Coverage and counting at scale ([#45](https://github.com/TarkinLarson/asvs-auditor/issues/45)). This is a minor release: three optional fields were added to the JSON contract, and a 3.2.x report still validates against the new schema.

### Added

- **Sampling Large Surfaces.** On a ~5,500-file codebase with ~2,250 endpoints, the rule that "the sweep is not sampled" could not be met. The auditor sampled anyway, with no method, and recorded the results as plain passes. Every requirement still gets a status. What may now be sampled is the evidence behind one requirement, when it is decided site by site (per endpoint, sink or query). The scanner enumerates every site, verifies every high-risk one (unauthenticated, state-changing, privileged, or acting on a caller-identified resource) and samples the rest across modules. A violation in a sample is a full failure. A clean sample is a pass marked as sampled: the interactive report adds a Coverage column (`full` / `sampled n of N`) and an "Of which sampled" summary line, and the CI variant adds `compliance_summary.sampled_requirements`.
- **Root causes.** Mapping one finding per violated requirement (3.2.2) keeps the compliance matrix right, but it made the level totals measure requirements touched, not defects. In the same audit, one deployment setting produced 7 findings. Every finding now names the change that fixes it: `RC-n` with a `file:line` in the interactive report, and `root_cause` (`path:line`) in the CI variant. Totals report findings, requirements violated and root causes separately, and interactive remediation is grouped by root cause. The CI variant adds `scan_summary.root_causes`.

### Changed

- **The 50-finding cap keeps attack paths whole.** "L1 first, then by confidence" pushed a fully traced L2 finding at the centre of an attack path below low-confidence L1 documentation findings. Findings that are links in an attack path now take the first places. In the CI variant, this also guarantees that every ID a chain recommendation links is emitted. The cap decides which findings get a full write-up, not their priority.
- **Reachability outside the repository no longer lowers confidence.** A fully traced flaw was capped at medium because whether an attacker could reach it depended on DNS. Confidence now comes from the code, and the deployment dependency is stated alongside it. This is distinct from a control that may be enforced outside the code, which remains unverifiable.
- `tools/smoke.sh` stage 2 also fails a report where a sampled requirement is not a passed one, a finding lacks `root_cause`, or `root_causes` disagrees with the findings.

## [3.2.2] - 2026-11-09

Coverage and repeatability patch. No JSON field was added, removed, or changed in meaning; two schema field descriptions were clarified to match what the prompt already required.

### Fixed

- **Scans checked a handful of requirements, not the standard** ([#37](https://github.com/TarkinLarson/asvs-auditor/issues/37)). 3.2.0 told the scanner to evaluate every requirement at or below the target level, in one sentence inside the pattern-scanning step, while the coverage rules defined "checked" as "searched for its pattern class". The narrower rule won. Two CI scans of the same tree recorded 2 and 8 checked requirements out of ~250 at L2, and the turn limit was ruled out as the cause. Both variants now have a mandatory **Requirement Sweep** step. It reads every applicable reference chapter and gives each requirement at or below the target level exactly one status: passed, failed, unverifiable, inconclusive (searched, found neither the control nor a violation), or not applicable. "Checked" and "failed" now have one definition each, and the CI variant states the invariants between the compliance arrays. Measured on the same tree with the interactive variant: every L1+L2 requirement was decided in all three runs, with 0 left unchecked.
- **The same defect was mapped differently on every run** ([#41](https://github.com/TarkinLarson/asvs-auditor/issues/41)). Two 3.2.1 CI scans shared no finding: one defect was cited as V13.3.1 in one run and V13.3.3 in the other, at different lines, and `pass` flipped. A new **Mapping Findings to Requirements** section decides this by rule:
  - cite the requirement whose text the evidence violates;
  - emit one finding per violated requirement rather than choosing between them;
  - anchor on the construct that introduces the weakness, not on a caller;
  - one root cause is one finding, with other use sites listed inside it.

  Across three interactive runs, 8 failed or unverifiable requirements were found by all three and 5 more by two, mostly at identical locations. The remaining difference is recall: each run surfaced two or three findings the others missed. Results are still probabilistic.
- **A violation could be reported only as a recommendation** ([#38](https://github.com/TarkinLarson/asvs-auditor/issues/38)). A scan recommended signing release artefacts with `findings_addressed: []`, so the gap counted against no requirement. Every recommendation must now link at least one finding, and anything that violates a requirement is reported as a finding first. The schema is unchanged; tightening it is a contract change.
- **Platform defaults were reported as violations.** A .NET client that leaves TLS versions to the operating system, as Microsoft recommends, failed V12.1.1 at L1. Relying on a vendor-recommended default is no longer a definite violation. It is recorded as passed when the default is known to satisfy the requirement, and as unverifiable when the outcome depends on platform configuration outside the repository.
- Clarified, after test runs reported the instructions as ambiguous:
  - documentation requirements are judged pass or fail when the policy is in the repository, and are unverifiable only when nothing is found;
  - a partially documented control is a failure that names what is missing;
  - a requirement that forbids a construct passes on an exhaustive, named search;
  - applications with no HTTP server enumerate their IPC, pipe, socket and CLI entry points instead of routes;
  - applications that authenticate no one mark V6, V7 and 16.3.1 not applicable;
  - the interactive variant allows not-applicable on single requirements, and its summary reports passed/checked plus a not-checked count instead of a percentage;
  - a leftover rule demanding a traced input path for every `high` finding, which contradicted the configuration rubric, now applies to taint-flow requirements only.

### Changed

- **Scans use considerably more tokens.** Reading and deciding every applicable requirement is the point of this release. An interactive L2 audit of a ~120-file C# codebase used ~330k tokens and about ten minutes.
- `tools/smoke.sh`:
  - Stage 2 now fails a shallow or self-contradictory report. It checks coverage against the bundled reference (`--min-coverage`, default 90%, not-applicable sections excluded), that `failed_requirements` matches the findings, that passed and failed are disjoint subsets of checked, and that every recommendation links an existing finding ([#40](https://github.com/TarkinLarson/asvs-auditor/issues/40)).
  - New `--max-turns` option, default 100 (was a fixed 40). The default `--budget` is now 10.
  - The line-ending check reads what git stores, not the working tree, so a stale CRLF checkout under `core.autocrlf=true` no longer fails it ([#39](https://github.com/TarkinLarson/asvs-auditor/issues/39)).
  - Without a plugin manifest, the skill is now invoked by the directory-derived plugin namespace. The obvious alternative, a bare `/agent-asvs-ci`, silently tests whatever copy is installed in `~/.claude/skills` instead of the working tree. The load check (stage 1) now runs without a manifest rather than skipping.

### Known limitations

- The CI schema accepts only section-level IDs in `not_applicable`, so the CI variant cannot mark a single requirement not applicable. On non-web targets this leaves such requirements out of the report and lowers the measured coverage. Tracked for 3.3.0 in [#42](https://github.com/TarkinLarson/asvs-auditor/issues/42).

## [3.2.1] - 2026-11-09

Correctness patch for the methodology added in 3.2.0. No JSON field was added, removed, or changed in meaning.

### Fixed

- **Two absence checks cited the wrong requirement.** Session termination on credential change was cited as V7.4.2, which covers termination when an account is disabled or deleted. The credential-change control is **V7.4.3 (L2)**, which requires *offering* termination of other sessions. Both are now listed separately with their actual wording. The lockfile check was cited as V15.2.1 (update and remediation timeframes); it now cites V15.1.2 and V15.2.4, consistent with the supply chain guidance elsewhere in both prompts.
- **The CI variant told the scanner to add a route map to `compliance_summary`**, which the published schema forbids (`additionalProperties: false`). Under `--json-schema` that instruction could only be broken or ignored. Endpoint coverage is now recorded through absence findings and the existing requirement arrays.
- **Attack-path chains could create violations that did not exist.** 3.2.0 reported a chain as a new finding mapped to the requirement violated by its *impact*, which could count against a requirement no individual finding violated, flip `pass`, and double-count findings already reported. Chains are now a relationship between findings: in the CI variant a `recommendations` entry whose `findings_addressed` lists the constituents, and in the interactive report a new **Attack Paths** section. Neither changes any counter or gate.
- Step 3 of the interactive variant said "the previous steps search for vulnerability patterns" when pattern scanning is the following step, and endpoint authentication cited the whole of V6 alongside V8.2.1; it now cites V8.2.1 alone.
- The `actions/checkout` pins carried a `# v4.2.2` comment on a SHA that is v7.0.1.

### Removed

- **`reference/index.md`**, added in 3.2.0. No prompt referenced it and the index inlined in `SKILL.md` already lists every section, so it was a duplicate the agent never read.

### Corrected release notes

The 3.2.0 entry below claimed the index extraction kept `SKILL.md` within a ~5,000-token compaction budget. It did not: both prompts grew in 3.2.0, to roughly 9,000 tokens each. It also described the absence checks as derived from ASVS rather than hand-curated; the six listed checks are a hand-picked illustration, and only the instruction to evaluate every requirement at or below the target level comes from the standard. Both statements are corrected below.

## [3.2.0] - 2026-11-09

Accuracy and methodology release. The bundled requirement reference added in 3.1.0 was never actually reachable during a scan, so every finding was cited at section level — the documented offline fallback — rather than at requirement level. Three methodology gaps identified during adversarial testing are also addressed: per-endpoint control verification, absence-oriented scanning, and composite attack path analysis. No JSON field was added, removed, or changed in meaning, but **the values of `asvs_requirement` and therefore of every finding `id` change on the first run after upgrading**; see the upgrade note below.

### Fixed — the bundled reference was unreachable, so citations silently degraded

- **Requirement text was looked up at a path relative to the working directory.** Both prompts pointed at `reference/V<n>.md`, and during an audit the working directory is the project being audited, not the skill, so the requirement text was never there. Paths are now written against `${CLAUDE_SKILL_DIR}`, which Claude Code substitutes for project skills and plugin skills alike, with the relative path documented as a fallback for contexts that do not substitute it.
- **Even with a correct path, the read was denied.** `reference/` sits outside the audited project, so it is not covered by the working-directory reads a session permits by default. A pipeline running a restrictive permission mode got a denied `Read`, no error surfaced, and the scan carried on citing sections. Both skills now pre-approve the reads they need through `allowed-tools`.
- Measured on a fixture containing a SQL injection, a hardcoded key and debug mode enabled, scanned with `--permission-mode dontAsk`: exact requirement IDs went from 0 of 6 findings to 8 of 8, and all 8 levels matched the bundled reference. This is the failure the generated reference existed to prevent, and it was present in every 3.1.0 scan.
- **Findings were anchored to files that do not exist.** The documentation-requirement instruction listed `README`, `SECURITY.md` and `docs/` as anchors, so a scan of a two-file fixture duly reported a finding in a `SECURITY.md` that was not in the tree. A fabricated location cannot be checked by the reader and discredits the findings that are real. Both variants now require that a cited path be one actually seen in the tree, falling back to the repository root, and Evidence Standards states the rule for every finding type.

### Added

- **`schema/asvs-report.schema.json`** — the CI output contract as JSON Schema (draft-07). Previously the only definition of the format was prose inside the prompt. Hand it to Claude Code's `--json-schema` and the shape is enforced rather than requested, with the report returned in the response envelope's `structured_output` field; or use it on its own to validate a report with `check-jsonschema`, `ajv`, or any standard validator. Versioned with the skill: added fields are a minor release, removed fields or changed meanings a major one. Draft-07 rather than 2020-12 because the CLI's validator cannot resolve the 2020-12 meta-schema and rejects the file outright.
  - Measured with and without the schema on the same fixture at identical settings: 8 findings either way, 8 of 8 exact requirement IDs, 8 of 8 matching levels, 8 of 8 paths present, average remediation text slightly longer with the schema, cost within 5%. No degradation from constraining the output. The unconstrained reply carried markdown fences — the hazard the README's `sed` filter existed for — and put requirement-level IDs in `not_applicable` where Rule 17 reserves section-level ones, failing validation in six places. One run per arm, so read it as no sign of harm rather than proof of equivalence.
  - The requirement-ID pattern deliberately admits section-level IDs such as `V1.2`, because the documented fallback when the bundled text is unreachable is to cite the section rather than invent a requirement number. Constraining it further would force exactly the fabrication the fallback avoids.
- **`tools/smoke.sh`** — a pre-release check that runs in cost order: static checks for free, then a minimal skill-load check, then a real scan of a target directory. The scan runs against a temporary copy and fails if the copy changed, so a prompt edit that makes the auditor write to the code it audits is caught before review. It also fails a scan that read no files, which is what a refusal looks like, and validates the emitted report against the committed schema when the `jsonschema` package is importable.
- **`tools/check-skills.py`** — frontmatter and packaging validation. Claude Code silently ignores unrecognised frontmatter fields and loads a skill with no fields at all when the YAML fails to parse, so a mistyped `allowed-tools` restricts nothing and reports nothing. Also checks each skill ships all 17 reference chapters, since a `SKILL.md`-only install degrades to section-level citations.
- **`--source` on `tools/generate-asvs-reference.py`** — regenerate from a local `OWASP/ASVS` checkout instead of the GitHub contents API, which is rate limited and unavailable to a runner without GitHub credentials. It refuses a checkout that is not at the pinned tag, so provenance is unchanged, and output is byte-identical either way.

### Added — scanning methodology improvements

Three methodology gaps identified during adversarial testing of the scanner ([#34](https://github.com/TarkinLarson/asvs-auditor/pull/34)):

- **Per-endpoint control verification** (new Step 3 interactive / Step 2 CI). Previous methodology searched for vulnerability patterns — dangerous code that is present. This step flips the perspective: enumerate the application's attack surface by building a route map, then verify each endpoint carries authentication, authorization, CSRF protection, and rate limiting. A grep for `[Authorize]` finds endpoints that *have* auth; this step finds endpoints that *don't*.
- **Absence-oriented scanning** added to the vulnerability patterns step. Many ASVS requirements are violated not by the presence of bad code but by the absence of a required control — password policy enforcement (V6.2), session invalidation on logout (V7.4.1), security event logging (V16.3), lockfile presence (V15.2.1). The methodology now instructs the agent to evaluate every requirement at or below the target level for a required control, with a short hand-picked list as illustration.
- **Composite attack path analysis** (new Step 6 interactive / Step 5 CI). After individual findings are collected, a review pass identifies chains where combined impact exceeds any single finding: data extraction → privilege escalation, injection → deserialization, missing controls compounding, information leakage → targeted exploitation, and supply chain → code execution.
- **Interactive section index compacted** to the one-line-per-chapter form the CI variant already used, and a duplicate copy written to `reference/index.md` (removed in 3.2.1). Net, both prompts still grew in this release, to roughly 9,000 tokens each.

### Changed

- **The CI variant can no longer write files.** `Write`, `Edit` and `NotebookEdit` are removed through `disallowed-tools`: an auditor has no business modifying the code it is auditing, and the variant's contract is JSON on stdout. Adding `allowed-tools` takes nothing away — it only pre-approves — so the interactive variant keeps its full tool set.
- **The README's CI example no longer runs the scan with `--permission-mode acceptEdits`**, which granted an unattended auditor permission to modify the repository it was auditing. It now uses `--permission-mode dontAsk --permission-prompts none`, verified against a fixture to leave the target tree byte-for-byte unchanged. `--permission-prompts none` needs Claude Code 2.1.259 or later.
- The README's CI example extracts the report from `.structured_output` instead of scraping between the first `{` and the last `}` with `sed`, and records what the schema cannot do: it checks shape, not truth, so the `files_scanned` and `checked_requirements` gate is still required.
- `CONTRIBUTING.md` points at `tools/smoke.sh` for the run evidence it already asked contributors to paste into a PR.

### Upgrade note — finding identity changes once

Gate semantics, field names and JSON shape are all unchanged, so no pipeline needs editing. But because citations move from section level to requirement level, `asvs_requirement` goes from e.g. `V1.2` to `V1.2.4`, and finding IDs derived from it change with it (`ASVS-V1.2-app.py-11` becomes `ASVS-V1.2.4-app.py-11`). A dashboard that tracks findings by ID will show every finding as new on the first run after upgrading, once. Per-level violation counts and both gate booleans are computed the same way and should not move except where a more precise citation corrects a level that was previously inferred from the section.

One known limitation: the optional subagent install documented in the README copies `SKILL.md` into `.claude/agents/`, which is not a skill, so `${CLAUDE_SKILL_DIR}` may reach the model unsubstituted. The prompt tells it to fall back to reading `reference/` relative to the prompt's own directory, and that install form already fetched chapters over the network rather than shipping them.

## [3.1.0] - 2026-07-31

Scanner accuracy and CI robustness release. All CI JSON changes are additive — existing consumers keep working, and `pass` gating semantics are unchanged.

### Added — generated ASVS reference

- **The requirement reference is now generated from the pinned ASVS source, and the full standard ships with each skill** ([#4](https://github.com/TarkinLarson/asvs-auditor/issues/4), [#17](https://github.com/TarkinLarson/asvs-auditor/issues/17), [#20](https://github.com/TarkinLarson/asvs-auditor/issues/20)).
  - `tools/generate-asvs-reference.py` derives everything from `OWASP/ASVS@v5.0.0`: `skills/*/reference/V<n>.md` holds the full text, ID, and level of all **345 requirements across 80 sections**, and the section index inside each `SKILL.md` is spliced in between generated markers.
  - [`.github/workflows/asvs-reference-drift.yml`](.github/workflows/asvs-reference-drift.yml) regenerates and diffs on every relevant change and weekly, so the committed reference cannot silently drift from the spec. `--check` is the CI entry point.
  - The generator asserts the expected 17/80/345 totals and raises on any unparsed table row, mis-sequenced requirement ID, or unexpected level rather than guessing.
  - **This removes the prompt-size versus accuracy tradeoff the README used to document.** Requirement text lives in supporting files that cost no context until the agent reads the chapter it needs, so `SKILL.md` carries an accurate section index instead of a lossy hand-written summary.
  - Fixes every error catalogued in [#20](https://github.com/TarkinLarson/asvs-auditor/issues/20) by construction: the fabricated `V9.3` and `V12.3 "Certificate Pinning"` sections are gone, `V10` and `V14` are no longer shifted by one, `V4.2` (HTTP Message Structure Validation), `V15.4` (Safe Concurrency) and `V17` (TURN Server / Media / Signaling) are correctly titled, `V12.2`'s two requirements are correctly L1 rather than L2, and the 14 previously missing sections — including V6.5–V6.8, 18 requirements — are present.
  - Requirement text is quoted from OWASP ASVS under **CC BY-SA 4.0** with attribution in `reference/README.md`; the rest of the repository remains MIT.
  - **Install note:** a skill is now a directory. `cp -r skills/agent-asvs .claude/skills/` ships the reference; a `SKILL.md`-only install still works but falls back to fetching chapters over the network.

### Changed — CI gating semantics (read this before upgrading a pipeline)

- **`pass` now covers only violations the scanner could verify from source** ([#21](https://github.com/TarkinLarson/asvs-auditor/issues/21)). Findings marked `not_verifiable_in_code: true` no longer set `pass` to false. New sibling `pass_including_unverifiable` preserves the strict, pre-3.1.0 behaviour, and new `scan_summary.unverifiable_findings` counts the difference. Both booleans are always emitted, and unverifiable findings still appear in the per-level violation totals.
- **This changes gate outcomes.** Security headers (3.4.1, 3.4.2), TLS (12.2.1, 12.2.2) and documentation requirements (15.1.1, 2.1.1, 8.1.1) are L1 and are routinely satisfied outside the codebase — at a proxy, CDN, or in a document. Under 3.0.0 the scanner reported them as confirmed L1 violations, so **any application terminating TLS or headers at its edge gated as `pass: false` no matter how secure it was**, which made the boolean useless and the gate something teams would disable. A repository failing on those alone now passes.
  - **If you want the old behaviour, gate on `pass_including_unverifiable`** — a one-word change in your workflow.
  - The direction of this change loosens a gate, which is worth a deliberate look before you upgrade: confirm the requirements now excluded are genuinely enforced at your edge. The new `unverifiable_findings` count and the README's warning step are there to keep them visible rather than silently dropped.
  - Strictly this alters the meaning of an existing field and could be argued as breaking. It ships in a minor release because the previous value was not usable as a gate, the strict reading remains available under a new name, and `not_verifiable_in_code` is itself new in 3.1.0.

### Fixed
- **CI variant lacked the anti-fabrication calibration the interactive variant gained in 2.0.0** ([#5](https://github.com/TarkinLarson/asvs-auditor/issues/5)). "Be thorough — first scans always find issues" had no counterweight in the variant that gates pipelines, combined with a mandatory JSON output contract. Thoroughness is now defined as coverage of the standard, zero findings with full coverage is explicitly a valid `pass: true` result, and the false-positive cost is stated.
- **"If you can't find the exact line, don't report it" contradicted mandated absence findings** ([#6](https://github.com/TarkinLarson/asvs-auditor/issues/6)). The same prompt required flagging missing lockfiles, rate limiting, CSRF protection, and security headers — none of which have a vulnerable line — so the model had to either break the rule or silently drop a whole finding class. Absence findings now anchor to the file and line where the control belongs and carry `finding_type: "absence"`; the rule is rescoped accordingly. Both variants also require stating what was searched for and not found, so an absence is verifiable rather than trusted.
- **`checked_requirements` and `not_applicable` had no definitions, inviting fabricated compliance claims** ([#7](https://github.com/TarkinLarson/asvs-auditor/issues/7)). "Checked" now means the pattern class was actually searched for; "passed" means the control was located and verified, not merely that no violation was found; N/A requires the governing technology to be absent, with a reason recorded in the new `not_applicable_reasons` map. Unchecked requirements are omitted rather than padded.
- **Interactive Core Beliefs contradicted its own calibration section** ([#15](https://github.com/TarkinLarson/asvs-auditor/issues/15)). "'No vulnerabilities found' means you didn't look hard enough" sat several sections above the 2.0.0 text walking that back. Reworded to the calibrated stance.
- **V15 chapter reference was substantially wrong in both variants** ([#17](https://github.com/TarkinLarson/asvs-auditor/issues/17)). The reference mapped V15.2 to Memory Safety, V15.3 to Concurrency, and V15.4 to Supply Chain Integrity. Verified against the [V15 chapter source](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md), the actual sections are V15.1 Secure Coding and Architecture Documentation, V15.2 Security Architecture and Dependencies, V15.3 Defensive Coding, and V15.4 **Safe Concurrency**. The supply chain guidance block — lockfiles, floating version ranges, dependabot — was therefore attached to a section about thread safety; it belongs to 15.1.2 (SBOM/inventory), 15.2.1 (component currency), and 15.2.4 (dependency confusion). Dependency vulnerabilities were also mapped to V13.2 (Backend Communication) rather than 15.2.1. Offline runs, which the README documents as falling back to section-level citations from this reference, would have emitted wrong requirement IDs for every supply chain finding.
- **V16.5 Error Handling was missing from the reference entirely** ([#17](https://github.com/TarkinLarson/asvs-auditor/issues/17)). The chapter is "Security Logging **and Error Handling**", but the reference stopped at V16.4, so requirements 16.5.1–16.5.4 were invisible to the agent. Also added the previously unlisted 16.3.4 and per-section requirement counts.

### Added
- **Scope exclusions** in both variants ([#8](https://github.com/TarkinLarson/asvs-auditor/issues/8)) — vendored, generated, and build-output paths are skipped by default; dependency manifests and lockfiles stay in scope for the supply chain requirements (15.1.2, 15.2.1), as do gitignored secret-bearing config files, seed and migration data, and the versions of libraries vendored by copy. Test code and fixtures are reported only where they represent production risk, so deliberately vulnerable fixtures no longer surface as findings.
- **Infrastructure awareness** ([#9](https://github.com/TarkinLarson/asvs-auditor/issues/9)) — security headers (V3.4), TLS (V12), and rate limiting (V2.4) are frequently enforced at a proxy, CDN, or gateway and invisible to source review. When no infrastructure config is present in the repo these are reported as unverifiable from source at low confidence, with `not_verifiable_in_code: true` in the CI schema, instead of as confirmed violations. In-repo infrastructure config (nginx, ingress, Terraform, Dockerfile) is now scanned and reported definitively.
- **Reachability requirement and placeholder-secret heuristics** ([#10](https://github.com/TarkinLarson/asvs-auditor/issues/10)) — `high` confidence now requires a traced path from an untrusted entry point to the sink; sinks fed only by constants or pre-validated data are dropped, and untraceable paths are downgraded rather than asserted. Environment-variable indirection, obvious dummy values, and `.example`/`.template` files are no longer reported as hardcoded secrets.
- **Deduplication rule** ([#12](https://github.com/TarkinLarson/asvs-auditor/issues/12)) — one finding per root cause per file, with instance count and additional line numbers in the description. Previously undefined, so repeated flaws inflated or deflated the level counters unpredictably between runs.
- **Output limits** ([#13](https://github.com/TarkinLarson/asvs-auditor/issues/13)) — emitted findings are capped at 50 (L1 first, then by confidence) with the new `scan_summary.findings_truncated` flag. The per-level counters and `total_findings` always reflect everything found, so `pass` gating stays correct when the array is capped. Prevents truncated, unparseable JSON on large codebases, which the README already required consumers to treat as a failed scan.
- **Confidence in the interactive variant** ([#15](https://github.com/TarkinLarson/asvs-auditor/issues/15)) — previously CI-only, though the false-positive risk is identical. Interactive findings now carry the same `high`/`medium`/`low` rubric.
- **Explicit target level in the interactive variant** ([#15](https://github.com/TarkinLarson/asvs-auditor/issues/15)) — defaults to L2, matching the CI variant, which already documented at-or-below gating semantics. Requirements above the target are reported in a separate hardening section.
- CI absence-finding example in the output sample, plus `UNVERIFIABLE` and reasoned `N/A` rows in the interactive compliance matrix.
- README: a False Positive Controls section, and CI notes covering the new fields with a `jq` example for filtering infrastructure-enforced findings out of gating.

### Changed
- **Finding IDs are derived from content, not sequential** ([#14](https://github.com/TarkinLarson/asvs-auditor/issues/14)) — `ASVS-V1.2.5-ReportService.cs-87` rather than `ASVS-001`. Sequential IDs renumbered on every run, making run-over-run tracking impossible for the dashboards the CI variant exists to feed. The schema shape is unchanged; only ID values differ, and nothing could have depended on the old unstable values.
- **`files_scanned` is now defined** ([#11](https://github.com/TarkinLarson/asvs-auditor/issues/11)) as the count of distinct files actually read or matched, with an explicit instruction to emit `0` rather than guess a plausible number.
- **`column` is now optional** ([#11](https://github.com/TarkinLarson/asvs-auditor/issues/11)) and must be omitted when not known exactly. It is false precision an LLM cannot reliably produce from search output, so the value was usually invented.

## [3.0.0] - 2026-07-30

Breaking release: repackaged from slash commands to Agent Skills. Prompt content, agent behavior, and the CI JSON contract are unchanged — only the packaging and install paths changed.

### Changed
- **Repackaged as Agent Skills (`SKILL.md` directory format)**. Claude Code merged custom commands into skills; `SKILL.md` is the documented recommendation, follows the [Agent Skills](https://agentskills.io) open standard, and — unlike command files — also works in claude.ai account contexts (Cowork, cloud sessions), which don't read `.claude/commands/`. It also allows supporting files to ship alongside the prompt in future releases.
  - `agent-asvs.md` → `skills/agent-asvs/SKILL.md`, installed to `.claude/skills/agent-asvs/SKILL.md`
  - `agent-asvs-ci.md` → `skills/agent-asvs-ci/SKILL.md`, installed to `.claude/skills/agent-asvs-ci/SKILL.md`
  - Slash invocations are unchanged (`/agent-asvs`, `/agent-asvs-ci`); the skill name comes from the directory name. Existing CI workflows calling `claude -p "/agent-asvs-ci"` keep working once the file is installed at the new path.
- README updated throughout: Quick Start, installation (including claude.ai/Cowork usage), variants table, CI notes, and badge.

### Migration from 2.x
1. Delete the old command files: `.claude/commands/agent-asvs.md` and `.claude/commands/agent-asvs-ci.md` (also any copies in `~/.claude/commands/`).
2. Install to the new paths per the README, e.g. `.claude/skills/agent-asvs/SKILL.md`.

## [2.0.0] - 2026-06-12

Breaking release: the CI JSON output contract changed (severity field removed, per-level violation counters added).

### Changed
- **Clarified packaging: slash commands, not subagents** ([#2](https://github.com/TarkinLarson/asvs-auditor/issues/2)). Frontmatter switched to command-style (`description`, `argument-hint`; dropped non-functional `name`/`color`), badge and README updated, with a note on how to run as a subagent if context isolation is preferred.
- **Removed severity ratings entirely** ([#1](https://github.com/TarkinLarson/asvs-auditor/issues/1)). The previous Critical/High/Medium/Low model was derived mechanically from ASVS level, which measures verification depth, not risk — and AI-judged severity is unreliable without deployment context. Findings now carry only the violated requirement's ASVS level (a priority ordering per ASVS 5.0) plus CWE ID and evidence; risk rating is delegated to the consumer.
- CI schema: `severity` field removed from findings; `scan_summary` counters are now `l1_violations`/`l2_violations`/`l3_violations`; `pass` is false when any requirement at or below the targeted ASVS level (default L2) is violated.
- Interactive report: findings tagged by level (`[L1]`), executive summary counts per level, remediation priority ordered by level.
- Consolidated the two CI workflow examples into one; the 1.1.0 example gated on the now-removed `critical`/`high` counters. The `confidence` field introduced in 1.1.0 is retained — finding confidence (is it real?) is orthogonal to severity (how risky?).

### Fixed
- **V5 File Handling reference corrected in both agents** — previous reference listed six sections including nonexistent V5.5 and V5.6; actual ASVS 5.0 structure is V5.1 Documentation, V5.2 File Upload and Content, V5.3 File Storage, V5.4 File Download. File-context SSRF is requirement 5.3.2, not a "V5.6 SSRF" section.
- **V8 Authorization reference corrected in both agents** — actual sections are V8.1 Authorization Documentation, V8.2 General Authorization Design (IDOR/BOLA lives here, 8.2.2), V8.3 Operation Level Authorization, V8.4 Other Authorization Considerations.
- **1.5.1 corrected** — it is the XML parser hardening / XXE requirement; deserialization type allowlisting is 1.5.2.
- **V13.4 requirement count corrected** (7, not 5); added 13.4.4 (HTTP TRACE disabled).
- **CI variant section-level labels reconciled with the interactive agent** — V3.3/V3.4/V3.5, V6.2/V6.3, V9, V10, V11.4, and V14 no longer overstate L2/L3 requirements as L1, which inflated severities in CI output.
- **11.4.1/11.4.2 wording** — algorithm names (MD5, argon2/scrypt/bcrypt) marked as examples rather than implied spec text.

### Added
- CI integration example in README (headless invocation, JSON extraction, `pass` gating, artifact upload).
- CI rule to take the scan timestamp from the system clock instead of guessing.
- Offline fallback rule in both agents: cite at section level (VX.Y) when the ASVS source cannot be fetched.

## [1.1.0] - 2026-03-05

### Added
- Parallel tool call instructions in both agents — reconnaissance and pattern scanning now explicitly instruct Claude to issue Grep/Glob calls simultaneously rather than sequentially, significantly reducing scan time
- Sub-agent delegation guidance for large codebases (>200 files) — interactive agent can spawn parallel sub-agents per ASVS chapter group
- `confidence` field in CI JSON schema (`high|medium|low`) per finding, with guidance on assignment — enables downstream tooling to filter likely false positives before failing pipelines
- GitHub Actions workflow example in README for CI/CD integration
- Model recommendation section in README (Opus 4.6 for thorough audits, Sonnet 4.6 for speed, extended thinking guidance)

### Changed
- V15.4 supply chain guidance expanded: now includes concrete checks for floating version ranges, lockfile presence, dependabot/renovate config, and `--ignore-scripts` usage
- Step 4 configuration review now explicitly includes supply chain checks
- "Signs of Fantasy Security" section renamed to "Signs of Fabricated Findings" and softened: "no vulnerabilities found" is no longer an automatic fail — accuracy is the goal, not quota-filling
- curl install command in README pinned to `v1.0.0` tag (was `main`) for reproducibility

## [1.0.0] - 2026-02-13

### Added
- Interactive auditor agent (`agent-asvs.md`) with full markdown report output
- CI/CD auditor agent (`agent-asvs-ci.md`) with strict JSON output schema
- ASVS 5.0 section-level requirements reference with direct GitHub links to each chapter
- Language-agnostic scanning with per-stack guidance (.NET/C#, Node/TS, Python, Java, Go, PHP, Ruby)
- Concrete example output in CI variant for reliable JSON formatting
- Coverage for all 17 ASVS 5.0 chapters (V1–V17)

### Key design decisions
- Requirements reference embedded inline with GitHub links for verification, balancing prompt size against accuracy
- Agent instructed to fetch chapter source from GitHub when unsure of exact requirement wording
- False positive caveat added to "every app has vulnerabilities" personality trait

[3.2.1]: https://github.com/TarkinLarson/asvs-auditor/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/TarkinLarson/asvs-auditor/releases/tag/v1.0.0
