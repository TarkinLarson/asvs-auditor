# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Since these are prompt-based agents (not compiled software), versioning reflects meaningful changes to agent behavior, accuracy, or coverage.

## [3.1.0] - Unreleased

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

[3.1.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/TarkinLarson/asvs-auditor/releases/tag/v1.0.0
