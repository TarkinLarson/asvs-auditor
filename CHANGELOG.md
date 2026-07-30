# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Since these are prompt-based agents (not compiled software), versioning reflects meaningful changes to agent behavior, accuracy, or coverage.

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

[3.0.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/TarkinLarson/asvs-auditor/releases/tag/v1.0.0
