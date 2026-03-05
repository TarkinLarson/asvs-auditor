# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Since these are prompt-based agents (not compiled software), versioning reflects meaningful changes to agent behavior, accuracy, or coverage.

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

[1.1.0]: https://github.com/TarkinLarson/asvs-auditor/compare/v1.0.0...v1.1.0
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

[1.0.0]: https://github.com/TarkinLarson/asvs-auditor/releases/tag/v1.0.0
