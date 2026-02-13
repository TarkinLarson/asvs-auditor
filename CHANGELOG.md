# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Since these are prompt-based agents (not compiled software), versioning reflects meaningful changes to agent behavior, accuracy, or coverage.

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
