# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Since these are prompt-based agents (not compiled software), versioning reflects meaningful changes to agent behavior, accuracy, or coverage.

## [Unreleased]

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
