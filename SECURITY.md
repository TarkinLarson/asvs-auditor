# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's private vulnerability
reporting:

1. Go to the [Security tab](https://github.com/TarkinLarson/asvs-auditor/security)
2. Click **Report a vulnerability**
3. Describe the issue and, where relevant, how to reproduce it

This routes the report to the maintainers privately via a
[GitHub Security Advisory](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
Please do **not** open a public issue for a security report.

We aim to acknowledge a report within 7 days and to agree a disclosure timeline
with you once the issue is confirmed.

## What counts as a vulnerability here

This project ships prompt-based security-audit agents, not a running service, so
"vulnerability" is broader than a code defect. In scope:

- **False assurance** — a prompt or methodology change that causes the auditor to
  report code as compliant when it contains a genuine ASVS violation, or to
  suppress a valid finding.
- **Prompt injection** — a way to make the agent follow instructions embedded in
  the code under audit rather than its own methodology (for example, hidden text
  that suppresses findings or alters the report).
- **Fabricated findings** presented with false evidence (file paths, line
  numbers, or requirement IDs that do not exist), where the cause is the shipped
  prompt rather than the model alone.
- Defects in the tooling under `tools/` or `.github/workflows/`.

Incorrect ASVS requirement references, false positives, and ordinary agent
misbehaviour are **not** security issues — please report those as a regular
[bug](https://github.com/TarkinLarson/asvs-auditor/issues/new?template=bug_report.md).

## Supported versions

This is an actively maintained, single-track project: fixes land on `main` and
ship in the next tagged release. Only the latest release is supported.
