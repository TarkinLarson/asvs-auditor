# ASVS Auditor

AI-powered security auditor agent for [Claude Code](https://claude.com/claude-code) that tests your application against the [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/).

## What It Does

- Scans your codebase for security vulnerabilities
- Maps every finding to a specific ASVS requirement (e.g., V1.2.5)
- Requires code evidence — file paths, line numbers, vulnerable snippets
- Supports both interactive reports and CI/CD JSON output
- Language-agnostic — works with any codebase

## Variants

| File | Purpose |
|------|---------|
| `agent-asvs.md` | Interactive auditor — produces a full markdown report with findings, compliance matrix, and remediation guidance |
| `agent-asvs-ci.md` | CI/CD variant — outputs strict JSON for pipeline integration, exit code gating, and automated dashboards |

## Installation

### Per-project (recommended)

```bash
# From your project root
mkdir -p .claude/commands
cp agent-asvs.md .claude/commands/
cp agent-asvs-ci.md .claude/commands/   # optional
```

### Global (all projects)

```bash
mkdir -p ~/.claude/commands
cp agent-asvs.md ~/.claude/commands/
cp agent-asvs-ci.md ~/.claude/commands/   # optional
```

## Usage

In Claude Code:

```
/agent-asvs
```

Or for CI output:

```
/agent-asvs-ci
```

You can also scope the audit:

```
/agent-asvs focus on authentication and session management
/agent-asvs audit src/controllers/ only
/agent-asvs L1 requirements only
```

## ASVS Version

These agents target **ASVS 5.0** (released May 2025). The chapter structure reflects the 5.0 reorganization:

| Chapter | Topic |
|---------|-------|
| V1 | Encoding and Sanitization |
| V2 | Validation and Business Logic |
| V3 | Web Frontend Security |
| V4 | API and Web Service |
| V5 | File Handling |
| V6 | Authentication |
| V7 | Session Management |
| V8 | Authorization |
| V9 | Self-contained Tokens |
| V10 | OAuth and OIDC |
| V11 | Cryptography |
| V12 | Secure Communication |
| V13 | Configuration |
| V14 | Data Protection |
| V15 | Secure Coding and Architecture |
| V16 | Security Logging and Error Handling |
| V17 | WebRTC |

## How It Works

The agent follows a structured process:

1. **Reconnaissance** — maps the codebase structure, identifies languages and frameworks
2. **Category-by-category review** — checks each relevant ASVS chapter against your code
3. **Common vulnerability patterns** — targeted searches for injection, XSS, secrets, auth gaps, etc.
4. **Configuration review** — security headers, dependencies, debug settings
5. **Report generation** — findings with evidence, compliance matrix, prioritized remediation

## Severity Mapping

| Severity | ASVS Level | Description |
|----------|------------|-------------|
| Critical | L1 violation | Directly exploitable, data breach risk |
| High | L1 violation | Significant security impact |
| Medium | L2 violation | Defense-in-depth gap |
| Low | L3 violation | Hardening recommendation |

## Contributing

Issues and PRs welcome. If you improve the methodology or add coverage for new ASVS 5.0 chapters, please submit a PR.

## License

MIT — see [LICENSE](LICENSE).

## References

- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [ASVS 4.0 → 5.0 Migration](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/0x05-For-Users-Of-4.0.md)
- [Claude Code](https://claude.com/claude-code)
