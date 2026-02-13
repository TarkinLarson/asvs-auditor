# ASVS Auditor

[![ASVS Version](https://img.shields.io/badge/ASVS-5.0-blue)](https://github.com/OWASP/ASVS/tree/v5.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude_Code-agent-purple)](https://claude.com/claude-code)

AI-powered security auditor agent for [Claude Code](https://claude.com/claude-code) that tests your application against the [OWASP Application Security Verification Standard (ASVS) 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0).

## What It Does

- Scans your codebase for security vulnerabilities
- Maps every finding to a specific ASVS 5.0 requirement (e.g., V1.2.5)
- Requires code evidence — file paths, line numbers, vulnerable snippets
- Supports both interactive markdown reports and CI/CD JSON output
- Language-agnostic — adapts scanning patterns to your stack

## Quick Start

```bash
# Copy to your project
mkdir -p .claude/commands
curl -sL https://raw.githubusercontent.com/TarkinLarson/asvs-auditor/main/agent-asvs.md \
  -o .claude/commands/agent-asvs.md
```

Then in Claude Code:

```
/agent-asvs
```

## Variants

| File | Purpose | Output |
|------|---------|--------|
| [`agent-asvs.md`](agent-asvs.md) | Interactive auditor | Markdown report with findings, compliance matrix, and remediation |
| [`agent-asvs-ci.md`](agent-asvs-ci.md) | CI/CD pipeline | Strict JSON for automation, exit code gating, and dashboards |

## Installation

### Per-project (recommended)

```bash
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

```
/agent-asvs                                    # Full audit
/agent-asvs focus on authentication             # Scoped to auth
/agent-asvs audit src/controllers/ only         # Scoped to directory
/agent-asvs L1 requirements only                # Minimum baseline only
/agent-asvs-ci                                  # JSON output for CI
```

## How It Works

1. **Reconnaissance** — maps the codebase, identifies languages and frameworks
2. **Category-by-category review** — checks each relevant ASVS chapter against your code
3. **Common vulnerability patterns** — targeted searches for injection, XSS, secrets, auth gaps, etc.
4. **Configuration review** — security headers, TLS, dependencies, debug settings
5. **Report generation** — findings with evidence, compliance matrix, prioritized remediation

### ASVS Requirement Accuracy

The agents include an inline section-level reference of all 17 ASVS 5.0 chapters with requirement IDs, levels, and direct links to the [ASVS 5.0 source on GitHub](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en). When the agent is uncertain about the exact wording of a requirement, it is instructed to fetch the chapter source rather than relying on training data.

This approach balances prompt size (embedding all 345 requirements would consume too much context) against accuracy (the agent has enough detail to cite correctly in most cases and knows where to verify).

## ASVS 5.0 Coverage

These agents target **ASVS 5.0** (released May 2025). The chapter structure reflects the [5.0 reorganization](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x05-For-Users-Of-4.0.md) from the previous 4.0.3 standard.

| Chapter | Topic | Key L1 Areas |
|---------|-------|--------------|
| V1 | Encoding and Sanitization | SQL/OS/LDAP injection, output encoding, deserialization |
| V2 | Validation and Business Logic | Input validation, anti-automation |
| V3 | Web Frontend Security | XSS, cookies, security headers, CSRF |
| V4 | API and Web Service | REST, GraphQL, WebSocket security |
| V5 | File Handling | Upload validation, SSRF, path traversal |
| V6 | Authentication | Passwords, MFA, credential storage |
| V7 | Session Management | Token security, termination, timeouts |
| V8 | Authorization | Access control, IDOR prevention |
| V9 | Self-contained Tokens | JWT validation, claims, lifecycle |
| V10 | OAuth and OIDC | PKCE, token validation, auth servers |
| V11 | Cryptography | Approved ciphers, password hashing, CSPRNG |
| V12 | Secure Communication | TLS configuration, certificates |
| V13 | Configuration | Secret management, debug mode, info leakage |
| V14 | Data Protection | PII, client-side storage, encryption at rest |
| V15 | Secure Coding and Architecture | Memory safety, supply chain |
| V16 | Security Logging and Error Handling | Audit logs, log protection |
| V17 | WebRTC | Peer connections, media streams |

## Severity Mapping

| Severity | ASVS Level | Description |
|----------|------------|-------------|
| Critical | L1 violation | Directly exploitable, data breach risk |
| High | L1 violation | Significant security impact |
| Medium | L2 violation | Defense-in-depth gap |
| Low | L3 violation | Hardening recommendation |

## Language Support

The agents adapt their scanning patterns to the detected stack. Explicit guidance is included for:

- .NET / C#
- Node.js / TypeScript
- Python
- Java
- Go
- PHP
- Ruby

Other languages are supported via general pattern matching — contributions for additional language-specific guidance are welcome.

## Limitations

- **Static analysis only** — the agent reads source code, it doesn't execute or probe the running application
- **LLM-dependent** — findings depend on the model's ability to understand code; complex vulnerabilities may be missed
- **Not a replacement for professional pentesting** — use this as a complement to manual security reviews, not a substitute
- **Prompt size vs. accuracy tradeoff** — the full ASVS 5.0 spec (345 requirements) is not embedded; the agent may need to fetch chapter sources for precise requirement text

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The most valuable contributions are:

- Correcting ASVS requirement references
- Adding language/framework-specific scanning patterns
- Improving methodology to reduce false positives

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT — see [LICENSE](LICENSE).

## References

- [OWASP ASVS 5.0 Specification](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)
- [ASVS 4.0 to 5.0 Migration Guide](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x05-For-Users-Of-4.0.md)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Claude Code](https://claude.com/claude-code)
