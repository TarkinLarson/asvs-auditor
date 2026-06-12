# ASVS Auditor

[![ASVS Version](https://img.shields.io/badge/ASVS-5.0-blue)](https://github.com/OWASP/ASVS/tree/v5.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude_Code-agent-purple)](https://claude.com/claude-code)

AI-powered security auditor agent for [Claude Code](https://claude.com/claude-code) that tests your application against the [OWASP Application Security Verification Standard (ASVS) 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0).

## Disclaimer

> **This tool is AI-powered and provided as-is with no warranty.** It is intended as a development aid, not a certified security assessment. You should be aware that:
>
> - **AI can and will make mistakes.** Findings may be incorrect, incomplete, or misattributed. Always verify results against the [ASVS specification](https://github.com/OWASP/ASVS/tree/v5.0.0) and your own expertise.
> - **This is not a substitute for professional security testing.** Use it to complement — not replace — manual code reviews, penetration testing, and formal compliance audits.
> - **No liability is accepted** for any security incidents, data breaches, compliance failures, or other damages arising from reliance on this tool's output. See [LICENSE](LICENSE).
> - **You are responsible** for validating all findings and remediation guidance before applying changes to your codebase.
>
> If your application handles sensitive data, financial transactions, healthcare records, or other regulated information, engage qualified security professionals.

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
/agent-asvs-ci                                  # JSON output for CI (default target: L2)
/agent-asvs-ci target L1                        # Gate on baseline violations only
```

## CI Integration

The CI variant outputs strict JSON with a `scan_summary.pass` boolean. Run Claude Code headless and gate the pipeline on it:

```yaml
# .github/workflows/asvs-scan.yml
name: ASVS Scan
on: [pull_request]
jobs:
  asvs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ASVS auditor
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          npm install -g @anthropic-ai/claude-code
          claude -p "/agent-asvs-ci" --permission-mode acceptEdits > scan-raw.txt
          # Strip any markdown fencing the model may emit around the JSON
          sed -n '/^{/,/^}/p' scan-raw.txt > scan.json
          jq . scan.json > /dev/null   # validate JSON
      - name: Gate on findings
        run: |
          if [ "$(jq -r '.scan_summary.pass' scan.json)" != "true" ]; then
            echo "::error::ASVS scan failed — violations at or below the target level"
            jq -r '.findings[] | "\(.asvs_level) \(.asvs_requirement) \(.file):\(.line) — \(.title)"' scan.json
            exit 1
          fi
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: asvs-scan
          path: scan.json
```

Notes:

- The agent file must be present in the repo at `.claude/commands/agent-asvs-ci.md` for the slash command to resolve.
- Model output may occasionally include markdown fences or preamble despite instructions — keep the extraction step defensive (the `sed` filter above) and treat unparseable output as a failed scan.
- Restricted runners without outbound network access prevent the agent from verifying requirement text against the ASVS GitHub source; it is instructed to fall back to section-level citations in that case.

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

## Why No Severity Ratings?

The agents deliberately do **not** assign severity ratings (Critical/High/Medium/Low). Real-world risk depends on deployment context a static review cannot see — internet exposure, data sensitivity, compensating controls like WAFs or network segmentation. An AI-guessed severity would be the least reliable part of the output, so we don't emit one.

Instead, findings carry the violated requirement's **ASVS level**, which ASVS 5.0 defines as a priority ordering:

| ASVS Level | Meaning | Priority |
|------------|---------|----------|
| L1 | Minimum baseline | Fix first |
| L2 | Standard for most applications | Fix next |
| L3 | High-assurance hardening | Fix as hardening |

Each finding also includes a CWE ID and code evidence, giving you everything needed to rate risk in your own process (e.g., [OWASP Risk Rating](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) or CVSS). CI gating is by target level: the scan fails if any requirement at or below the targeted level is violated.

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

- **Static analysis only** — the agent reads source code; it doesn't execute, fuzz, or probe the running application
- **LLM-dependent** — findings depend on the model's reasoning ability; complex multi-step vulnerabilities or logic flaws may be missed
- **False positives and negatives** — AI may misidentify safe code as vulnerable or miss genuine issues; always verify findings manually
- **Prompt size vs. accuracy tradeoff** — the full ASVS 5.0 spec (345 requirements) is not embedded; the agent may need to fetch chapter sources for precise requirement text
- **Not a compliance certification** — a passing scan does not constitute ASVS compliance; formal assessment requires qualified auditors

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
