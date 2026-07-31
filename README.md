# ASVS Auditor

[![ASVS Version](https://img.shields.io/badge/ASVS-5.0-blue)](https://github.com/OWASP/ASVS/tree/v5.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude_Code-agent_skill-purple)](https://claude.com/claude-code)

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

## Requirements

**To run an audit** — [Claude Code](https://claude.com/claude-code) and nothing else. The skill is prompt files plus bundled reference text: no runtime, no build step, nothing to install. Developed and tested against Claude Code 2.1.220.

**To install from this repository** — `git`, since the Quick Start clones to get the `reference/` directory. Any other way of copying the skill folder works equally well.

**To run the CI variant in a pipeline** — Node.js and npm (to install `@anthropic-ai/claude-code`), `jq` to parse the JSON output, and an `ANTHROPIC_API_KEY` secret. See [CI Integration](#ci-integration).

**To regenerate the ASVS reference** (contributors only) — Python 3, standard library only, no packages to install; plus network access to github.com to fetch the pinned ASVS tag. Tested on 3.13.

## Quick Start

```bash
# Copy the skill (prompt + bundled ASVS requirement reference) into your project
git clone --depth 1 --branch v3.0.0 https://github.com/TarkinLarson/asvs-auditor /tmp/asvs-auditor
mkdir -p .claude/skills
cp -r /tmp/asvs-auditor/skills/agent-asvs .claude/skills/
```

The skill is a **directory**, not a single file — `SKILL.md` plus `reference/` holding the full ASVS 5.0 requirement text. `SKILL.md` alone still works (it falls back to fetching chapters from GitHub), but shipping the folder is what makes offline and restricted-runner scans cite requirements accurately.

Then in Claude Code:

```
/agent-asvs
```


## Model Recommendation

| Use case | Recommended model |
|----------|-------------------|
| Thorough audit, large codebase | Claude Opus 5 (`claude-opus-5`) |
| Fast scan, smaller project | Claude Sonnet 5 (`claude-sonnet-5`) |

**Effort level**: raise the effort level in Claude Code settings (`/config`) for complex codebases where multi-step logic flaws or subtle authorization issues are a concern. It buys the auditor considerably more reasoning depth at the cost of speed and tokens, and matters more than it did on earlier models.

**A note on Claude Fable 5.** It is Anthropic's most capable widely released model, so it looks like the obvious choice here — but it is explicitly **not intended for cybersecurity work**, and its safety classifiers specifically target that content. A security audit is exactly the workload most likely to trip them, and a refusal arrives as a successful response with no findings rather than an error, so a scan can appear to pass while having done nothing. Use Opus 5 or Sonnet 5 instead. Opus 5 also carries elevated cybersecurity safeguards; a benign source-code audit is well within bounds, but if a CI scan ever produces empty or unparseable output, a refusal is worth ruling out before you debug the pipeline.

## Variants

| File | Purpose | Output |
|------|---------|--------|
| [`skills/agent-asvs/SKILL.md`](skills/agent-asvs/SKILL.md) | Interactive auditor | Markdown report with findings, compliance matrix, and remediation |
| [`skills/agent-asvs-ci/SKILL.md`](skills/agent-asvs-ci/SKILL.md) | CI/CD pipeline | Strict JSON for automation, exit code gating, and dashboards |

### Skills, not subagents

Both are packaged as Claude Code **skills** — `SKILL.md` prompt files following the [Agent Skills](https://agentskills.io) open standard, installed to `.claude/skills/<name>/` and invoked as `/agent-asvs` (or loaded automatically by Claude when relevant). The "agent" in the name refers to the auditor *persona* the prompt creates, not Claude Code's separate [subagent](https://docs.claude.com/en/docs/claude-code/sub-agents) feature (`.claude/agents/`).

If you prefer an isolated context window for long scans of large codebases, the files also work as subagents: copy a `SKILL.md` to `.claude/agents/` as e.g. `asvs-auditor.md`, and add `name:` (e.g., `asvs-auditor`) to the frontmatter. The skill form is the supported default — the CI workflow below depends on it.

## Installation

### Per-project (recommended)

```bash
mkdir -p .claude/skills
cp -r skills/agent-asvs .claude/skills/
cp -r skills/agent-asvs-ci .claude/skills/   # optional
```

### Global (all projects)

```bash
mkdir -p ~/.claude/skills
cp -r skills/agent-asvs ~/.claude/skills/
cp -r skills/agent-asvs-ci ~/.claude/skills/   # optional
```

### claude.ai / Cowork

Cowork and cloud sessions don't read local `.claude` directories. To use the auditor there, enable the skill folder on your claude.ai account — from the skills settings on claude.ai or the desktop app's **Customize** sidebar. Cloud sessions also pick up project skills committed to the repository's `.claude/skills/`.

## Usage

```
/agent-asvs                                    # Full audit
/agent-asvs focus on authentication             # Scoped to auth
/agent-asvs audit src/controllers/ only         # Scoped to directory
/agent-asvs L1 requirements only                # Minimum baseline only
/agent-asvs-ci                                  # JSON output for CI (default target: L2)
/agent-asvs-ci target L1                        # Gate on baseline violations only
```

### Windows: Git Bash mangles the slash command

Running the auditor headless from **Git Bash on Windows** silently fails to invoke the skill:

```bash
claude -p "/agent-asvs-ci"     # does NOT work under Git Bash
```

MSYS rewrites any argument that looks like a Unix absolute path before handing it to a native Windows executable, so `/agent-asvs-ci` arrives as `C:/Program Files/Git/agent-asvs-ci`. Claude treats it as a missing file path, answers that the path doesn't exist, and exits 0 — so a pipeline sees success and an empty report. Quoting the argument or passing it through a variable does **not** help; the rewrite happens either way.

Any of these work:

```bash
MSYS_NO_PATHCONV=1 claude -p "/agent-asvs-ci"   # disable the rewrite for this call
claude -p "//agent-asvs-ci"                      # a doubled leading slash is passed through as one
```

Or run it from PowerShell or `cmd`, which do no such rewriting. Linux and macOS are unaffected, including the GitHub Actions example below.

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

- The skill must be present in the repo at `.claude/skills/agent-asvs-ci/SKILL.md` for `/agent-asvs-ci` to resolve.
- Model output may occasionally include markdown fences or preamble despite instructions — keep the extraction step defensive (the `sed` filter above) and treat unparseable output as a failed scan.
- Controls commonly enforced at a proxy, CDN, or gateway (security headers, TLS, rate limiting) are reported with `not_verifiable_in_code: true` and low confidence when no infrastructure config is present in the repo. They still count toward the violation totals and `pass` — if your edge enforces them, filter those findings out in your gating step rather than expecting the scanner to guess:

  ```bash
  jq '[.findings[] | select(.not_verifiable_in_code != true)] | length' scan.json
  ```

- Findings violated by absence (missing rate limiting, missing lockfile) carry `finding_type: "absence"` and are anchored to the file and line where the control belongs, so every finding has a location.
- On large codebases the emitted findings array is capped at 50 with `findings_truncated: true`; the per-level counters and `total_findings` always reflect everything found, so `pass` gating stays correct even when the list is truncated.
- Finding IDs are derived from requirement, repo-relative path, and line (e.g. `ASVS-V1.2.5-src/Services/ReportService.cs-87`) rather than a sequence number, so a finding keeps its identity between runs while it stays in the same place. Note that editing lines above a finding shifts its line number and therefore its ID — key on requirement plus path if you need identity to survive refactoring.
- Restricted runners without outbound network access are fine as long as the `reference/` directory is committed alongside `SKILL.md` — requirement text is read from disk, so citations stay exact. Only a `SKILL.md`-only install degrades to section-level citations offline.
- Audits on large codebases can take several minutes. Consider running on a schedule or scoping to PRs that touch sensitive paths rather than every push.

## How It Works

1. **Reconnaissance** — maps the codebase, identifies languages and frameworks
2. **Category-by-category review** — checks each relevant ASVS chapter against your code
3. **Common vulnerability patterns** — targeted searches for injection, XSS, secrets, auth gaps, etc.
4. **Configuration review** — security headers, TLS, dependencies, debug settings
5. **Report generation** — findings with evidence, compliance matrix, prioritized remediation

### False Positive Controls

Static AI review is prone to reporting patterns that aren't real risk. The agents apply several constraints to reduce that:

- **Reachability** — a dangerous sink is only reported once untrusted input can be traced to it. Sinks fed by constants or already-validated data are dropped, and untraceable paths are downgraded to medium confidence rather than reported as certain.
- **Scope exclusions** — vendored, generated, and build-output directories are skipped. Test code and fixtures are only reported when they represent production risk, so a deliberately vulnerable fixture doesn't become a finding.
- **Placeholder detection** — environment-variable indirection and obvious dummy values are not reported as hardcoded secrets.
- **Infrastructure awareness** — controls that commonly live at a proxy, CDN, or gateway are marked as unverifiable from source rather than reported as confirmed violations.
- **Confidence levels** — every finding carries `high`/`medium`/`low`, so you can filter before acting.
- **Honest coverage** — a requirement is only reported as checked if it was actually searched for, and only as passed if the control was located and verified. Chapters whose technology is absent are marked not-applicable with a reason.

### ASVS Requirement Accuracy

Each skill ships the **full text of all 345 ASVS 5.0 requirements** in `reference/V<n>.md`, one file per chapter, with exact requirement IDs and levels. `SKILL.md` carries only a section index — titles, requirement counts, level ranges — and instructs the agent to read the relevant chapter file before citing anything. Because supporting files load on demand, the full standard costs no context until the agent needs a specific chapter.

**The reference is generated, not hand-written.** `tools/generate-asvs-reference.py` derives it from the pinned [`OWASP/ASVS@v5.0.0`](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en) source, and [a CI workflow](.github/workflows/asvs-reference-drift.yml) regenerates and diffs on every change plus weekly, so committed output cannot drift from the spec:

```bash
python3 tools/generate-asvs-reference.py          # regenerate
python3 tools/generate-asvs-reference.py --check   # fail if committed output has drifted
```

This replaced a hand-maintained summary that had drifted from the standard in four separate releases — fabricated sections that do not exist in 5.0 (`V9.3`, `V12.3 "Certificate Pinning"`, `V5.5`, `V5.6`), whole chapters shifted by one (`V10`, `V14`), mis-mapped topics (`V4.2`, `V15.4`, `V17`), understated levels that changed CI gating, and 14 missing sections including 18 V6 requirements. The generator asserts the expected 17/80/345 chapter, section, and requirement totals and fails loudly on any unparsed row rather than guessing.

Requirement text is quoted from OWASP ASVS under CC BY-SA 4.0; see [`skills/agent-asvs/reference/README.md`](skills/agent-asvs/reference/README.md) for attribution.

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
- **Requirement text is bundled, but interpretation is not** — all 345 requirements ship with the skill, so citations are accurate; whether a given control genuinely satisfies a requirement is still the model's judgement
- **Not a compliance certification** — a passing scan does not constitute ASVS compliance; formal assessment requires qualified auditors

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The most valuable contributions are:

- Correcting ASVS requirement references
- Adding language/framework-specific scanning patterns
- Improving methodology to reduce false positives

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT — see [LICENSE](LICENSE) — with one exception: the generated ASVS requirement text in `skills/*/reference/` quotes the [OWASP Application Security Verification Standard](https://github.com/OWASP/ASVS) and is licensed **CC BY-SA 4.0**, as documented in [`skills/agent-asvs/reference/README.md`](skills/agent-asvs/reference/README.md). The prompts, tooling, and documentation are MIT.

## References

- [OWASP ASVS 5.0 Specification](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)
- [ASVS 4.0 to 5.0 Migration Guide](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x05-For-Users-Of-4.0.md)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Claude Code](https://claude.com/claude-code)
