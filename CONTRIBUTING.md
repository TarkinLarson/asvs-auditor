# Contributing

Thanks for your interest in improving the ASVS Auditor agents. This is a prompt engineering project — contributions typically involve improving scanning methodology, fixing requirement references, or expanding language/framework coverage.

## How to contribute

1. **Fork** the repository
2. **Create a branch** from `main` (e.g., `fix/v6-requirement-ids`)
3. **Make your changes** and test them by running the agent against a real codebase
4. **Submit a PR** with a clear description of what changed and why

## What makes a good contribution

### Accuracy fixes (most valuable)
- Correcting ASVS requirement IDs or descriptions
- Fixing section references that don't match ASVS 5.0
- Updating for ASVS patch releases (e.g., 5.0.1)

### Coverage improvements
- Adding language-specific scanning patterns (e.g., Rust, Kotlin, Swift)
- Adding framework-specific guidance (e.g., Django, Spring Boot, Rails)
- Expanding coverage for under-represented ASVS chapters

### Methodology improvements
- Better scanning heuristics that reduce false positives
- Improved report structure or remediation guidance
- New CI output fields that improve pipeline integration

## Standards

### Requirement references
- **Never edit `skills/*/reference/` or the generated block in `SKILL.md` by hand.** Both are produced by `tools/generate-asvs-reference.py` from the pinned ASVS tag, and CI fails on drift. To change them, change the generator and regenerate:
  ```bash
  python3 tools/generate-asvs-reference.py           # regenerate
  python3 tools/generate-asvs-reference.py --check   # what CI runs
  ```
- Every ASVS reference you write elsewhere in a prompt must use the exact `VX.Y.Z` format and match the bundled `reference/V<n>.md`, which is the authority — check there before citing
- If you believe the reference is wrong, the generator or the pinned tag is wrong; fix that, don't patch the output

### Testing
- Run the agent against at least one real codebase before submitting, and say in your PR what you ran it against with the relevant output pasted in — a prompt change with no evidence of a run is unreviewable
- For the CI variant, validate that the output is parseable JSON
- Check that findings include file paths, line numbers, and correct requirement IDs

### Commit messages
Keep them descriptive. Reference the ASVS sections affected:
```
Fix V6.2 password requirement IDs for ASVS 5.0

V6.2.1 is min 8 chars (not 12), V6.2.9 is 64+ chars (not V6.1.2).
Cross-referenced against ASVS 5.0 V6 chapter source.
```

## What we won't merge

- Hand-written additions to the generated requirement reference (change the generator instead)
- Requirement text pasted into `SKILL.md` itself — it belongs in `reference/`, where it loads on demand
- Vulnerability patterns without ASVS requirement mapping
- Framework-specific scanning that only works for one language
- Anything that would cause the agent to fabricate findings

## Questions?

Open an issue. We're happy to discuss approach before you invest time in a PR.
