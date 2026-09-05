<!--
  Thanks for contributing. See CONTRIBUTING.md for the full standards.
  Keep the title descriptive and reference the ASVS sections affected.
-->

## What changed and why

<!-- One or two sentences. Reference the ASVS sections affected, e.g. V6.2. -->

## ASVS references touched

<!-- List the VX.Y.Z IDs this PR adds or corrects, or "none". -->

## Evidence of a run

<!--
  Required for prompt/methodology changes. Say what codebase you ran the agent
  against and paste the relevant output. A prompt change with no evidence of a
  run is unreviewable and will not be merged.
-->

- Ran against:
- Output:

```
paste relevant output here
```

## Checklist

- [ ] I did **not** hand-edit `skills/*/reference/` or the generated block in
      `SKILL.md` (changed `tools/generate-asvs-reference.py` and regenerated instead)
- [ ] `python3 tools/generate-asvs-reference.py --check` passes (no reference drift)
- [ ] Every ASVS reference uses the exact `VX.Y.Z` format and matches the bundled `reference/V<n>.md`
- [ ] For CI-variant changes: output validated as parseable JSON
- [ ] Findings include file paths, line numbers, and correct requirement IDs
