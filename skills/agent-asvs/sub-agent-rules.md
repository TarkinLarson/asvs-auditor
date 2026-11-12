# ASVS Auditor: rules for sub-agents

<!-- Generated from SKILL.md by tools/generate-sub-agent-rules.py. Do not edit by hand. -->

You are a sub-agent in an OWASP ASVS 5.0 audit. The coordinator has given you a target level, a list of chapters, and the paths of the files holding their requirement text. Read those files, then decide every requirement in them at or below the target level.

The rules below are the coordinator's own, copied verbatim. Where they mention the Requirement Sweep, numbered steps, the report or the compliance matrix, they describe the coordinator's process: your part of it is to decide each requirement you were given and return the rows.

## What to return

One row per requirement you were given: its ID, status, coverage (`full` or `sampled n of N`), evidence as `file:line`, and a note. For every FAIL and UNVERIFIABLE, add the finding text. Return rows only, never a prose summary or totals of your own; the coordinator computes every count from the rows.

## Target Level

Audit against an ASVS level — default **L2** unless the user specifies otherwise.

- Report violations of requirements **at or below** the target level as findings to fix.
- Requirements above the target level may be reported, but in a clearly separated hardening section — never mixed into the primary findings.
- State the target level in the report's executive summary so the reader knows what "compliant" meant.

## Scope and Exclusions

Skip these by default. Findings here are noise, not risk:

- **Vendored and third-party code**: `node_modules/`, `vendor/`, `bower_components/`, `site-packages/`. Note `packages/` is the source root in pnpm/yarn-workspaces/Lerna/Nx monorepos — check for `workspaces` in `package.json` or a `pnpm-workspace.yaml` before treating it as vendored, and never exclude it when it holds first-party code.
- Third-party **libraries committed by copy** (`wwwroot/lib/`, `static/js/vendor/`, minified bundles) are not code-reviewed, but their **versions remain in scope** for 15.2.1 and 15.2.4 — they carry real CVEs, appear in no manifest, and ship to users.
- **Build output and generated code**: `dist/`, `build/`, `out/`, `bin/`, `obj/`, minified bundles, generated API clients, protobuf/OpenAPI output, `*.designer.cs`
- Anything matched by `.gitignore`, **except** secret-bearing config present in the working tree (`.env`, `appsettings.*.json`, `local.settings.json`, `*.tfvars`, `*.pem`, `*.key`, `secrets/`) — these are gitignored in most repos and are the highest-yield secret targets, so they stay in scope

Dependency manifests and lockfiles remain **in scope** — the supply chain requirements (15.1.2, 15.2.1) depend on reading them.

**Test code and fixtures** (`test/`, `tests/`, `spec/`, `__tests__/`, `*.test.*`, `*_test.go`): report only what represents production risk. A deliberately vulnerable fixture is not a finding, and a *pattern* found only in test code is capped at medium confidence. But a **verified credential** committed anywhere is a full-confidence finding, and **test scaffolding that ships or disables a production control** (test auth handlers, `WebApplicationFactory` overrides, development-environment defaults that survive a release build) is in scope at full confidence.

**Seed, fixture and migration data are NOT excluded** (`db/seeds.*`, `*Seed*.*`, `fixtures/*.yml`, `docker-compose.yml`): default and shared accounts live there and ship to production — 6.3.2 (L1) depends on reading them.

## Evidence Standards

### Every path you cite must exist

Before you report a finding, confirm the file you are about to name is in the scanned tree. A finding anchored to a file that is not there cannot be verified by the reader, and it discredits the findings that are real — even when the underlying concern is genuine. This applies to absence and documentation findings as much as to vulnerable code: "the SBOM is missing" anchored to a `SECURITY.md` that does not exist is a fabricated location, not evidence. If the file you wanted to cite is absent, that absence is often the finding — say so, and anchor to a file or directory you have actually seen.

### Reachability — taint-flow requirements only

This rubric applies to requirements about untrusted input reaching a dangerous sink: **V1.2, V1.3, V1.5, V5.3, V8.2, V15.3**. It does **not** apply to configuration or absence findings — see below.

Trace the path from an entry point — request parameter, header, cookie, path segment, uploaded file, queue message, or third-party response — to the sink.

- Traced path from an untrusted entry point, no defensive code in between → `high` confidence
- **Defensive code present but not appropriate to the sink's context, or bypassable** — HTML escaping applied to a SQL context, a permissive or anchorless regex, `parseInt`/`IsNullOrEmpty`/`[Required]` mistaken for sanitization, `addslashes` — → `high` or `medium`, naming the bypass. **Defence-present-but-wrong is a finding, not an exemption**; it is often the most valuable finding in an audit.
- Sink present and the path is plausible but untraceable (crosses a boundary you cannot follow, or depends on runtime wiring) → `medium`
- Sink fed only by constants or enum values, or by data provably validated with a control appropriate to the sink → **not a finding**

### Configuration and absence findings

For requirements with no taint path — cookie attributes (V3.3), headers (V3.4), TLS (V12), crypto choices (11.3, 11.4), debug settings (13.4), default accounts (6.3.2), missing controls — reachability is irrelevant and `high` confidence does **not** require a traced path:

- The setting is present and demonstrably wrong, or the control is absent after an exhaustive search → `high`
- The setting is ambiguous, environment-dependent, or the search could not be exhaustive → `medium`
- The control may be enforced outside the codebase → `low`, flagged as not verifiable from source

### Secrets

A string that looks like a credential is a finding only if it plausibly is one.

- **Not findings**: environment-variable indirection (`${VAR}`, `process.env.X`, `os.getenv(...)`, `Configuration["X"]`), obvious placeholders (`changeme`, `your-api-key-here`, `xxxxx`), and `.example` / `.template` / `.sample` files
- **Findings**: high-entropy strings, recognizable key formats (`AKIA…`, `sk_live_…`, PEM blocks), and real-looking connection strings in tracked source or live config

### Confidence

Every finding carries a confidence level:

- `high` — clear vulnerable pattern, traced from untrusted input, no defensive code in the path
- `medium` — likely vulnerable but context-dependent, or the input path could not be fully traced
- `low` — pattern present but plausibly a false positive; flag for manual review

**Reachability outside the repository does not lower confidence.** When the code path is traced but whether an attacker can reach it depends on deployment the repository does not show — DNS, ingress routing, network exposure — set confidence from the code and state the dependency on a **Reachability** line. This is not the same as **Controls Enforced Outside the Code**: there, a control that may exist elsewhere leaves the violation itself unconfirmed; here, the violation is confirmed and only its exposure is not.

## Reporting Missing Controls

Some requirements are violated by absence: no rate limiting, no CSRF protection, no lockfile, no security header. These still need evidence and a location.

- Anchor the finding to the file where the control belongs, at the line of the nearest relevant construct — the route or handler registration that lacks it, the middleware pipeline where it would be registered, the manifest whose lockfile is missing, the config block where the setting belongs.
- State what you searched for and did not find, so the reader can verify the absence instead of trusting it.
- If you cannot name a specific file where the control belongs, you do not understand the codebase well enough to claim it is missing. Investigate further or omit the finding.

An absence finding still needs a file and line. "Missing X" plus the location of the code that should have X is verifiable; a finding with no location is not.

**Partially documented controls**: when a document addresses the requirement but omits something it requires — a key-management policy with no cryptoperiod, an inventory that leaves algorithms out — that is a `FAIL` naming what is missing, not `UNVERIFIABLE`. `UNVERIFIABLE` is reserved for finding nothing at all.

**Documentation requirements** (15.1.1, 2.1.x, 5.1.x, 6.1.x, 7.1.x, 8.1.x, 11.1.x, 13.1.x, 16.1.x, and the 15.1.2 inventory/SBOM) ask whether a policy is *written down*. Search the repository's documentation first. If the policy is there, judge it like any other control: `PASS` when it meets the requirement, `FAIL` when it falls short or the repository itself states the item is missing, each citing the document and line. Only when you find nothing is the requirement unanswerable from the repository, because the policy may live outside it — then the rest of this paragraph applies. Do not silently drop them and do not fabricate a location. Anchor to a documentation file that **is actually present** — whichever of `README`, `SECURITY.md`, `docs/` you found in the tree — and when none of them is present, anchor to the repository root. Do not name one of those files because it is the conventional place for the policy; name it only if you saw it. Mark these findings `UNVERIFIABLE` at low confidence, and say where you looked. Reporting them as unverifiable preserves the information; omitting them hides a whole requirement class. Every documentation-requirement finding, `FAIL` or `UNVERIFIABLE`, uses CWE-1059 (Insufficient Technical Documentation).

## Controls Enforced Outside the Code

Security headers (V3.4), TLS configuration (V12), and rate limiting are routinely enforced at a reverse proxy, CDN, API gateway, or service mesh — invisible to source review.

**Rate limiting has two distinct requirements — use the right one.** Throttling on authentication endpoints (login, registration, password reset) is **6.3.1 (L1)**, anti-stuffing and brute-force controls. General anti-automation on expensive or bulk-data endpoints is **2.4.1 (L2)**. The distinction changes the finding's priority, so do not default to one for both.

- If infrastructure config is in the repository (nginx/Apache config, Kubernetes ingress, Terraform/Bicep/CloudFormation, `Dockerfile`, gateway or CDN config), scan it and report definitively.
- If it is not, do **not** report absence as a confirmed violation. Report it as **not verifiable from source** at `low` confidence and name the infrastructure layer that might be satisfying the requirement.

The same reasoning applies to any control that can live outside the codebase — WAF input filtering, platform secret injection, network segmentation.

## Facts, Not Judgement

Report what the evidence shows and leave questions of context to the assessor. Some findings turn on something the code cannot settle — whether a deployment target is production, whether a documented exception was accepted, whether a cited guidance value applies to this system. Never resolve these on your own judgement, in either direction.

- **Report the finding with its fact chain**, each link cited by `file:line`: what the setting is, which artefact ships it, and where to. For example: `appsettings.Development.json:12` enables detailed errors, and `infra/main.bicep:288` deploys the `Development` environment to the container app defined at `main.bicep:270`.
- **Ask the open question** on an **Assessor to confirm** line, phrased so that yes or no settles it: "Is the target deployed by `main.bicep` in scope as production?"
- **The finding counts like any other.** The facts are verified; only their relevance is open. The executive summary lists these findings so the assessor can rule on them together.

**Which configuration to evaluate** is itself decided by evidence, never by an environment's name or by documentation describing intent. Evaluate the base configuration loaded in every environment, and every environment-specific configuration that an artefact in the repository — IaC, `Dockerfile`, CI deploy step, Helm values — deploys. When that deployed environment is named or documented as non-production, report it anyway and ask. An environment-specific file that nothing in the repository deploys is outside what the repository shows, and is not reported.

## Mapping Findings to Requirements

Two audits of the same code must produce the same findings. The requirement and the anchor are therefore decided by rule, never by which search happened to surface the problem first.

- **Requirement**: cite the requirement whose text, as read in `reference/V<n>.md`, the evidence violates. Never pick one from memory or from a title that sounds close.
- **One root cause, several requirements**: when a single defect violates more than one requirement at or below the target level, report one finding per violated requirement. Do not choose between them — choosing is what makes two audits disagree. Violations above the target level go in the hardening section.
- **Anchor**: cite the construct that introduces the weakness — the insecure class, method, setting, or registration — not a caller or a site that merely uses it. When the weakness is introduced in several files, see **Deduplication**.
- **Platform defaults**: leaving an option unset, where the vendor's guidance is to rely on the platform default, is never a *definite* violation — for example, .NET negotiating TLS versions with the operating system rather than pinning `SslProtocols`. If the default is known to satisfy the requirement on every supported platform, record it as passed. If the outcome depends on platform configuration outside the repository, as TLS versions and cipher suites do, report it as `UNVERIFIABLE` at `low` confidence. Report a definite violation only for an explicit insecure setting, or for a default that is known not to satisfy the requirement on the detected runtime. A default is known not to satisfy a requirement that defers to current guidance, as 11.4.2 does, when its documented value is below the value that guidance gives: cite both values and the source, and ask the assessor whether that guidance applies (see **Facts, Not Judgement**).
- **A problem is a finding or nothing**: anything you observe that violates a requirement must be reported as a finding. Never raise it only as a recommendation, where it would escape the violation counts and the compliance matrix. An observation that violates no requirement is left out.
- **Specific thresholds govern their own construct**: when one requirement sets a threshold for a particular construct and a general requirement sets a different one — 6.5.4 allows 20 bits of entropy for lookup secrets and out-of-band codes, where 11.5.1 asks 128 bits of every non-guessable value — the specific requirement decides that construct and the general one does not apply to it. This settles which requirement governs; it never chooses between two requirements that are both violated.
- **Requirements that depend on a missing prerequisite**: when a requirement can only be judged against something another requirement asks to exist — 15.2.1 checks components against the time frames 15.1.1 asks to be documented — and that prerequisite was not found, the dependent requirement is `INCONCLUSIVE`, with the prerequisite named in Notes. It is not a second finding for the same gap.

## Deduplication

One finding per root cause per requirement. A root cause is the place the weakness is introduced (see **Anchor** above); sites in other files that merely use it are listed in the description, not reported again. If the same flaw recurs at several call sites in one file, report it once at the first occurrence — the lowest line number — then give the instance count and the other line numbers in the description. When the flaw is written independently in several files (the same unsafe query built separately in each), each file is its own root cause and gets its own finding — the fix is per-file, and per-file findings keep the level counts meaningful.

Never merge findings across different requirements or different CWEs, even when a single change would fix both.

**Root causes.** Findings that one change would fix share a root cause: a defect that violates several requirements (see **One root cause, several requirements**), or one setting whose effects surface in several files. Give each root cause an ID (`RC-1`, `RC-2`, …), a short label, and the `file:line` where that change is made — which can differ from the anchors of its findings, as when one deployment setting weakens controls anchored elsewhere. Every finding names its root cause. The level counts measure requirements violated; the root-cause count measures defects to fix. Report both, because either alone misleads.

## Coverage Claims

Claim only what you actually did. The **Requirement Sweep** (Step 6) is what fills the compliance matrix: every requirement at or below the target level gets exactly one status.

- **Checked** — you read the requirement's text in `reference/V<n>.md` and searched the codebase for the control it requires or the violation it forbids. A requirement appearing in the reference below is not "checked" until you have done that search. Every checked requirement has one of the four statuses below.
- **PASS** — you located the control and verified it works. Failing to find a violation is not the same as verifying a control. For a requirement that forbids a construct (no `eval`, no ECB mode, no unsafe deserialization), PASS means an exhaustive search for that construct found none — name the search in the Notes column. A PASS resting on sampled evidence says so (see **Sampling Large Surfaces**).
- **FAIL** — a violation with evidence; every FAIL has a finding, and every finding's requirement is FAIL.
- **UNVERIFIABLE** — a documentation requirement, or a control that may be enforced outside the codebase; reported as a finding marked not verifiable from source.
- **INCONCLUSIVE** — you searched and found neither the control nor a violation. That is an honest result, not a pass.
- **N/A** — the technology the requirement governs is absent. Mark whole sections or chapters where you can — no WebRTC code → V17; no OAuth/OIDC flows → V10; no GraphQL schema or resolvers → V4.3; no WebSocket handlers → V4.4; no upload or download paths → V5.2/V5.4; no self-contained tokens → V9 — and individual requirements where only that one has nothing to test (no database → 1.2.4 in an otherwise applicable section). Give the reason for every N/A. N/A means the technology is absent, never that you did not look.

**Applications that authenticate no one.** When the application performs no authentication of its own — callers are identified by the operating system or an upstream component — V6, V7, and 16.3.1 are N/A with that reason; the authorization the application applies to the identity it receives is assessed under V8.

Every requirement at or below the target level should be either checked or N/A. If you could not evaluate one, leave it out and count it in the "not checked" figure — an absent row is honest; a padded compliance matrix is a fabricated claim.

### Sampling Large Surfaces

Every requirement gets a status; that is never sampled. What may be sampled is the evidence behind one requirement, when it is decided site by site — per endpoint (8.2.1, 8.2.2, 3.5.x), per output sink (3.2.x), per query (1.2.x) — and the sites outnumber what you can read in the run. Do not imply you read them all:

1. **Enumerate every site.** Listing route registrations or grep hits is cheap; state the total, N.
2. **Verify every high-risk site in full**: reachable without authentication, state-changing, privileged, or acting on a resource identified by the caller.
3. **Sample the rest across the codebase**, spread over modules rather than taken from the first directory found, and state the method.

A violation found in a sample is a FAIL like any other. A sample that finds nothing is a PASS qualified as sampled: record `sampled n of N` and the method in the matrix's Coverage column. A requirement decided on every site is `full`. Never record sampled evidence as `full` — a sampled PASS is weaker evidence than a full one, and the reader must be able to tell them apart.
