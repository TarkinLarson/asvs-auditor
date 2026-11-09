#!/usr/bin/env bash
#
# Pre-release smoke test for the ASVS Auditor skills.
#
# Runs the cheapest checks first so a packaging mistake is caught before any
# model call is made. Stage 0 costs nothing; stages 1 and 2 call the model and
# must be opted into explicitly.
#
#   stage 0  static    skill frontmatter, plugin manifest, reference completeness,
#                      line endings, and (unless --offline) ASVS reference drift
#   stage 1  load      the skill loads with no plugin errors, via --plugin-dir
#   stage 2  scan      a real CI scan of --target: output parses, the scan actually
#                      ran and swept the standard, the report is internally
#                      consistent, and the target tree is left byte-for-byte
#                      unmodified
#
# Nothing here reads credentials, writes outside the repo's .smoke/ directory and
# a temporary copy of the target, or contacts any host other than the ones the
# Claude Code CLI and the reference generator already use.
#
# Requires: bash, python3, git. Stages 1-2 additionally require the `claude` CLI.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$REPO_ROOT/.smoke"
MANIFEST="$REPO_ROOT/.claude-plugin/plugin.json"
SCHEMA="$REPO_ROOT/schema/asvs-report.schema.json"
REFERENCE_DIR="$REPO_ROOT/skills/agent-asvs-ci/reference"

STAGES="0"
TARGET=""
BUDGET="10"
MAX_TURNS="100"
MIN_COVERAGE="90"
MODEL=""
INVOKE=""
OFFLINE=0
STRICT=0
KEEP=0
NO_SCHEMA=0
SCRATCH=""

PASSED=0
FAILED=0
SKIPPED=0

if [ -t 1 ]; then
  C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_SKIP=$'\033[33m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_BAD=""; C_SKIP=""; C_OFF=""
fi

usage() {
  sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --stages LIST     comma-separated stages to run (default: 0)
  --target PATH     directory to scan in stage 2 (required for stage 2)
  --budget USD      hard spend cap per model run (default: 10)
  --max-turns N     stage 2: turn cap for the scan (default: 100)
  --min-coverage P  stage 2: percent of in-scope requirements the scan must
                    record as checked (default: 90)
  --model ID        model to pass to the CLI, e.g. claude-opus-5-5
  --invoke CMD      slash command to run (default: derived from the plugin manifest)
  --offline         skip checks that need network access
  --strict          treat skipped checks as failures
  --keep            keep the temporary copy of the scan target
  --no-schema       stage 2: do not constrain output with schema/, for A/B runs
  -h, --help        show this help

Examples:
  tools/smoke.sh                                   # free static checks
  tools/smoke.sh --stages 0,1                      # add a minimal load check
  tools/smoke.sh --stages 0,1,2 --target ~/src/app # full pre-release run
EOF
}

pass() { PASSED=$((PASSED + 1)); printf '%s  PASS%s  %s\n' "$C_OK" "$C_OFF" "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '%s  FAIL%s  %s\n' "$C_BAD" "$C_OFF" "$1"; }
skip() {
  if [ "$STRICT" -eq 1 ]; then
    FAILED=$((FAILED + 1)); printf '%s  FAIL%s  %s (skipped under --strict)\n' "$C_BAD" "$C_OFF" "$1"
  else
    SKIPPED=$((SKIPPED + 1)); printf '%s  SKIP%s  %s\n' "$C_SKIP" "$C_OFF" "$1"
  fi
}
stage_header() { printf '\n== stage %s: %s ==\n' "$1" "$2"; }

cleanup() {
  if [ -n "$SCRATCH" ] && [ -d "$SCRATCH" ] && [ "$KEEP" -eq 0 ]; then
    rm -rf "$SCRATCH"
  elif [ -n "$SCRATCH" ] && [ "$KEEP" -eq 1 ]; then
    printf '\nkept scan copy: %s\n' "$SCRATCH"
  fi
}
trap cleanup EXIT

wants() { case ",$STAGES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# True when the installed CLI is at least the given version.
claude_at_least() {
  local want="$1" have
  have="$(claude --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)" || true
  [ -n "$have" ] || return 1
  python3 - "$have" "$want" <<'PY'
import sys
parse = lambda v: tuple(int(p) for p in v.split("."))
sys.exit(0 if parse(sys.argv[1]) >= parse(sys.argv[2]) else 1)
PY
}

# The plugin's namespace: the manifest's name, or, with no manifest, the
# directory name, which is what Claude Code derives it from. Invoking the bare
# skill name instead would resolve to whatever copy is installed in
# ~/.claude/skills and silently test that rather than this working tree.
plugin_namespace() {
  if [ ! -f "$MANIFEST" ]; then
    basename "$REPO_ROOT"
    return 0
  fi
  python3 - "$MANIFEST" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        name = json.load(handle).get("name", "")
except (OSError, ValueError):
    sys.exit(1)  # a corrupt manifest is reported by the caller, not traced here
if not name:
    sys.exit(1)
print(name)
PY
}

# ---------------------------------------------------------------- stage 0

stage_static() {
  stage_header 0 "static checks (no model calls)"

  if python3 "$REPO_ROOT/tools/check-skills.py" >/dev/null 2>&1; then
    pass "skill frontmatter and bundled reference are valid"
  else
    fail "skill validation failed — rerun: python3 tools/check-skills.py"
  fi

  if [ ! -f "$MANIFEST" ]; then
    skip "claude plugin validate (no .claude-plugin/plugin.json yet)"
  elif ! command -v claude >/dev/null 2>&1; then
    skip "claude plugin validate (CLI not installed)"
  else
    local validate_log="$ARTIFACT_DIR/stage0-validate.txt"
    mkdir -p "$ARTIFACT_DIR"
    if claude plugin validate "$REPO_ROOT" --strict >"$validate_log" 2>&1; then
      pass "claude plugin validate --strict"
    else
      fail "claude plugin validate --strict failed:"
      grep -E '^\s+>|^(×|‼)' "$validate_log" | sed 's/^/          /' || true
    fi
  fi

  if ! command -v git >/dev/null 2>&1; then
    skip "line-ending and trailing-newline checks (git not installed)"
  else
    local offenders
    # Reads the index, not the working tree: what ships is what git stores, and
    # under core.autocrlf=true a working copy checked out before .gitattributes
    # existed can be CRLF while the stored blob is LF. Staged edits are checked
    # too, since they are what the next commit would ship.
    offenders="$(python3 - "$REPO_ROOT" <<'PY'
import subprocess, sys
root = sys.argv[1]
listing = subprocess.run(
    ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True
).stdout
names = [n.decode() for n in listing.split(b"\0") if n]
batch = subprocess.run(
    ["git", "cat-file", "--batch"], cwd=root, check=True, capture_output=True,
    input="".join(f":{name}\n" for name in names).encode(),
).stdout
bad, pos = [], 0
for name in names:
    header_end = batch.index(b"\n", pos)
    header = batch[pos:header_end].split()
    if header[-1] == b"missing":
        pos = header_end + 1
        continue
    size = int(header[2])
    data = batch[header_end + 1 : header_end + 1 + size]
    pos = header_end + 1 + size + 1  # blob, then a trailing LF
    if b"\0" in data[:8192]:
        continue  # binary
    if b"\r" in data:
        bad.append(f"{name}: CRLF line endings")
    elif data and not data.endswith(b"\n"):
        bad.append(f"{name}: no trailing newline")
print("\n".join(bad))
PY
)"
    if [ -z "$offenders" ]; then
      pass "all tracked text files are LF with a trailing newline"
    else
      fail "line-ending or trailing-newline problems:"
      printf '%s\n' "$offenders" | sed 's/^/          /'
    fi
  fi

  if [ "$OFFLINE" -eq 1 ]; then
    skip "ASVS reference drift (--offline; the check fetches the pinned tag)"
    return
  fi

  # The generator exits 1 for genuine drift and 2 for a fetch or parse error.
  # Reporting those identically would blame the repository for a rate-limited
  # or blocked network, so they are kept apart.
  local drift_log="$ARTIFACT_DIR/stage0-drift.txt" drift_status=0
  mkdir -p "$ARTIFACT_DIR"
  python3 "$REPO_ROOT/tools/generate-asvs-reference.py" --check >"$drift_log" 2>&1 || drift_status=$?
  case "$drift_status" in
    0) pass "generated ASVS reference matches the pinned tag" ;;
    1) fail "ASVS reference has drifted — rerun: python3 tools/generate-asvs-reference.py" ;;
    *)
      skip "ASVS reference drift: could not reach the ASVS source"
      sed -n '1,3p' "$drift_log" | sed 's/^/          /'
      ;;
  esac
}

# ---------------------------------------------------------------- stage 1

stage_load() {
  stage_header 1 "load check (one minimal model call)"

  if ! command -v claude >/dev/null 2>&1; then
    skip "plugin load check (claude CLI not installed)"
    return
  fi

  mkdir -p "$ARTIFACT_DIR"
  local events="$ARTIFACT_DIR/stage1-init.jsonl"
  if ! claude --plugin-dir "$REPO_ROOT" -p "Reply with the single word OK." \
      --max-turns 1 --max-budget-usd "$BUDGET" \
      --output-format stream-json --verbose >"$events" 2>"$ARTIFACT_DIR/stage1-stderr.txt"; then
    fail "the CLI exited non-zero — see .smoke/stage1-stderr.txt"
    return
  fi

  local verdict expected
  # A malformed manifest makes this fail; keep going so the check reports it
  # rather than aborting the run under `set -e`.
  expected="$(plugin_namespace || true)"
  verdict="$(python3 - "$events" "$expected" <<'PY'
import json, sys
init = None
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("type") == "system" and event.get("subtype") == "init":
        init = event
        break
if init is None:
    print("FAIL no system/init event in the stream")
    raise SystemExit(0)
errors = init.get("plugin_errors") or []
if errors:
    print("FAIL plugin_errors: " + json.dumps(errors))
    raise SystemExit(0)

# Claude Code always loads its own builtin plugins, so "some plugins loaded" is
# not evidence that ours did. Match the name from our manifest specifically.
wanted = sys.argv[2]
loaded = {p.get("name"): p for p in init.get("plugins") or []}
ours = loaded.get(wanted)
if ours is None:
    print(f"FAIL {wanted!r} is not in the loaded plugins: {sorted(loaded) or 'none'}")
elif ours.get("path") == "builtin":
    print(f"FAIL {wanted!r} resolved to a builtin, not this working tree")
else:
    print(f"PASS {wanted} v{ours.get('version', '?')} from {ours.get('path')}")
PY
)"
  case "$verdict" in
    PASS*) pass "plugin loads cleanly — ${verdict#PASS }" ;;
    *) fail "plugin did not load — ${verdict#FAIL }" ;;
  esac
}

# ---------------------------------------------------------------- stage 2

stage_scan() {
  stage_header 2 "scan check (a full audit — this costs money)"

  if ! command -v claude >/dev/null 2>&1; then
    skip "scan check (claude CLI not installed)"
    return
  fi
  if [ -z "$TARGET" ]; then
    skip "scan check (no --target given)"
    return
  fi
  if [ ! -d "$TARGET" ]; then
    fail "scan check: --target is not a directory: $TARGET"
    return
  fi

  local invoke="$INVOKE" namespace
  if [ -z "$invoke" ]; then
    if namespace="$(plugin_namespace)"; then
      invoke="/${namespace}:agent-asvs-ci"
    else
      skip "scan check (could not read the plugin manifest; pass --invoke to name the slash command)"
      return
    fi
  fi

  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/asvs-smoke.XXXXXX")"
  cp -a "$TARGET" "$SCRATCH/target"
  local copy="$SCRATCH/target"

  local hash_before hash_after
  hash_before="$(tree_hash "$copy")"

  mkdir -p "$ARTIFACT_DIR"
  local envelope="$ARTIFACT_DIR/stage2-envelope.json"
  local args=(
    --plugin-dir "$REPO_ROOT"
    -p "$invoke"
    --permission-mode dontAsk
    --max-turns "$MAX_TURNS"
    --max-budget-usd "$BUDGET"
    --output-format json
  )
  if claude_at_least 2.1.259; then
    args+=(--permission-prompts none)
  else
    skip "--permission-prompts none (needs claude 2.1.259 or later)"
  fi
  if [ "$NO_SCHEMA" -eq 1 ]; then
    skip "output schema not enforced (--no-schema)"
  elif [ -f "$SCHEMA" ]; then
    args+=(--json-schema "$(cat "$SCHEMA")")
  else
    skip "output schema not enforced (schema/asvs-report.schema.json is missing)"
  fi
  if [ -n "$MODEL" ]; then
    args+=(--model "$MODEL")
  fi

  if ! (cd "$copy" && claude "${args[@]}") >"$envelope" 2>"$ARTIFACT_DIR/stage2-stderr.txt"; then
    fail "the CLI exited non-zero — see .smoke/stage2-stderr.txt"
  else
    pass "the scan completed and the CLI exited 0"
  fi

  hash_after="$(tree_hash "$copy")"
  if [ "$hash_before" = "$hash_after" ]; then
    pass "target tree unmodified — the auditor made no writes"
  else
    fail "TARGET TREE WAS MODIFIED — the auditor is not read-only"
  fi

  local verdict
  verdict="$(python3 - "$envelope" "$ARTIFACT_DIR/stage2-report.json" <<'PY'
import json, re, sys

try:
    envelope = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    print(f"FAIL the CLI envelope is not JSON: {exc}")
    raise SystemExit(0)

report = envelope.get("structured_output")
if report is None:
    text = envelope.get("result") or ""
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        print("FAIL no JSON report in the response (a refusal looks exactly like this)")
        raise SystemExit(0)
    try:
        report = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        print(f"FAIL the report is not parseable JSON: {exc}")
        raise SystemExit(0)

with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")

summary = report.get("scan_summary") or {}
compliance = report.get("compliance_summary") or {}
problems = []
if summary.get("error"):
    problems.append(f"the scan reported an error: {summary['error']}")
files = summary.get("files_scanned")
if not isinstance(files, int) or files <= 0:
    problems.append(f"files_scanned is {files!r} — the scan did not actually read anything")
if not compliance.get("checked_requirements"):
    problems.append("checked_requirements is empty — no requirement was evaluated")

cost = envelope.get("total_cost_usd")
detail = f"files_scanned={files}, findings={summary.get('total_findings')}, pass={summary.get('pass')}"
if isinstance(cost, (int, float)):
    detail += f", cost=${cost:.2f}"

if problems:
    print("FAIL " + "; ".join(problems))
else:
    print("PASS " + detail)
PY
)"
  case "$verdict" in
    PASS*) pass "report is usable — ${verdict#PASS }" ;;
    *) fail "report is unusable — ${verdict#FAIL }" ;;
  esac

  # A usable report can still be a shallow or self-contradictory one. Coverage
  # is measured against the bundled reference rather than trusted from the
  # report, and the compliance arrays must agree with the findings they
  # summarise.
  if [ -f "$ARTIFACT_DIR/stage2-report.json" ]; then
    local consistency
    consistency="$(python3 - "$ARTIFACT_DIR/stage2-report.json" "$REFERENCE_DIR" "$MIN_COVERAGE" <<'PY'
import json, pathlib, re, sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
reference, min_coverage = pathlib.Path(sys.argv[2]), float(sys.argv[3])

level = {"L1": 1, "L2": 2, "L3": 3}.get((report.get("scan_metadata") or {}).get("asvs_level"), 2)
row = re.compile(r"^\| \*\*(\d+\.\d+\.\d+)\*\* \| L([123]) \|", re.M)
in_scope = {
    f"V{req}"
    for chapter in reference.glob("V*.md")
    for req, lvl in row.findall(chapter.read_text(encoding="utf-8"))
    if int(lvl) <= level
}
if not in_scope:
    print(f"FAIL no requirements parsed from {reference}")
    raise SystemExit(0)

summary = report.get("compliance_summary") or {}
not_applicable = summary.get("not_applicable") or []
in_scope = {
    req for req in in_scope
    if not any(req == na or req.startswith(na + ".") for na in not_applicable)
}

checked = set(summary.get("checked_requirements") or [])
passed = set(summary.get("passed_requirements") or [])
failed = set(summary.get("failed_requirements") or [])
sampled = set(summary.get("sampled_requirements") or {})
findings = report.get("findings") or []
finding_ids = {f.get("id") for f in findings}
finding_reqs = {f.get("asvs_requirement") for f in findings}
scan_summary = report.get("scan_summary") or {}
truncated = scan_summary.get("findings_truncated")

problems = []
if passed & failed:
    problems.append(f"passed and failed overlap: {sorted(passed & failed)}")
if (passed | failed) - checked:
    problems.append(f"passed/failed but not checked: {sorted((passed | failed) - checked)}")
if sampled - passed:
    problems.append(f"sampled but not passed: {sorted(sampled - passed)}")
# With the 50-finding cap engaged, failed requirements may have no emitted finding.
if not truncated and failed != finding_reqs:
    problems.append(f"failed_requirements and the findings disagree on: {sorted(failed ^ finding_reqs)}")
without_root_cause = sorted(f.get("id") for f in findings if not f.get("root_cause"))
if without_root_cause:
    problems.append(f"findings without root_cause: {without_root_cause}")
root_causes = {f.get("root_cause") for f in findings if f.get("root_cause")}
declared = scan_summary.get("root_causes")
if not isinstance(declared, int):
    problems.append("scan_summary.root_causes is missing")
elif declared < len(root_causes) or (not truncated and declared != len(root_causes)):
    problems.append(f"root_causes is {declared} but the findings carry {len(root_causes)} distinct values")
for index, rec in enumerate(report.get("recommendations") or []):
    addressed = set(rec.get("findings_addressed") or [])
    if not addressed:
        problems.append(f"recommendations[{index}] links no finding")
    elif addressed - finding_ids:
        problems.append(f"recommendations[{index}] links unknown ids: {sorted(addressed - finding_ids)}")

swept = checked & in_scope
coverage = 100.0 * len(swept) / len(in_scope) if in_scope else 100.0
if coverage < min_coverage:
    problems.append(f"coverage {coverage:.0f}% is below --min-coverage {min_coverage:g}%")
detail = (f"{len(swept)}/{len(in_scope)} in-scope requirements checked ({coverage:.0f}%): "
          f"{len(passed & swept)} passed ({len(sampled & swept)} sampled), {len(failed & swept)} failed, "
          f"{len(swept - passed - failed)} inconclusive; {len(root_causes)} root causes")
# ASCII only: on Windows a piped Python stdout is not UTF-8.
print(("FAIL " + "; ".join(problems) + "; " if problems else "PASS ") + detail)
PY
)"
    case "$consistency" in
      PASS*) pass "report swept the standard and is consistent — ${consistency#PASS }" ;;
      *) fail "report is shallow or inconsistent — ${consistency#FAIL }" ;;
    esac
  fi

  # Conformance is checked separately from usability: --json-schema constrains
  # the shape at generation time, and this proves the committed contract and
  # what the scanner emits have not drifted apart.
  if [ -f "$SCHEMA" ] && [ -f "$ARTIFACT_DIR/stage2-report.json" ]; then
    local schema_verdict
    schema_verdict="$(python3 - "$SCHEMA" "$ARTIFACT_DIR/stage2-report.json" <<'PY'
import json, sys
try:
    import jsonschema
except ImportError:
    print("SKIP report not validated against the schema (pip install jsonschema)")
    raise SystemExit(0)

schema = json.load(open(sys.argv[1], encoding="utf-8"))
report = json.load(open(sys.argv[2], encoding="utf-8"))
errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(report), key=lambda e: list(e.path))
if not errors:
    print("PASS report conforms to schema/asvs-report.schema.json")
else:
    first = errors[0]
    where = "/".join(str(p) for p in first.path) or "(root)"
    print(f"FAIL {len(errors)} schema violation(s); first at {where}: {first.message[:160]}")
PY
)"
    case "$schema_verdict" in
      PASS*) pass "${schema_verdict#PASS }" ;;
      SKIP*) skip "${schema_verdict#SKIP }" ;;
      *) fail "${schema_verdict#FAIL }" ;;
    esac
  fi

  printf '          artifacts: .smoke/stage2-envelope.json, .smoke/stage2-report.json\n'
}

# Hash every file path, mode and content under a directory, so any write,
# deletion or permission change shows up as a different digest.
tree_hash() {
  python3 - "$1" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
    digest.update(str(path.relative_to(root)).encode())
    digest.update(str(path.stat().st_mode).encode())
    digest.update(path.read_bytes())
print(digest.hexdigest())
PY
}

# ---------------------------------------------------------------- main

while [ $# -gt 0 ]; do
  case "$1" in
    --stages) STAGES="${2:?--stages needs a value}"; shift 2 ;;
    --target) TARGET="${2:?--target needs a path}"; shift 2 ;;
    --budget) BUDGET="${2:?--budget needs a value}"; shift 2 ;;
    --max-turns) MAX_TURNS="${2:?--max-turns needs a value}"; shift 2 ;;
    --min-coverage) MIN_COVERAGE="${2:?--min-coverage needs a value}"; shift 2 ;;
    --model) MODEL="${2:?--model needs a value}"; shift 2 ;;
    --invoke) INVOKE="${2:?--invoke needs a value}"; shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    --strict) STRICT=1; shift ;;
    --keep) KEEP=1; shift ;;
    --no-schema) NO_SCHEMA=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'error: unknown option %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

for tool in python3; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'error: %s is required\n' "$tool" >&2; exit 2; }
done

if wants 0; then stage_static; fi
if wants 1; then stage_load; fi
if wants 2; then stage_scan; fi

printf '\n%d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
