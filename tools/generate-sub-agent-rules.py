#!/usr/bin/env python3
"""Generate the rule file the interactive auditor hands to its sub-agents.

On a large codebase the interactive skill delegates groups of chapters to
sub-agents. They need the coordinator's rules, but not its process, its chapter
index or its report template. Having the coordinator retype the rules into each
brief was lossy: sub-agents applied the documentation, prerequisite and
judgement rules inconsistently. Loading the whole of SKILL.md into each
sub-agent instead costs more than twice what the rules alone do.

So the rules stay in SKILL.md, where the coordinator always has them, and this
script copies them verbatim into a file a sub-agent reads directly. SKILL.md is
the single source: the file is everything between MARKER_BEGIN and MARKER_END,
under a fixed preamble.

Outputs, for each skill directory in SKILL_DIRS:
  sub-agent-rules.md

Usage:
  python3 tools/generate-sub-agent-rules.py            # write
  python3 tools/generate-sub-agent-rules.py --check    # exit 1 if the file drifts

Requires only the standard library, and reads no network or credentials.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Only the interactive variant delegates to sub-agents.
SKILL_DIRS = [REPO_ROOT / "skills" / "agent-asvs"]
OUTPUT_NAME = "sub-agent-rules.md"

MARKER_BEGIN = "<!-- BEGIN SUB-AGENT RULES -->"
MARKER_END = "<!-- END SUB-AGENT RULES -->"

PREAMBLE = """\
# ASVS Auditor: rules for sub-agents

<!-- Generated from SKILL.md by tools/generate-sub-agent-rules.py. Do not edit by hand. -->

You are a sub-agent in an OWASP ASVS 5.0 audit. The coordinator has given you a target level, a list of chapters, and the paths of the files holding their requirement text. Read those files, then decide every requirement in them at or below the target level.

The rules below are the coordinator's own, copied verbatim. Where they mention the Requirement Sweep, numbered steps, the report or the compliance matrix, they describe the coordinator's process: your part of it is to decide each requirement you were given and return the rows.

## What to return

One row per requirement you were given: its ID, status, coverage (`full` or `sampled n of N`), evidence as `file:line`, and a note. For every FAIL and UNVERIFIABLE, add the finding text. Return rows only, never a prose summary or totals of your own; the coordinator computes every count from the rows.
"""


class GenerationError(RuntimeError):
    pass


def extract_rules(skill_md: str, path: Path) -> str:
    """Return the text between the markers, exclusive, stripped of surrounding blank lines."""
    for marker in (MARKER_BEGIN, MARKER_END):
        if skill_md.count(marker) != 1:
            raise GenerationError(
                f"{path}: expected exactly one {marker}, found {skill_md.count(marker)}"
            )
    start = skill_md.index(MARKER_BEGIN) + len(MARKER_BEGIN)
    end = skill_md.index(MARKER_END)
    if end < start:
        raise GenerationError(f"{path}: END marker precedes BEGIN marker")
    rules = skill_md[start:end].strip("\n")
    if not rules.strip():
        raise GenerationError(f"{path}: nothing between the sub-agent rule markers")
    return rules


def build_outputs() -> dict[Path, str]:
    outputs: dict[Path, str] = {}
    for skill_dir in SKILL_DIRS:
        skill_md_path = skill_dir / "SKILL.md"
        if not skill_md_path.is_file():
            raise GenerationError(f"{skill_md_path} not found")
        rules = extract_rules(skill_md_path.read_text(encoding="utf-8"), skill_md_path)
        outputs[skill_dir / OUTPUT_NAME] = f"{PREAMBLE}\n{rules}\n"
    return outputs


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--check", action="store_true", help="verify committed files match a fresh generation")
    args = ap.parse_args()

    try:
        outputs = build_outputs()
    except GenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        drifted = 0
        for path, content in sorted(outputs.items()):
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current == content:
                continue
            drifted += 1
            rel = path.relative_to(REPO_ROOT).as_posix()
            diff = difflib.unified_diff(
                current.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
                n=1,
            )
            sys.stdout.writelines(list(diff)[:40])
        if drifted:
            print(
                f"\nerror: {drifted} sub-agent rule file(s) differ from SKILL.md. "
                "Run: python3 tools/generate-sub-agent-rules.py",
                file=sys.stderr,
            )
            return 1
        print(f"ok: {len(outputs)} sub-agent rule file(s) match SKILL.md")
        return 0

    for path, content in sorted(outputs.items()):
        path.write_text(content, encoding="utf-8", newline="\n")
    print(f"wrote {len(outputs)} sub-agent rule file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
