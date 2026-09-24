#!/usr/bin/env python3
"""Validate skill packaging: frontmatter fields and bundled reference completeness.

Claude Code silently ignores unrecognised frontmatter fields and loads a skill
with no fields at all if the YAML fails to parse. Both failures are invisible at
runtime: a mistyped `allowed-tools` simply does not restrict anything, and a
skill whose frontmatter did not parse loses its description. This script turns
those silent failures into a non-zero exit.

It also checks that each skill ships the full `reference/` directory. A
`SKILL.md`-only install still works but degrades to section-level citations, so a
missing chapter file is a packaging defect worth catching before release.

Usage:
  python3 tools/check-skills.py            # check every skill under skills/
  python3 tools/check-skills.py PATH ...   # check specific skill directories

Requires only the standard library, and reads no network or credentials.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"

# Frontmatter fields Claude Code recognises. Anything else is silently ignored
# at runtime, so an unknown key here is almost always a typo.
KNOWN_FIELDS = {
    "agent",
    "allowed-tools",
    "argument-hint",
    "arguments",
    "background",
    "compatibility",
    "context",
    "description",
    "disable-model-invocation",
    "disallowed-tools",
    "effort",
    "hooks",
    "license",
    "metadata",
    "model",
    "name",
    "paths",
    "shell",
    "user-invocable",
    "when_to_use",
}

BOOLEAN_FIELDS = {"background", "disable-model-invocation", "user-invocable"}
BOOLEAN_VALUES = {"yes", "no", "on", "off", "1", "0", "true", "false"}
EFFORT_VALUES = {"low", "medium", "high", "xhigh", "max"}

# One file per ASVS 5.0 chapter, plus the attribution README.
EXPECTED_CHAPTERS = 17

KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):(.*)$")


def parse_frontmatter(text: str) -> tuple[dict[str, str], list[str]]:
    """Return (top-level scalar fields, problems).

    Deliberately not a YAML parser: it extracts column-zero `key:` lines, which
    is all the field-name and scalar-value checks below need, and keeps this
    script on the standard library like the rest of tools/.
    """
    problems: list[str] = []
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, ["no YAML frontmatter: first line is not '---'"]

    end = next((i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---"), None)
    if end is None:
        return {}, ["unterminated YAML frontmatter: no closing '---'"]

    fields: dict[str, str] = {}
    for lineno, line in enumerate(lines[1:end], start=2):
        if not line.strip() or line.startswith("#") or line[0].isspace() or line.lstrip().startswith("- "):
            continue  # blank, comment, or a nested/list continuation of the previous key
        match = KEY_RE.match(line)
        if not match:
            problems.append(f"line {lineno}: not a 'key: value' pair: {line.strip()!r}")
            continue
        key, value = match.group(1), match.group(2).strip()
        if key in fields:
            problems.append(f"line {lineno}: duplicate field {key!r}")
        fields[key] = value
    return fields, problems


def check_fields(fields: dict[str, str]) -> list[str]:
    problems: list[str] = []

    for key in sorted(set(fields) - KNOWN_FIELDS):
        problems.append(
            f"unknown field {key!r} — Claude Code ignores unrecognised fields silently, "
            "so this does nothing at runtime"
        )

    if not fields.get("description"):
        problems.append("missing or empty 'description' — Claude uses it to decide when to invoke the skill")

    for key in sorted(BOOLEAN_FIELDS & set(fields)):
        if fields[key].lower() not in BOOLEAN_VALUES:
            problems.append(f"field {key!r} is not a boolean: {fields[key]!r}")

    effort = fields.get("effort")
    if effort is not None and effort.lower() not in EFFORT_VALUES:
        problems.append(f"field 'effort' must be one of {sorted(EFFORT_VALUES)}, got {effort!r}")

    context = fields.get("context")
    if context is not None and context.lower() != "fork":
        problems.append(f"field 'context' only accepts 'fork', got {context!r}")
    if "agent" in fields and context is None:
        problems.append("field 'agent' has no effect without 'context: fork'")
    if "background" in fields and context is None:
        problems.append("field 'background' has no effect without 'context: fork'")

    return problems


def check_reference(skill_dir: Path) -> list[str]:
    problems: list[str] = []
    reference = skill_dir / "reference"
    if not reference.is_dir():
        problems.append("no reference/ directory — citations would degrade to section level")
        return problems

    missing = [f"V{n}.md" for n in range(1, EXPECTED_CHAPTERS + 1) if not (reference / f"V{n}.md").is_file()]
    if missing:
        problems.append(f"reference/ is missing {len(missing)} chapter file(s): {', '.join(missing)}")
    if not (reference / "README.md").is_file():
        problems.append("reference/README.md is missing — it carries the CC BY-SA 4.0 attribution")
    return problems


def check_skill(skill_dir: Path) -> list[str]:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return ["no SKILL.md"]

    text = skill_md.read_text(encoding="utf-8")
    problems: list[str] = []
    if "\r" in text:
        problems.append("SKILL.md contains CR characters — .gitattributes pins LF")

    fields, parse_problems = parse_frontmatter(text)
    problems.extend(parse_problems)
    if not parse_problems:
        problems.extend(check_fields(fields))
    problems.extend(check_reference(skill_dir))
    return problems


def discover() -> list[Path]:
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(p for p in SKILLS_DIR.iterdir() if (p / "SKILL.md").is_file())


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="*", type=Path, help="skill directories to check (default: all under skills/)")
    args = ap.parse_args()

    skills = [p.resolve() for p in args.paths] if args.paths else discover()
    if not skills:
        print("error: no skills found to check", file=sys.stderr)
        return 2

    failed = 0
    for skill_dir in skills:
        try:
            rel = skill_dir.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            rel = skill_dir.as_posix()
        problems = check_skill(skill_dir)
        if problems:
            failed += 1
            print(f"error: {rel}", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
        else:
            print(f"ok: {rel}")

    if failed:
        print(f"\nerror: {failed} of {len(skills)} skill(s) failed validation", file=sys.stderr)
        return 1
    print(f"ok: {len(skills)} skill(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
