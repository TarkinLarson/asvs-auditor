#!/usr/bin/env python3
"""Generate the ASVS requirement reference shipped with each skill.

The reference used to be maintained by hand and drifted from the spec in four
separate releases: fabricated sections (V5.5/V5.6, V9.3, V12.3), whole chapters
shifted by one (V10, V14), mis-mapped topics (V4.2, V15.4, V17), understated
levels, and 14 missing sections. This script removes that failure mode by
deriving everything from the pinned ASVS tag.

Outputs, for each skill directory:
  reference/V<n>.md   full requirement text, IDs and levels for chapter <n>
  reference/README.md provenance and CC BY-SA 4.0 attribution
and rewrites the section index inside each SKILL.md between the markers
defined in MARKER_BEGIN / MARKER_END.

Usage:
  python3 tools/generate-asvs-reference.py            # write
  python3 tools/generate-asvs-reference.py --check     # exit 1 if outputs drift

Requires only the standard library so it runs on a bare CI runner.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ASVS_TAG = "v5.0.0"
ASVS_REPO = "OWASP/ASVS"
CHAPTER_DIR = "5.0/en"

RAW_BASE = f"https://raw.githubusercontent.com/{ASVS_REPO}/{ASVS_TAG}/{CHAPTER_DIR}"
BLOB_BASE = f"https://github.com/{ASVS_REPO}/blob/{ASVS_TAG}/{CHAPTER_DIR}"
API_CONTENTS = f"https://api.github.com/repos/{ASVS_REPO}/contents/{CHAPTER_DIR}?ref={ASVS_TAG}"

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIRS = [REPO_ROOT / "skills" / "agent-asvs", REPO_ROOT / "skills" / "agent-asvs-ci"]
# The CI variant needs a compact index; the interactive one can afford per-section lines.
COMPACT_SKILLS = {"agent-asvs-ci"}

MARKER_BEGIN = "<!-- BEGIN GENERATED ASVS REFERENCE -->"
MARKER_END = "<!-- END GENERATED ASVS REFERENCE -->"

# Expected totals, asserted so a silent parse regression cannot ship.
EXPECTED_CHAPTERS = 17
EXPECTED_SECTIONS = 80
EXPECTED_REQUIREMENTS = 345

CHAPTER_FILE_RE = re.compile(r"^0x\d{2}-V(\d{1,2})-(.+)\.md$")
H1_RE = re.compile(r"^#\s+V(\d{1,2})\s+(.+?)\s*$")
SECTION_RE = re.compile(r"^##\s+V(\d{1,2})\.(\d{1,2})\s+(.+?)\s*$")
REQ_ROW_RE = re.compile(r"^\|\s*\*\*(\d{1,2})\.(\d{1,2})\.(\d{1,2})\*\*\s*\|(.+?)\|\s*([^|]*?)\s*\|\s*$")
TABLE_HEAD_RE = re.compile(r"^\|\s*#\s*\|\s*Description\s*\|\s*Level\s*\|")


class ParseError(RuntimeError):
    pass


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "asvs-auditor-reference-generator"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise ParseError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise ParseError(f"network error fetching {url}: {exc.reason}") from exc


def chapter_files() -> list[tuple[int, str]]:
    """Return [(chapter_number, filename)] for the pinned tag, chapter order."""
    listing = json.loads(fetch(API_CONTENTS))
    found: list[tuple[int, str]] = []
    for entry in listing:
        if entry.get("type") != "file":
            continue
        m = CHAPTER_FILE_RE.match(entry["name"])
        if m:
            found.append((int(m.group(1)), entry["name"]))
    found.sort(key=lambda t: t[0])
    if len(found) != EXPECTED_CHAPTERS:
        raise ParseError(
            f"expected {EXPECTED_CHAPTERS} chapter files at {ASVS_TAG}, found {len(found)}: "
            f"{[f for _, f in found]}"
        )
    numbers = [n for n, _ in found]
    if numbers != list(range(1, EXPECTED_CHAPTERS + 1)):
        raise ParseError(f"chapter numbers are not V1..V{EXPECTED_CHAPTERS}: {numbers}")
    return found


def parse_chapter(number: int, filename: str, text: str) -> dict:
    """Parse one chapter into {number, title, filename, sections:[...]}.

    Raises ParseError on anything unexpected rather than guessing, because a
    silent mis-parse is exactly the failure this script exists to prevent.
    """
    lines = text.splitlines()
    title = None
    sections: list[dict] = []
    current: dict | None = None
    in_table = False

    for lineno, line in enumerate(lines, 1):
        if title is None:
            m = H1_RE.match(line)
            if m:
                if int(m.group(1)) != number:
                    raise ParseError(f"{filename}:{lineno}: H1 says V{m.group(1)}, file says V{number}")
                title = m.group(2).strip()
                continue

        m = SECTION_RE.match(line)
        if m:
            chap, sec, sec_title = int(m.group(1)), int(m.group(2)), m.group(3).strip()
            if chap != number:
                raise ParseError(f"{filename}:{lineno}: section V{chap}.{sec} in chapter V{number}")
            current = {"id": f"V{chap}.{sec}", "number": sec, "title": sec_title, "requirements": []}
            sections.append(current)
            in_table = False
            continue

        if TABLE_HEAD_RE.match(line):
            if current is None:
                raise ParseError(f"{filename}:{lineno}: requirement table before any V{number}.x section")
            in_table = True
            continue

        if line.startswith("|") and in_table:
            if re.match(r"^\|[\s:|-]+\|$", line):  # separator row
                continue
            m = REQ_ROW_RE.match(line)
            if not m:
                raise ParseError(f"{filename}:{lineno}: unparsed table row: {line[:120]}")
            chap, sec, idx = int(m.group(1)), int(m.group(2)), int(m.group(3))
            desc = m.group(4).strip()
            level_raw = m.group(5).strip()
            if current is None or (chap, sec) != (number, current["number"]):
                raise ParseError(
                    f"{filename}:{lineno}: requirement {chap}.{sec}.{idx} is not inside "
                    f"section {current['id'] if current else 'None'}"
                )
            if level_raw not in {"1", "2", "3"}:
                raise ParseError(f"{filename}:{lineno}: level {level_raw!r} for {chap}.{sec}.{idx}")
            expected_idx = len(current["requirements"]) + 1
            if idx != expected_idx:
                raise ParseError(
                    f"{filename}:{lineno}: requirement {chap}.{sec}.{idx} out of sequence, "
                    f"expected {chap}.{sec}.{expected_idx}"
                )
            current["requirements"].append(
                {"id": f"{chap}.{sec}.{idx}", "text": desc, "level": int(level_raw)}
            )
            continue

        if in_table and not line.startswith("|"):
            in_table = False

    if title is None:
        raise ParseError(f"{filename}: no '# V{number} <title>' heading found")
    if not sections:
        raise ParseError(f"{filename}: no V{number}.x sections found")

    numbers = [s["number"] for s in sections]
    if numbers != sorted(numbers):
        raise ParseError(f"{filename}: sections out of order: {numbers}")

    return {"number": number, "title": title, "filename": filename, "sections": sections}


def level_range(levels: list[int]) -> str:
    if not levels:
        return "—"
    lo, hi = min(levels), max(levels)
    return f"L{lo}" if lo == hi else f"L{lo}–L{hi}"


def req_range(reqs: list[dict]) -> str:
    if not reqs:
        return "no requirements"
    if len(reqs) == 1:
        return f"1 requirement ({reqs[0]['id']})"
    return f"{len(reqs)} requirements ({reqs[0]['id']}–{reqs[-1]['id']})"


def render_chapter_file(chapter: dict) -> str:
    n, title = chapter["number"], chapter["title"]
    total = sum(len(s["requirements"]) for s in chapter["sections"])
    out = [
        f"# V{n}: {title}",
        "",
        f"ASVS {ASVS_TAG} — {len(chapter['sections'])} sections, {total} requirements.",
        f"Source: [{chapter['filename']}]({BLOB_BASE}/{chapter['filename']})",
        "",
        "Generated by `tools/generate-asvs-reference.py`. Do not edit by hand.",
        "Requirement text is quoted from OWASP ASVS, licensed CC BY-SA 4.0 — see `README.md` in this directory.",
        "",
    ]
    for s in chapter["sections"]:
        reqs = s["requirements"]
        out.append(f"## {s['id']} {s['title']}")
        out.append("")
        if not reqs:
            out.append("_No requirements in this section._")
            out.append("")
            continue
        out.append(f"{req_range(reqs)}, {level_range([r['level'] for r in reqs])}")
        out.append("")
        out.append("| Requirement | Level | Text |")
        out.append("| :--- | :---: | :--- |")
        for r in reqs:
            text = r["text"].replace("|", "\\|")
            out.append(f"| **{r['id']}** | L{r['level']} | {text} |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_reference_readme(chapters: list[dict]) -> str:
    total_sections = sum(len(c["sections"]) for c in chapters)
    total_reqs = sum(len(s["requirements"]) for c in chapters for s in c["sections"])
    rows = "\n".join(
        f"| [V{c['number']}.md](V{c['number']}.md) | {c['title']} | {len(c['sections'])} | "
        f"{sum(len(s['requirements']) for s in c['sections'])} |"
        for c in chapters
    )
    return f"""# ASVS {ASVS_TAG} requirement reference

Generated by `tools/generate-asvs-reference.py` from the pinned
[{ASVS_REPO}@{ASVS_TAG}]({BLOB_BASE}) source. **Do not edit these files by hand** —
regenerate them instead, or CI will fail on drift.

{len(chapters)} chapters, {total_sections} sections, {total_reqs} requirements.

| File | Chapter | Sections | Requirements |
| :--- | :--- | :---: | :---: |
{rows}

## Why these files exist

The auditor prompt used to carry a hand-written summary of the standard. It drifted
from the spec in four separate releases — fabricated sections, chapters shifted by
one, mis-mapped topics, understated levels, and missing sections — because nothing
checked it against the source. These files are generated, and CI diffs them against
a fresh generation, so that class of error cannot ship again.

Keeping full requirement text here rather than in `SKILL.md` also means it costs no
context until the agent reads the chapter it needs.

## Attribution and licence

Requirement text is quoted from the [OWASP Application Security Verification
Standard](https://github.com/{ASVS_REPO}) version 5.0.0, © OWASP Foundation,
licensed under [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/)
(CC BY-SA 4.0). These generated files are derivative works and carry the same
CC BY-SA 4.0 licence.

The rest of this repository — the prompts, tooling, and documentation — is MIT
licensed; see [LICENSE](../../../LICENSE). The two licences apply to different
files: CC BY-SA 4.0 to the quoted ASVS requirement text in this directory, MIT to
everything else.
"""


def render_index(chapters: list[dict], compact: bool) -> str:
    total_sections = sum(len(c["sections"]) for c in chapters)
    total_reqs = sum(len(s["requirements"]) for c in chapters for s in c["sections"])
    out = [
        MARKER_BEGIN,
        f"<!-- Generated from {ASVS_REPO}@{ASVS_TAG} by tools/generate-asvs-reference.py. Do not edit by hand. -->",
        "",
        f"ASVS {ASVS_TAG}: {len(chapters)} chapters, {total_sections} sections, {total_reqs} requirements.",
        "",
        "**Full requirement text for every chapter ships alongside this prompt in "
        "`reference/V<n>.md`.** Read the relevant file before citing a requirement ID — "
        "the index below gives section titles, requirement counts, and level ranges, "
        "but not the requirement text. Never cite from memory.",
        "",
        f"If the reference files are not present (only `SKILL.md` was installed), fetch the "
        f"chapter from {BLOB_BASE}/ instead. If neither is reachable, cite at section level "
        f"(e.g. V1.2) rather than guessing a requirement number.",
        "",
    ]
    for c in chapters:
        n = c["number"]
        creqs = sum(len(s["requirements"]) for s in c["sections"])
        if compact:
            parts = [
                f"{s['id']} {s['title']} ({len(s['requirements'])}, "
                f"{level_range([r['level'] for r in s['requirements']])})"
                for s in c["sections"]
            ]
            out.append(f"- **V{n}: {c['title']}** ({creqs} reqs) — " + "; ".join(parts) + f" — `reference/V{n}.md`")
        else:
            out.append(f"### V{n}: {c['title']}")
            out.append(f"`reference/V{n}.md` — {len(c['sections'])} sections, {creqs} requirements")
            out.append("")
            for s in c["sections"]:
                reqs = s["requirements"]
                out.append(
                    f"- **{s['id']}** {s['title']} — {req_range(reqs)}, "
                    f"{level_range([r['level'] for r in reqs])}"
                )
            out.append("")
    out.append(MARKER_END)
    return "\n".join(out).rstrip() + "\n"


def splice_index(skill_md: str, index: str, path: Path) -> str:
    start = skill_md.find(MARKER_BEGIN)
    end = skill_md.find(MARKER_END)
    if start == -1 or end == -1:
        raise ParseError(
            f"{path}: missing {MARKER_BEGIN} / {MARKER_END} markers — add them around the "
            "generated reference section before running this script"
        )
    if end < start:
        raise ParseError(f"{path}: END marker precedes BEGIN marker")
    return skill_md[:start] + index.rstrip("\n") + skill_md[end + len(MARKER_END):]


def build_outputs(chapters: list[dict]) -> dict[Path, str]:
    outputs: dict[Path, str] = {}
    for skill_dir in SKILL_DIRS:
        ref_dir = skill_dir / "reference"
        for c in chapters:
            outputs[ref_dir / f"V{c['number']}.md"] = render_chapter_file(c)
        outputs[ref_dir / "README.md"] = render_reference_readme(chapters)

        skill_md_path = skill_dir / "SKILL.md"
        if not skill_md_path.exists():
            raise ParseError(f"{skill_md_path} not found")
        index = render_index(chapters, compact=skill_dir.name in COMPACT_SKILLS)
        outputs[skill_md_path] = splice_index(
            skill_md_path.read_text(encoding="utf-8"), index, skill_md_path
        )
    return outputs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="verify committed files match a fresh generation")
    args = ap.parse_args()

    try:
        chapters = [parse_chapter(n, f, fetch(f"{RAW_BASE}/{f}")) for n, f in chapter_files()]
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    total_sections = sum(len(c["sections"]) for c in chapters)
    total_reqs = sum(len(s["requirements"]) for c in chapters for s in c["sections"])
    problems = []
    if total_sections != EXPECTED_SECTIONS:
        problems.append(f"parsed {total_sections} sections, expected {EXPECTED_SECTIONS}")
    if total_reqs != EXPECTED_REQUIREMENTS:
        problems.append(f"parsed {total_reqs} requirements, expected {EXPECTED_REQUIREMENTS}")
    if problems:
        print("error: " + "; ".join(problems), file=sys.stderr)
        print(
            "If ASVS published a revision, update EXPECTED_SECTIONS/EXPECTED_REQUIREMENTS "
            "deliberately after reviewing the diff.",
            file=sys.stderr,
        )
        return 2

    try:
        outputs = build_outputs(chapters)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        drifted = []
        for path, content in sorted(outputs.items()):
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != content:
                drifted.append(path)
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
                f"\nerror: {len(drifted)} generated file(s) differ from a fresh generation. "
                "Run: python3 tools/generate-asvs-reference.py",
                file=sys.stderr,
            )
            return 1
        print(f"ok: {len(outputs)} generated files match {ASVS_TAG} "
              f"({len(chapters)} chapters, {total_sections} sections, {total_reqs} requirements)")
        return 0

    for path, content in sorted(outputs.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    print(f"wrote {len(outputs)} files from {ASVS_REPO}@{ASVS_TAG} "
          f"({len(chapters)} chapters, {total_sections} sections, {total_reqs} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
