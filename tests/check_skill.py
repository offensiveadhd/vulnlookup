#!/usr/bin/env python3
"""The skill-format check CI runs: SKILL.md has the frontmatter the Agent Skills format wants,
every file it names exists, every command it shows parses, the plugin manifests agree on the
name and version, and the example input files are what `bulk` expects. Exit 1 on any failure.

    python tests/check_skill.py
"""

from __future__ import annotations

import json
import pathlib
import re
import shlex
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "vulnlookup"
sys.path.insert(0, str(SKILL / "scripts"))

problems: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        problems.append(msg)


def frontmatter(text: str) -> dict[str, str]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    check(m is not None, "SKILL.md has no YAML frontmatter block")
    out: dict[str, str] = {}
    if m:
        for line in m.group(1).splitlines():
            mm = re.match(r"^([a-z_]+):\s*(.*)$", line)
            if mm:
                out[mm.group(1)] = mm.group(2)
    return out


def main() -> int:
    text = (SKILL / "SKILL.md").read_text("utf-8")
    fm = frontmatter(text)
    check(fm.get("name") == "vulnlookup", "frontmatter name must be 'vulnlookup' (the folder name)")
    check(re.fullmatch(r"[a-z0-9-]{1,64}", fm.get("name", "")) is not None, "name must be lowercase letters, digits, hyphens")
    desc = fm.get("description", "")
    check(60 <= len(desc) <= 1024, f"description length {len(desc)} outside 60..1024")
    check("license" in fm, "frontmatter should carry a license")
    body = text.split("---\n", 2)[2]
    check(len(body.splitlines()) <= 500, f"SKILL.md body is {len(body.splitlines())} lines; keep it under 500")

    # every relative path mentioned in SKILL.md exists
    for p in set(re.findall(r"`((?:scripts|references|assets)/[A-Za-z0-9_./-]+)`", text)):
        check((SKILL / p).exists(), f"SKILL.md names {p} which does not exist")

    # every command in the tables parses with the real argument parser
    from vl import cli

    parser = cli.build_parser()
    for cmd in re.findall(r"`python \$S ([^`]+)`", text) + re.findall(r"^python \$S (.+)$", text, re.MULTILINE):
        for part in re.split(r"\s+·\s+", cmd):
            part = part.strip()
            if not part or part.startswith("--"):
                continue
            try:
                parser.parse_args(shlex.split(part.replace("…", "CVE-2000-0001")))
            except SystemExit:
                problems.append(f"SKILL.md command does not parse: {part!r}")

    # manifests agree
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text("utf-8"))
    codex = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text("utf-8"))
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text("utf-8"))
    from vl import __version__

    check(plugin["name"] == codex["name"] == market["plugins"][0]["name"] == "vulnlookup", "manifest names disagree")
    check(plugin["version"] == codex["version"] == __version__, "manifest versions disagree with vl.__version__")
    check(fm.get("metadata") is not None or "version: " in text.split("---\n", 2)[1], "frontmatter metadata.version missing")
    check(f"version: {__version__}" in text.split("---\n", 2)[1], "SKILL.md metadata.version differs from vl.__version__")

    # example inputs
    from vl import cpe as C

    for line in (SKILL / "assets" / "cpes.example.txt").read_text("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            check(C.parse_cpe(line) is not None, f"cpes.example.txt: not a CPE: {line}")
    for line in (SKILL / "assets" / "cves.example.txt").read_text("utf-8").splitlines():
        if line.strip():
            check(re.fullmatch(r"CVE-\d{4}-\d{4,}", line.strip()) is not None, f"cves.example.txt: not a CVE id: {line}")
    from vl import resolve as R

    for line in (SKILL / "assets" / "products.example.txt").read_text("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            check(R.resolve_alias(R.parse_product(line)) is not None, f"products.example.txt: {line!r} is not in the alias table")

    # references
    for f in ("aliases.json", "api-notes.md", "cpe-matching.md", "output-styles.md"):
        check((SKILL / "references" / f).exists(), f"references/{f} missing")
    json.loads((SKILL / "references" / "aliases.json").read_text("utf-8"))

    for p in problems:
        print("FAIL", p)
    print("skill check:", "ok" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
