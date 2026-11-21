#!/usr/bin/env python3
"""Builds the blueboard administrator, security and design documents as editable Word and PDF.

Markdown sources in docs/admin/ stay readable directly on GitHub (hand-numbered headings, contents list and
document control table). This script prepares each file for tools/docs/build-doc.sh so the PDF and Word editions
have matching covers, document control, numbered sections and tables of contents.

Usage: python3 tools/docs/build-admin-docs.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.path.join(REPO, "tools", "docs", "build-doc.sh")

ADMIN_DOCS = [
    ("deployment-guide.md", "Blueboard-Deployment-Guide", "Deployment Guide",
     "Deploy, configure, upgrade, verify and tear down blueboard on Azure"),
    ("admin-sops.md", "Blueboard-Admin-SOPs", "Administrator SOPs",
     "Standard operating procedures for blueboard SOC platform administrators"),
    ("developer-guide.md", "Blueboard-Developer-Guide", "Developer Guide",
     "Build, test, extend and release blueboard"),
]

PACK_DOCS = [
    ("docs/security", "Blueboard-Security-Controls"),
    ("docs/design", "Blueboard-Solution-Design"),
]


def control_table(lines):
    rows, inside = [], False
    for line in lines:
        if line.startswith("## Document control"):
            inside = True
            continue
        if inside and line.startswith("## "):
            break
        if inside and line.startswith("|") and not line.startswith("|---") and "Item" not in line:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 2:
                rows.append((cells[0], cells[1]))
    return rows


def convert(text):
    lines = text.splitlines()
    title = lines[0].lstrip("# ").strip()
    rows = control_table(lines)
    body, skip = [], False
    for line in lines[1:]:
        if line.startswith("## Document control") or line.startswith("## Contents"):
            skip = True
            continue
        if skip and line.startswith("## "):
            skip = False
        if skip:
            continue
        body.append(line)

    out, fenced = [], False
    for line in body:
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if not fenced:
            m = re.match(r"^(#{2,6})\s+(?:\d+(?:\.\d+)*\.?\s+)?(.*)$", line)
            if m:
                line = "#" * (len(m.group(1)) - 1) + " " + m.group(2)
            line = re.sub(r"(?<!!)\[([^\]]+)\]\((?!https?://)(?!#)[^)]*\)", r"\1", line)
            line = re.sub(r"(?<!!)\[([^\]]+)\]\(#[^)]*\)", r"\1", line)
        out.append(line)

    first = next((i for i, l in enumerate(out) if l.startswith("# ")), len(out))
    intro = "\n".join(out[:first]).strip()
    rest = "\n".join(out[first:])
    md = (f"# About this document {{.unnumbered}}\n\n{intro}\n\n" if intro else "") + rest + "\n"
    return title, rows, md


def metadata(title, kicker, note, rows):
    version = next((v for k, v in rows if k == "Version"), "2.0")
    date = next((v for k, v in rows if k == "Date"), "21-11-2026")
    table = "\n".join(f"  | {k} | {v} |" for k, v in rows)
    return f'''title: "{title}"
running-title: "{title}"
kicker: "{kicker}"
subtitle: "Collaborative Blue-Team SOC Board"
note: "{note}"
version: "{version}"
date: "{date}"
status: "Published"
lang: en-AU
toc-title: Contents
control: |
  ## Document control

  | Item | Value |
  |---|---|
{table}
  | Source | `docs/admin/` in the `blueboard` repository; rebuilt with `python3 tools/docs/build-admin-docs.py` |

  Commands, routes, MCP tools and expected outputs reflect the repository at this version.
'''


def run_build(folder, output_name):
    result = subprocess.run([BUILD, folder, output_name], cwd=REPO, capture_output=True, text=True)
    noise = [l for l in result.stderr.splitlines() if "word-break" not in l and l.strip()]
    if result.returncode != 0:
        sys.stderr.write("\n".join(noise) + "\n")
        sys.exit(result.returncode)
    print(result.stdout.strip())


def main():
    for source, name, kicker, note in ADMIN_DOCS:
        with open(os.path.join(REPO, "docs", "admin", source), encoding="utf-8") as f:
            title, rows, md = convert(f.read())
        work = tempfile.mkdtemp(prefix="blueboard-admin-")
        try:
            with open(os.path.join(work, "01-body.md"), "w", encoding="utf-8") as f:
                f.write(md)
            with open(os.path.join(work, "metadata.yaml"), "w", encoding="utf-8") as f:
                f.write(metadata(title, kicker, note, rows))
            run_build(work, name)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    for folder, name in PACK_DOCS:
        run_build(os.path.join(REPO, folder), name)


if __name__ == "__main__":
    main()
