#!/usr/bin/env python3
"""Builds the blueboard user walkthrough guides as editable Word and PDF.

Sources are the numbered Markdown files in docs/guides/ (00-overview.md through 12-*.md).
Writes, through tools/docs/build-doc.sh:
  docs/Blueboard-Walkthrough-Guides.docx and .pdf         combined handbook (all chapters)
  docs/Blueboard-Walkthrough-NN-<Name>.docx and .pdf      one standalone document per journey

Usage: python3 tools/docs/build-guides.py [--combined-only]
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.path.join(REPO, "tools", "docs", "build-doc.sh")
GUIDES = os.path.join(REPO, "docs", "guides")
VERSION = "2.1"
DATE = "25-11-2026"


def sources():
    files = sorted(f for f in os.listdir(GUIDES) if re.match(r"^\d\d-.*\.md$", f))
    out = []
    for f in files:
        with open(os.path.join(GUIDES, f), encoding="utf-8") as fh:
            text = fh.read()
        title = text.splitlines()[0].lstrip("# ").strip()
        out.append((f, title, text))
    return out


def clean_for_print(text):
    """Strip repo-relative Markdown links that do not resolve in Word/PDF, keeping their link text."""
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if not fenced:
            # Keep image links ![...](...) and external http(s) links intact; turn relative file links into plain text.
            line = re.sub(r"(?<!!)\[([^\]]+)\]\((?!https?://)(?!#)[^)]*\)", r"\1", line)
            line = re.sub(r"(?<!!)\[([^\]]+)\]\(#[^)]*\)", r"\1", line)
        out.append(line)
    return "\n".join(out) + "\n"


def file_name(number, title):
    words = re.sub(r"[^A-Za-z0-9 ]+", " ", title).split()
    return f"Blueboard-Walkthrough-{number}-" + "-".join(w[:1].upper() + w[1:] for w in words[:6])


def metadata(title, running, note, chapters):
    rows = "\n".join(f"  | {n} | {t} |" for n, t in chapters)
    return f'''title: "{title}"
running-title: "{running}"
kicker: "User Walkthrough"
subtitle: "Collaborative Blue-Team SOC Board"
note: "{note}"
version: "{VERSION}"
date: "{DATE}"
status: "Published"
lang: en-AU
toc-title: Contents
control: |
  ## Document control

  | Item | Value |
  |---|---|
  | Document | {title} |
  | Version | {VERSION} |
  | Date | {DATE} |
  | Status | Published |
  | Owner | blueboard SOC platform team |
  | Source | `docs/guides/` in the `blueboard` repository; rebuilt with `python3 tools/docs/build-guides.py` |
  | Related | Deployment Guide; Administrator SOPs; Developer Guide; Security Controls; Solution Design Document |

  ## Contents of this edition

  | Chapter | Walkthrough |
  |---|---|
{rows}

  Page, role, MCP tool, action and error text is taken from the blueboard source at this version. Example users, devices, domains and incidents (such as `contoso.com`, `198.51.100.88`, `203.0.113.45`) are fictitious.
'''


def build(name, title, running, note, files):
    work = tempfile.mkdtemp(prefix="blueboard-guides-")
    try:
        chapters = []
        for i, (src, chapter_title, text) in enumerate(files, start=1):
            with open(os.path.join(work, f"{i:02d}-{src[3:]}"), "w", encoding="utf-8") as fh:
                fh.write(clean_for_print(text))
            chapters.append((str(i), chapter_title))
        with open(os.path.join(work, "metadata.yaml"), "w", encoding="utf-8") as fh:
            fh.write(metadata(title, running, note, chapters))
        result = subprocess.run([BUILD, work, name], cwd=REPO, capture_output=True, text=True)
        noise = [l for l in result.stderr.splitlines() if "word-break" not in l and l.strip()]
        if result.returncode != 0:
            sys.stderr.write("\n".join(noise) + "\n")
            sys.exit(result.returncode)
        print(result.stdout.strip())
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    args = set(sys.argv[1:])
    unknown = args - {"--combined-only"}
    if unknown:
        sys.exit(f"unknown option {' '.join(sorted(unknown))}")

    files = sources()
    build("Blueboard-Walkthrough-Guides",
          "blueboard: End-to-End SOC User Walkthroughs",
          "blueboard User Walkthroughs",
          "End-to-end guides for every Microsoft Defender XDR, Microsoft Sentinel and multi-agent SOC journey",
          files)
    if "--combined-only" in args:
        return

    for src, title, text in files:
        number = src[:2]
        build(file_name(number, title),
              f"blueboard walkthrough: {title}",
              f"blueboard walkthrough: {title}",
              "One blueboard SOC journey, end to end",
              [(src, title, text)])


if __name__ == "__main__":
    main()
