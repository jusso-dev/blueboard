#!/usr/bin/env python3
"""Verifies blueboard's published documentation suite and Azure architecture diagram.

Checks:
  1. Architecture diagram files (.drawio, .svg, .png) exist, parse cleanly and have no double-escaped XML entities.
  2. All expected PDF and editable Word (.docx) deliverables exist and pass format/ZIP/XML validation.
  3. Documents with screenshots or architecture diagrams embed their images in word/media/.
  4. Zero leftover docs/design/.build-*.html build artefacts.
  5. Zero broken relative Markdown links or image paths across README.md and docs/{guides,admin,security,design}.

Usage: python3 tools/docs/verify-docs.py [--combined-only]
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(REPO)

CORE_PACKS = [
    "Blueboard-Walkthrough-Guides",
    "Blueboard-Deployment-Guide",
    "Blueboard-Admin-SOPs",
    "Blueboard-Developer-Guide",
    "Blueboard-Security-Controls",
    "Blueboard-Solution-Design",
]

EXPECTED_MIN_IMAGES = {
    "Blueboard-Walkthrough-Guides.docx": 6,
    "Blueboard-Deployment-Guide.docx": 1,
    "Blueboard-Solution-Design.docx": 1,
}


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def check_architecture() -> None:
    drawio = "docs/architecture/azure-architecture.drawio"
    svg = "docs/architecture/azure-architecture.svg"
    png = "docs/architecture/azure-architecture.png"
    for path in (drawio, svg, png):
        if not os.path.exists(path):
            fail(f"missing architecture diagram file: {path}")
    for path in (drawio, svg):
        raw = open(path, encoding="utf-8").read()
        try:
            ET.fromstring(raw)
        except ET.ParseError as exc:
            fail(f"invalid XML in {path}: {exc}")
        if path == svg and ("&amp;amp;" in raw or "&amp;lt;" in raw or "&amp;gt;" in raw):
            fail(f"double-escaped XML entity in {path}")
    with open(png, "rb") as fh:
        if fh.read(8) != b"\x89PNG\r\n\x1a\n":
            fail(f"invalid PNG signature in {png}")
    if os.path.getsize(png) < 50_000:
        fail(f"architecture PNG unexpectedly small: {png}")


def check_deliverables(combined_only: bool) -> tuple[int, int]:
    guide_chapters = sorted(
        f for f in os.listdir("docs/guides") if re.match(r"^\d\d-.*\.md$", f)
    )
    pdfs = sorted(glob.glob("docs/Blueboard-*.pdf"))
    docxs = sorted(glob.glob("docs/Blueboard-*.docx"))

    expected_count = len(CORE_PACKS) if combined_only else len(CORE_PACKS) + len(guide_chapters)
    for pack in CORE_PACKS:
        for ext in (".pdf", ".docx"):
            path = f"docs/{pack}{ext}"
            if not os.path.exists(path):
                fail(f"missing core deliverable: {path}")

    if not combined_only:
        if len(pdfs) < expected_count or len(docxs) < expected_count:
            fail(f"expected at least {expected_count} PDFs and DOCXs, found {len(pdfs)} PDFs / {len(docxs)} DOCXs")

    for pdf in pdfs:
        if os.path.getsize(pdf) < 10_000:
            fail(f"PDF unexpectedly small: {pdf}")
        with open(pdf, "rb") as fh:
            if fh.read(5) != b"%PDF-":
                fail(f"invalid PDF header: {pdf}")

    for docx in docxs:
        if os.path.getsize(docx) < 5_000:
            fail(f"DOCX unexpectedly small: {docx}")
        try:
            with zipfile.ZipFile(docx) as zf:
                bad = zf.testzip()
                if bad is not None:
                    fail(f"corrupt ZIP member '{bad}' in {docx}")
                ET.fromstring(zf.read("word/document.xml"))
                media = [n for n in zf.namelist() if n.startswith("word/media/")]
                base = os.path.basename(docx)
                if base in EXPECTED_MIN_IMAGES and len(media) < EXPECTED_MIN_IMAGES[base]:
                    fail(
                        f"{docx} embeds {len(media)} image(s), expected at least {EXPECTED_MIN_IMAGES[base]}"
                    )
        except (zipfile.BadZipFile, KeyError, ET.ParseError) as exc:
            fail(f"invalid DOCX {docx}: {exc}")

    leftovers = glob.glob("docs/design/.build-*.html")
    if leftovers:
        fail(f"leftover temporary build HTML files: {leftovers}")

    return len(pdfs), len(docxs)


def check_markdown_links() -> int:
    md_files = (
        ["README.md"]
        + sorted(glob.glob("docs/guides/*.md"))
        + sorted(glob.glob("docs/admin/*.md"))
        + sorted(glob.glob("docs/security/*.md"))
        + sorted(glob.glob("docs/design/*.md"))
        + sorted(glob.glob("skills/*/SKILL.md"))
        + sorted(glob.glob("skills/*/references/*.md"))
    )
    broken = []
    for mf in md_files:
        base = os.path.dirname(os.path.abspath(mf))
        in_fence = False
        with open(mf, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if line.lstrip().startswith("```"):
                    in_fence = not in_fence
                if in_fence:
                    continue
                for match in re.finditer(r"!?\[[^\]]*\]\(([^)#\s]+)", line):
                    target = match.group(1)
                    if target.startswith(("http://", "https://", "mailto:")):
                        continue
                    resolved = os.path.normpath(os.path.join(base, target))
                    if not os.path.exists(resolved):
                        broken.append((mf, lineno, target))
    if broken:
        details = "\n".join(f"  {mf}:{ln} -> {t}" for mf, ln, t in broken)
        fail(f"broken relative Markdown links:\n{details}")
    return len(md_files)


def main() -> None:
    args = set(sys.argv[1:])
    unknown = args - {"--combined-only"}
    if unknown:
        sys.exit(f"unknown option: {' '.join(sorted(unknown))}")
    combined_only = "--combined-only" in args

    check_architecture()
    n_pdf, n_docx = check_deliverables(combined_only)
    n_md = check_markdown_links()
    print(f"OK: architecture diagram + {n_pdf} PDFs + {n_docx} DOCXs + {n_md} Markdown files verified (0 errors).")


if __name__ == "__main__":
    main()
