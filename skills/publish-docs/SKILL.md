---
name: publish-docs
description: Author, update, build, and verify blueboard's publication-grade documentation suite (numbered SOC walkthrough chapters 00–11, Deployment Guide, Administrator SOPs, Developer Guide, Security Controls, and Solution Design Document) as both GitHub Markdown and print-ready PDF plus editable Word (.docx) deliverables. Use when adding features, actions, MCP tools, playbooks, SOPs, or security controls, or when asked to rebuild or verify docs.
---

# Documentation Publishing Skill

Maintains and reproduces **blueboard**'s complete documentation suite — 18 PDFs, 18 editable Word (`.docx`) files, and their Markdown sources — using Pandoc 3, WeasyPrint, and Python 3 standard library (no third-party Python packages required).

## One-command reproduction

```sh
# Rebuild Azure architecture diagram + every PDF & Word deliverable + run full verifier
./tools/docs/publish-all.sh

# Rebuild PDFs & Word deliverables only (offline / no diagram change)
./tools/docs/publish-all.sh --skip-diagram

# Fast edit loop: combined Walkthrough handbook + admin/security/design packs + verify
./tools/docs/publish-all.sh --skip-diagram --combined-only

# Verify existing outputs and links without rebuilding
./tools/docs/publish-all.sh --check-only
```

## Prerequisites

- `pandoc` 3+ (`brew install pandoc`)
- `weasyprint` (`brew install weasyprint`)
- `python3` (stdlib only — `docs/design/make_reference_docx.py` builds the Word reference template with `zipfile` + `xml`)
- `rsvg-convert` (`brew install librsvg`) if rebuilding the Azure architecture diagram

## Document families and authoring rules

See [references/doc-structure.md](references/doc-structure.md) for the full folder-to-output map. Follow these strict rules so both GitHub Markdown and PDF/Word outputs render cleanly:

1. **Australian English (`en-AU`)** throughout (e.g. *organisation*, *authorise*, *centre*, *behaviour*, *catalogue*, *customise*).
2. **Exact source fidelity.** Every route, MCP tool name, action `kind`, Entra role, error message, KQL table, environment variable, file path and test name must match the actual codebase — never invent endpoints or permissions.
3. **Fictitious examples only.** Use RFC 2606 / RFC 5737 placeholders (`contoso.com`, `*.example`, `198.51.100.x`, `203.0.113.x`, `192.0.2.x`). Never include real tenant IDs, customer domains, or secrets.
4. **Image paths resolve from `docs/design/`.** Reference screenshots and diagrams as `../screenshots/<name>.png` or `../architecture/azure-architecture.png` from any chapter in `docs/guides/`, `docs/admin/`, `docs/security/`, or `docs/design/` — this works simultaneously on GitHub, WeasyPrint (`--base-url docs/design/`), and Pandoc DOCX.
5. **Walkthrough chapters (`docs/guides/NN-<slug>.md`)**:
   - First line `# <Title>` (no manual numbering; Pandoc numbers chapters automatically).
   - Standard sections: *Who this is for*, *Before you start*, *Steps* (numbered), *What blueboard checks* (table), *What is recorded in `audit_log`*, *Troubleshooting* (table), *Related guides*.
   - Update `docs/guides/00-overview.md` if you add or rename a chapter.
6. **Admin guides (`docs/admin/*.md`)**:
   - **Place the introductory paragraph directly beneath `# <Title>`, BEFORE `## Document control`.** `tools/docs/build-admin-docs.py` strips `## Document control` and `## Contents` when generating PDF/DOCX (moving Document Control to the cover/front-matter and letting Pandoc build the TOC); anything placed between `## Contents` and `## 1.` will be skipped in print!
   - Keep `## Document control` table (`Version`, `Date`, `Status`, `Owner`, `Audience`, `Related`), `## Contents`, and hand-numbered `## 1. ...` sections so GitHub Markdown stays directly readable.
7. **Pack documents (`docs/security/`, `docs/design/`)**:
   - Put cover/control metadata in `metadata.yaml` and unnumbered `# Section` headings in `01-*.md` (built directly by `tools/docs/build-doc.sh --number-sections`).

## Updating version or date

When cutting a new documentation release:
1. Update `VERSION` and `DATE` in `tools/docs/build-guides.py`.
2. Update `Version` and `Date` in `docs/admin/*.md` (`## Document control`), `docs/security/metadata.yaml`, and `docs/design/metadata.yaml`.
3. Run `./tools/docs/publish-all.sh` and confirm `OK: architecture diagram + ... verified (0 errors).`

## Verification checks (`tools/docs/verify-docs.py`)

`verify-docs.py` fails the build if any of the following regress:
- Missing or malformed `.drawio` / `.svg` / `.png` architecture files or double-escaped XML entities.
- Missing or truncated PDF/DOCX deliverables, invalid `%PDF-` header, corrupt DOCX ZIP, or invalid `word/document.xml`.
- Missing embedded screenshots or architecture diagrams in `word/media/` (`Blueboard-Walkthrough-Guides.docx`, `Blueboard-Deployment-Guide.docx`, `Blueboard-Solution-Design.docx`).
- Leftover `docs/design/.build-*.html` temporary files.
- Any broken relative Markdown link or image path in `README.md`, `docs/{guides,admin,security,design}/*.md`, or `skills/*/SKILL.md`.
