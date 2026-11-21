# blueboard Documentation Map

| Source path | Builder | Published deliverables (`docs/`) |
|---|---|---|
| `docs/guides/00-overview.md` … `11-*.md` | `python3 tools/docs/build-guides.py` | `Blueboard-Walkthrough-Guides.{pdf,docx}` + standalone `Blueboard-Walkthrough-00-*` … `11-*.{pdf,docx}` |
| `docs/admin/deployment-guide.md` | `python3 tools/docs/build-admin-docs.py` | `Blueboard-Deployment-Guide.{pdf,docx}` |
| `docs/admin/admin-sops.md` | `python3 tools/docs/build-admin-docs.py` | `Blueboard-Admin-SOPs.{pdf,docx}` |
| `docs/admin/developer-guide.md` | `python3 tools/docs/build-admin-docs.py` | `Blueboard-Developer-Guide.{pdf,docx}` |
| `docs/security/` (`metadata.yaml` + `01-security.md`) | `python3 tools/docs/build-admin-docs.py` | `Blueboard-Security-Controls.{pdf,docx}` |
| `docs/design/` (`metadata.yaml` + `01-solution-design.md`) | `python3 tools/docs/build-admin-docs.py` | `Blueboard-Solution-Design.{pdf,docx}` |
| `scripts/build-architecture-diagram.py` | `./scripts/build-architecture-diagram.sh` | `docs/architecture/azure-architecture.{drawio,svg,png}` |

## Shared print & Word styling (`docs/design/`)

- `template.html`: HTML5 cover, document control, TOC and running headers/footers for WeasyPrint
- `style.css`: A4 portrait, 18 mm margins, blueboard cobalt (`#2563EB`) and slate (`#0F172A`) palette
- `docx.lua`: Pandoc Lua filter building the Word cover block, page breaks, callouts and table widths
- `make_reference_docx.py`: Python 3 stdlib generator producing styled `reference.docx` (no `python-docx` dependency)
