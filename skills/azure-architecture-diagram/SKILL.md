---
name: azure-architecture-diagram
description: Create, update, and reproduce publication-grade Azure solution architecture diagrams for blueboard using Microsoft's official Azure Public Service Icons (V25), producing editable Draw.io (.drawio), vector SVG (.svg), and high-DPI PNG (.png) files embedded in the design and deployment docs. Use when infrastructure in infra/main.bicep changes or when asked to design or refresh an Azure architecture diagram with real Azure icons.
---

# Azure Architecture Diagram Skill

Produces and updates `docs/architecture/azure-architecture.{drawio,svg,png}` using **official, unmodified Microsoft Azure Public Service Icons (V25)**.

## One-command reproduction

```sh
./scripts/build-architecture-diagram.sh
```

What this script does automatically:
1. Downloads and caches Microsoft's official `Azure_Public_Service_Icons_V25.zip` (or uses `AZURE_ICONS_DIR=/path/to/Icons` if already extracted).
2. Runs `python3 -I scripts/build-architecture-diagram.py` to generate both:
   - `docs/architecture/azure-architecture.drawio` (editable Draw.io XML with embedded base64 SVGs)
   - `docs/architecture/azure-architecture.svg` (crisp vector SVG)
3. Renders a 2400 px PNG (`docs/architecture/azure-architecture.png`) via `rsvg-convert`.
4. Validates XML well-formedness, PNG header integrity, and zero double-escaped entities (`&amp;amp;`, `&amp;lt;`).

After regenerating the diagram, rebuild the documents that embed it:

```sh
python3 tools/docs/build-admin-docs.py && python3 tools/docs/verify-docs.py
```

Or run everything together with `./tools/docs/publish-all.sh`.

## Prerequisites

- `python3`, `curl`, `unzip`
- `rsvg-convert` (`brew install librsvg` on macOS; `sudo apt-get install librsvg2-bin` on Debian/Ubuntu)

## Microsoft icon terms (mandatory)

1. **Use official icons unmodified.** Never crop, flip, rotate, recolour, or distort any official Microsoft SVG icon (`aspect=fixed`, `preserveAspectRatio="xMidYMid meet"`).
2. **Label every icon with its full official service name** (e.g. *Azure Database for PostgreSQL Flexible Server*, *Azure Key Vault*, *Microsoft Sentinel*, *App Service Web App*).
3. **Never borrow an unrelated product's icon.** Services that have no official Azure architecture icon (Microsoft Graph, Microsoft Defender XDR, Microsoft Defender for Endpoint API) must be drawn as clean plain cards (`key=None`).
4. **Keep attribution in the footer note** (*"Official Azure architecture icons (c) Microsoft, used unmodified under the Azure architecture icon terms."*).

## Adding or editing Azure resources in the diagram

1. Verify the exact resource in `infra/main.bicep` (and `infra/network.bicep`, `infra/audit-export.bicep`, `templates/sentinel/`). Never invent resources that do not exist in code.
2. Look up the official icon path in [references/icon-catalog.md](references/icon-catalog.md) (or search `${AZURE_ICONS_CACHE}/Azure_Public_Service_Icons/Icons` with `find`).
3. Add the icon key to `ICONS` in `scripts/build-architecture-diagram.py` and place the card inside the right trust/network group.
4. Follow these layout hygiene rules to keep diagrams publication-grade:
   - **Pass plain text** (`&`, `<`, `>`) to `card()`, `group()`, `header()`, and `note_lines()` — `escape()` runs once internally so entities never double-escape. Only `<b>...</b>` is supported inline inside card lines.
   - **Never route arrows behind cards.** Use dedicated vertical/horizontal gutters (`x = 330..350` on the left, `x = 1240..1276` on the right, `y = 1262` on the bottom) with explicit orthogonal `points=[...]`.
   - **Keep badge pills off card titles.** If a card title is wide, set `badge_pos="bottom"`.
   - **Wrap footnotes explicitly** with `d.note_lines([...], x, y, w)` so no line overflows its container.
   - **Use numbered flow badges + legend** instead of long text on arrow lines:
     - Blue (`#0078D4`): browser/API/MCP auth & traffic
     - Deep sky (`#0369A1`): VNet / Private Endpoint / data tier
     - Teal (`#0F766E`): read-only ingest, lookups & KQL
     - Crimson (`#B91C1C`): policy-gated, human-approved containment writes
     - Purple (`#7C3AED`): audit export (`BlueboardAudit_CL`) & Sentinel Automation Rule sync
     - Slate (`#0F172A`): agent LLM plane (Microsoft Foundry)

## Verification checklist (required before finishing)

1. Run `./scripts/build-architecture-diagram.sh` and confirm exit code 0.
2. **Visually inspect** `docs/architecture/azure-architecture.png` (open/read the image) and check every quadrant for:
   - zero literal `&amp;` / `&lt;` / `&gt;` text
   - zero overlapping arrows, badges or labels
   - zero clipped or overflowing footnotes
   - every icon crisp and undistorted
3. Run `python3 tools/docs/build-admin-docs.py && python3 tools/docs/verify-docs.py` to confirm the updated diagram is embedded in both `Blueboard-Solution-Design.{pdf,docx}` and `Blueboard-Deployment-Guide.{pdf,docx}`.
