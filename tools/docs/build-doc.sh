#!/usr/bin/env bash
# Builds a blueboard document (PDF and editable Word) from a folder of numbered Markdown files plus metadata.yaml,
# using the shared styles in docs/design (template.html, style.css, docx.lua, make_reference_docx.py).
# Usage: tools/docs/build-doc.sh <source-folder> <output-name>   e.g. docs/security Blueboard-Security-Controls
# Writes docs/<output-name>.pdf and docs/<output-name>.docx. Needs pandoc 3, Python 3 and WeasyPrint.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
src="$(cd "$1" && pwd)"
name="$2"
design="$repo/docs/design"
pdf="$repo/docs/$name.pdf"
docx="$repo/docs/$name.docx"
meta="$src/metadata.yaml"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1795132800}"

command -v pandoc >/dev/null || { echo "pandoc is required." >&2; exit 1; }
command -v weasyprint >/dev/null || { echo "WeasyPrint is required." >&2; exit 1; }
sources=("$src"/[0-9][0-9]-*.md)
value() { sed -n "s/^$1: *\"\{0,1\}\([^\"]*\)\"\{0,1\} *$/\1/p" "$meta" | head -1; }

html="$design/.build-$name.html"
pandoc "${sources[@]}" \
  --from markdown+pipe_tables+raw_html+fenced_divs+bracketed_spans \
  --to html5 --standalone \
  --template "$design/template.html" \
  --metadata-file "$meta" \
  --number-sections --columns=10000 --toc --toc-depth 2 --section-divs=false --syntax-highlighting=none \
  --resource-path "$src:$design" \
  --output "$html"
weasyprint --base-url "$design/" "$html" "$pdf"
rm -f "$html"
echo "Wrote $pdf"

reference="$(mktemp -d)/reference.docx"
BLUEBOARD_REFERENCE_OUT="$reference" \
BLUEBOARD_DOC_TITLE="$(value running-title)" \
BLUEBOARD_DOC_VERSION="$(value version)" \
BLUEBOARD_DOC_DATE="$(value date)" \
  python3 "$design/make_reference_docx.py" >/dev/null
(cd "$design" && pandoc "${sources[@]}" \
  --from markdown+pipe_tables+fenced_divs+bracketed_spans \
  --to docx \
  --reference-doc "$reference" \
  --metadata-file "$meta" \
  --lua-filter "$design/docx.lua" \
  --number-sections \
  --resource-path "$design:$src" \
  --output "$docx")
rm -rf "$(dirname "$reference")"
echo "Wrote $docx"
