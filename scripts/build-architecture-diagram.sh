#!/usr/bin/env bash
# Reproduces docs/architecture/azure-architecture.{drawio,svg,png} using Microsoft's
# official Azure Public Service Icons (V25).
#
# Usage:
#   ./scripts/build-architecture-diagram.sh
#   AZURE_ICONS_DIR=/path/to/Icons ./scripts/build-architecture-diagram.sh
#   PNG_WIDTH=3000 ./scripts/build-architecture-diagram.sh
#
# Environment variables:
#   AZURE_ICONS_URL    Official icon pack ZIP URL (default: Microsoft V25)
#   AZURE_ICONS_CACHE  Local cache folder for downloaded icons (default: /tmp/blueboard-azure-icons-v25)
#   AZURE_ICONS_DIR    Use an already-extracted Icons/ folder (skips download)
#   PNG_WIDTH          Output PNG width in pixels (default: 2400)
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

AZURE_ICONS_URL="${AZURE_ICONS_URL:-https://arch-center.azureedge.net/icons/Azure_Public_Service_Icons_V25.zip}"
AZURE_ICONS_CACHE="${AZURE_ICONS_CACHE:-${TMPDIR:-/tmp}/blueboard-azure-icons-v25}"
PNG_WIDTH="${PNG_WIDTH:-2400}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: '$1' is required. $2" >&2
    exit 1
  fi
}

need python3 "Install Python 3."
need rsvg-convert "Install librsvg (macOS: brew install librsvg; Debian/Ubuntu: sudo apt-get install librsvg2-bin)."

icon_dir="${AZURE_ICONS_DIR:-}"
if [[ -z "$icon_dir" ]]; then
  icon_dir="$AZURE_ICONS_CACHE/Azure_Public_Service_Icons/Icons"
  if [[ ! -d "$icon_dir" ]]; then
    need curl "Install curl, or pass AZURE_ICONS_DIR=/path/to/Icons."
    need unzip "Install unzip, or pass AZURE_ICONS_DIR=/path/to/Icons."
    mkdir -p "$AZURE_ICONS_CACHE"
    zip_file="$AZURE_ICONS_CACHE/icons.zip"
    echo "Downloading official Microsoft Azure Public Service Icons..."
    curl -fsSL -o "$zip_file" "$AZURE_ICONS_URL"
    unzip -qo "$zip_file" -d "$AZURE_ICONS_CACHE"
    rm -f "$zip_file"
  fi
fi

if [[ ! -d "$icon_dir" ]]; then
  echo "error: icon directory not found: $icon_dir" >&2
  exit 1
fi

out_drawio="docs/architecture/azure-architecture.drawio"
out_svg="docs/architecture/azure-architecture.svg"
out_png="docs/architecture/azure-architecture.png"

python3 -I scripts/build-architecture-diagram.py "$icon_dir" "$out_drawio" "$out_svg"
rsvg-convert -w "$PNG_WIDTH" -o "$out_png" "$out_svg"

# Sanity checks: well-formed XML, valid PNG signature, and zero double-escaped entities in SVG.
python3 - "$out_drawio" "$out_svg" "$out_png" <<'PY'
import sys, xml.etree.ElementTree as ET

drawio_path, svg_path, png_path = sys.argv[1:4]
for path in (drawio_path, svg_path):
    ET.fromstring(open(path, encoding="utf-8").read())

svg_raw = open(svg_path, encoding="utf-8").read()
if "&amp;amp;" in svg_raw or "&amp;lt;" in svg_raw or "&amp;gt;" in svg_raw:
    sys.exit(f"error: double-escaped XML entity detected in {svg_path}")

with open(png_path, "rb") as f:
    sig = f.read(8)
if sig != b"\x89PNG\r\n\x1a\n":
    sys.exit(f"error: invalid PNG header in {png_path}")
PY

echo "Wrote $out_drawio, $out_svg and $out_png (${PNG_WIDTH}px wide)."
