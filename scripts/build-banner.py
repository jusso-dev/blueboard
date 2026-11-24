#!/usr/bin/env python3
"""
Generates blueboard's README & Docs hero banner in the Cobalt dark-console palette
(web/design.md), rendering both SVG and a high-DPI PNG via rsvg-convert.

Usage:
    python3 scripts/build-banner.py
"""
from html import escape
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parent.parent
OUT_SVG = REPO / "docs" / "images" / "blueboard-banner.svg"
OUT_PNG = REPO / "docs" / "images" / "blueboard-banner.png"

W, H = 1280, 452
SANS = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "'JetBrains Mono', 'SF Mono', Menlo, Monaco, Consolas, monospace"

# Cobalt dark-console palette aligned with web/design.md & web/src/styles.css
BG = "#0F131A"
CARD = "#161B26"
CARD_INNER = "#1C2331"
RULE = "#283347"
RULE_BLUE = "#355389"
RULE_AMBER = "#6B4E24"
INK = "#EDF2FA"
INK_2 = "#C3CEE0"
MUTED = "#8A97AD"
COBALT = "#5B95FF"
COBALT_SOFT = "#1A2B4B"
GREEN = "#45D483"
GREEN_SOFT = "#143025"
AMBER = "#F2B34B"
AMBER_SOFT = "#332613"
PURPLE = "#9C84FF"
PURPLE_SOFT = "#251E40"


def card_row(x: float, y: float, w: float, title: str, subtitle: str, tag: str, tag_col: str, tag_bg: str) -> str:
    tw = max(48, len(tag) * 6.2 + 14)
    tx = x + w - tw - 10
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="48" rx="6" fill="{CARD_INNER}" stroke="{RULE}" stroke-width="1"/>'
        f'<text x="{x + 12}" y="{y + 20}" font-family="{SANS}" font-size="12.2" font-weight="600" fill="{INK}">{escape(title)}</text>'
        f'<text x="{x + 12}" y="{y + 37}" font-family="{MONO}" font-size="9.8" fill="{MUTED}">{escape(subtitle)}</text>'
        f'<rect x="{tx}" y="{y + 6}" width="{tw}" height="18" rx="9" fill="{tag_bg}"/>'
        f'<text x="{tx + tw/2}" y="{y + 18.2}" text-anchor="middle" font-family="{MONO}" font-size="8.8" font-weight="600" fill="{tag_col}">{escape(tag)}</text>'
    )


def build_svg() -> str:
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        "<defs>",
        f'<linearGradient id="bgGrad" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0%" stop-color="#0D1117"/><stop offset="55%" stop-color="{BG}"/><stop offset="100%" stop-color="#111827"/>'
        "</linearGradient>",
        f'<radialGradient id="glow" cx="50%" cy="18%" r="58%">'
        f'<stop offset="0%" stop-color="#4D8DFF" stop-opacity="0.16"/><stop offset="100%" stop-color="{BG}" stop-opacity="0"/>'
        "</radialGradient>",
        '<marker id="arrBlue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto">'
        f'<path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="{COBALT}"/></marker>',
        '<marker id="arrAmber" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto">'
        f'<path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="{AMBER}"/></marker>',
        "</defs>",
        f'<rect x="0" y="0" width="{W}" height="{H}" rx="12" fill="url(#bgGrad)"/>',
        f'<rect x="0" y="0" width="{W}" height="{H}" rx="12" fill="url(#glow)"/>',
        # Subtle console grid hairlines
        f'<line x1="0" y1="112" x2="{W}" y2="112" stroke="{RULE}" stroke-width="1"/>',
        f'<line x1="0" y1="414" x2="{W}" y2="414" stroke="{RULE}" stroke-width="1"/>',
    ]

    # Top emblem + wordmark
    parts.extend([
        f'<rect x="44" y="28" width="42" height="42" rx="9" fill="{COBALT_SOFT}" stroke="{COBALT}" stroke-width="1.5"/>',
        f'<path d="M 65 37 L 77 42.5 V 50.5 C 77 57.2 71.8 62.6 65 65 C 58.2 62.6 53 57.2 53 50.5 V 42.5 Z" fill="none" stroke="{COBALT}" stroke-width="1.8"/>',
        f'<circle cx="65" cy="49" r="3" fill="{COBALT}"/>',
        f'<line x1="65" y1="52" x2="65" y2="57" stroke="{COBALT}" stroke-width="1.8" stroke-linecap="round"/>',
        f'<text x="102" y="59" font-family="{SANS}" font-size="31" font-weight="700" letter-spacing="-0.6" fill="{INK}">blueboard</text>',
        f'<rect x="272" y="38" width="212" height="22" rx="11" fill="{COBALT_SOFT}" stroke="{RULE_BLUE}" stroke-width="1"/>',
        f'<text x="378" y="52.5" text-anchor="middle" font-family="{MONO}" font-size="10.5" font-weight="600" fill="{COBALT}">MICROSOFT SOC CONTROL PLANE</text>',
        # Right top badges
        f'<rect x="822" y="37" width="414" height="24" rx="12" fill="{CARD}" stroke="{RULE}" stroke-width="1"/>',
        f'<text x="1029" y="53" text-anchor="middle" font-family="{MONO}" font-size="10.5" fill="{INK_2}">31 MCP Tools · 21 Brokered Actions · 10 Playbooks · Entra ID</text>',
        # Subtitle
        f'<text x="44" y="96" font-family="{SANS}" font-size="15.2" fill="{INK_2}">'
        'The human-gated shared workspace where SOC analysts and AI agents investigate Microsoft Defender, Sentinel &amp; Purview incidents together.</text>',
    ])

    # Column geometry
    cw, ch, cy = 368, 266, 130
    c1x, c2x, c3x = 44, 456, 868

    # Column 1: Signals & Hunting
    parts.extend([
        f'<rect x="{c1x}" y="{cy}" width="{cw}" height="{ch}" rx="10" fill="{CARD}" stroke="{RULE}" stroke-width="1.2"/>',
        f'<circle cx="{c1x + 20}" cy="{cy + 24}" r="4.5" fill="{GREEN}"/>',
        f'<text x="{c1x + 32}" y="{cy + 28}" font-family="{MONO}" font-size="11.2" font-weight="700" fill="{GREEN}">1 · READ-ONLY SIGNALS &amp; HUNTING</text>',
        card_row(c1x + 14, cy + 44, cw - 28, "Microsoft Defender XDR", "Unified incidents · MDE · MDO · KQL", "INGEST", GREEN, GREEN_SOFT),
        card_row(c1x + 14, cy + 98, cw - 28, "Microsoft Sentinel MCP & Graph", "mcp/triage · mcp/graph · Log Analytics", "MCP + KQL", PURPLE, PURPLE_SOFT),
        card_row(c1x + 14, cy + 152, cw - 28, "Microsoft Purview", "DLP · Insider Risk · Sensitivity Labels", "PURVIEW", COBALT, COBALT_SOFT),
        f'<text x="{c1x + 18}" y="{cy + 236}" font-family="{SANS}" font-size="11.5" fill="{MUTED}">Managed Identity queries Microsoft APIs.</text>',
        f'<text x="{c1x + 18}" y="{cy + 252}" font-family="{MONO}" font-size="10.2" fill="{GREEN}">Agents hold zero Microsoft security credentials.</text>',
    ])

    # Column 2: blueboard Workspace
    parts.extend([
        f'<rect x="{c2x}" y="{cy}" width="{cw}" height="{ch}" rx="10" fill="{CARD}" stroke="{RULE_BLUE}" stroke-width="1.5"/>',
        f'<circle cx="{c2x + 20}" cy="{cy + 24}" r="4.5" fill="{COBALT}"/>',
        f'<text x="{c2x + 32}" y="{cy + 28}" font-family="{MONO}" font-size="11.2" font-weight="700" fill="{COBALT}">2 · SHARED INVESTIGATION BOARD</text>',
        card_row(c2x + 14, cy + 44, cw - 28, "Typed Incident Thread", "finding · ioc · verdict · question · status", "#INCIDENTS", COBALT, COBALT_SOFT),
        card_row(c2x + 14, cy + 98, cw - 28, "Atomic Task Claim Leases", "claim_message stops duplicate work", "LEASED", GREEN, GREEN_SOFT),
        card_row(c2x + 14, cy + 152, cw - 28, "Roll-Up & Data Guards", "Evidence grounding · Secret & Purview guard", "VERIFIED", PURPLE, PURPLE_SOFT),
        f'<text x="{c2x + 18}" y="{cy + 236}" font-family="{SANS}" font-size="11.5" fill="{MUTED}">Claude, Copilot, Python &amp; TS agents collaborate.</text>',
        f'<text x="{c2x + 18}" y="{cy + 252}" font-family="{MONO}" font-size="10.2" fill="{COBALT}">Untrusted incident text never runs tools directly.</text>',
    ])

    # Column 3: Policy & Human Gate
    parts.extend([
        f'<rect x="{c3x}" y="{cy}" width="{cw}" height="{ch}" rx="10" fill="{CARD}" stroke="{RULE_AMBER}" stroke-width="1.5"/>',
        f'<circle cx="{c3x + 20}" cy="{cy + 24}" r="4.5" fill="{AMBER}"/>',
        f'<text x="{c3x + 32}" y="{cy + 28}" font-family="{MONO}" font-size="11.2" font-weight="700" fill="{AMBER}">3 · POLICY &amp; HUMAN APPROVAL GATE</text>',
        card_row(c3x + 14, cy + 44, cw - 28, "Crown-Jewel Policy Engine", "protected users · devices · apps · IOCs", "POLICY", AMBER, AMBER_SOFT),
        card_row(c3x + 14, cy + 98, cw - 28, "Strict Separation of Duties", "1- or 2-person approval · no self-approve", "HUMAN ONLY", AMBER, AMBER_SOFT),
        card_row(c3x + 14, cy + 152, cw - 28, "Brokered Containment", "Typed confirmation · Sentinel audit log", "21 ACTIONS", GREEN, GREEN_SOFT),
        f'<text x="{c3x + 18}" y="{cy + 236}" font-family="{SANS}" font-size="11.5" fill="{MUTED}">Policy re-checked before execution (post-pause safe).</text>',
        f'<text x="{c3x + 18}" y="{cy + 252}" font-family="{MONO}" font-size="10.2" fill="{AMBER}">Destructive containment never auto-runs.</text>',
    ])

    # Connector arrows between cards
    ay = cy + ch / 2
    parts.extend([
        f'<line x1="{c1x + cw}" y1="{ay}" x2="{c2x - 2}" y2="{ay}" stroke="{COBALT}" stroke-width="2.2" marker-end="url(#arrBlue)"/>',
        f'<line x1="{c2x + cw}" y1="{ay}" x2="{c3x - 2}" y2="{ay}" stroke="{AMBER}" stroke-width="2.2" marker-end="url(#arrAmber)"/>',
    ])

    # Bottom footer strip (evenly spaced with generous breathing room inside 44..1236)
    footer = [
        ("Zero-secret Entra ID auth", GREEN, 44),
        ("Fail-closed cloud defaults", COBALT, 268),
        ("5-min Docker demo", GREEN, 504),
        ("AU East/Southeast Bicep + Private Endpoints", COBALT, 682),
        ("Security Copilot & Entra Agent ID", PURPLE, 1018),
    ]
    for label, col, fx in footer:
        parts.append(f'<circle cx="{fx + 4}" cy="433" r="3" fill="{col}"/>')
        parts.append(f'<text x="{fx + 14}" y="437" font-family="{MONO}" font-size="10.4" fill="{MUTED}">{escape(label)}</text>')

    parts.append("</svg>")
    return "".join(parts)


def main() -> None:
    OUT_SVG.parent.mkdir(parents=True, exist_ok=True)
    OUT_SVG.write_text(build_svg(), encoding="utf-8")
    rsvg = shutil.which("rsvg-convert")
    if not rsvg:
        sys.exit("error: rsvg-convert is required to render docs/images/blueboard-banner.png")
    subprocess.run([rsvg, "-w", "2560", "-h", "904", "-o", str(OUT_PNG), str(OUT_SVG)], check=True)
    print(f"Wrote {OUT_SVG} and {OUT_PNG}")


if __name__ == "__main__":
    main()
