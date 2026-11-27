#!/usr/bin/env python3
"""
Builds blueboard's Azure solution architecture diagram using Microsoft's official Azure
Public Service Icons (V25), producing both an editable Draw.io file (.drawio) and a
publication-grade vector SVG (.svg) that converts cleanly to PNG with rsvg-convert.

    curl -fsSL -o /tmp/az.zip https://arch-center.azureedge.net/icons/Azure_Public_Service_Icons_V25.zip
    unzip -q /tmp/az.zip -d /tmp/az
    python3 -I scripts/build-architecture-diagram.py \\
      /tmp/az/Azure_Public_Service_Icons/Icons \\
      docs/architecture/azure-architecture.drawio \\
      docs/architecture/azure-architecture.svg
    rsvg-convert -w 2400 -o docs/architecture/azure-architecture.png docs/architecture/azure-architecture.svg

Icons are (c) Microsoft and used unmodified under the Azure architecture icon terms
(no crop, flip, rotation, colour change or distortion), each labelled with its full
service name. Microsoft Graph, Defender XDR and the Defender for Endpoint API have no
Azure architecture icon, so they are drawn as clean labelled cards.
"""
import base64
import re
import sys
from html import escape
from pathlib import Path

ICONS = {
    "users": "identity/10230-icon-service-Users.svg",
    "appreg": "identity/10232-icon-service-App-Registrations.svg",
    "entapp": "identity/10225-icon-service-Enterprise-Applications.svg",
    "mi": "identity/10227-icon-service-Managed-Identities.svg",
    "idprot": "identity/10231-icon-service-Entra-ID-Protection.svg",
    "rg": "general/10007-icon-service-Resource-Groups.svg",
    "appsvc": "web/10035-icon-service-App-Services.svg",
    "func": "compute/10029-icon-service-Function-Apps.svg",
    "vnet": "networking/10061-icon-service-Virtual-Networks.svg",
    "nat": "networking/10310-icon-service-NAT.svg",
    "pe": "other/02579-icon-service-Private-Endpoints.svg",
    "postgres": "databases/10131-icon-service-Azure-Database-PostgreSQL-Server.svg",
    "kv": "security/10245-icon-service-Key-Vaults.svg",
    "storage": "storage/10086-icon-service-Storage-Accounts.svg",
    "appi": "monitor/00012-icon-service-Application-Insights.svg",
    "dcr": "other/01857-icon-service-Data-Collection-Rules.svg",
    "law": "monitor/00009-icon-service-Log-Analytics-Workspaces.svg",
    "logic": "integration/02631-icon-service-Logic-Apps.svg",
    "sentinel": "security/10248-icon-service-Azure-Sentinel.svg",
    "mdc": "security/10241-icon-service-Microsoft-Defender-for-Cloud.svg",
    "foundry": "ai + machine learning/035746832-icon-service-AI-Foundry.svg",
    "aca": "other/02884-icon-service-Worker-Container-App.svg",
}

# Palette (Azure Architecture Center conventions)
BLUE = "#0078D4"
BLUE_LIGHT = "#F0F7FF"
ENTRA = "#6D28D9"
ENTRA_LIGHT = "#F5F3FF"
SLATE = "#0F172A"
MUTED = "#475569"
BORDER = "#CBD5E1"
READ = "#0F766E"    # read-only ingest, hunting & entity lookups
WRITE = "#B91C1C"   # brokered containment writes (policy + human approval)
SYNC = "#7C3AED"    # audit export & Sentinel Automation Rule sync
VNET_COLOR = "#0369A1"
VNET_LIGHT = "#E0F2FE"
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"


def _escape_mx_rich(line: str) -> str:
    """Escape plain text while preserving intentional <b>...</b> tags for Draw.io HTML labels."""
    parts = re.split(r"(<b>.*?</b>)", line)
    out = []
    for part in parts:
        if part.startswith("<b>") and part.endswith("</b>"):
            out.append(f"<b>{escape(part[3:-4])}</b>")
        else:
            out.append(escape(part))
    return "".join(out)


class Diagram:
    def __init__(self, icon_dir: Path, width: int, height: int):
        self.icon_dir = icon_dir
        self.w = width
        self.h = height
        self.mx_cells: list[str] = []
        self.svg_groups: list[str] = []
        self.svg_cards: list[str] = []
        self.svg_edges: list[str] = []
        self.svg_badges: list[str] = []
        self.nodes: dict[str, tuple[float, float, float, float]] = {}
        self.n = 2
        self._b64_cache: dict[str, str] = {}

    def _id(self) -> str:
        self.n += 1
        return f"c{self.n}"

    def _icon_uri(self, key: str) -> str:
        if key not in self._b64_cache:
            data = (self.icon_dir / ICONS[key]).read_bytes()
            self._b64_cache[key] = "data:image/svg+xml;base64," + base64.b64encode(data).decode()
        return self._b64_cache[key]

    def _mx_img(self, key: str) -> str:
        b64 = self._icon_uri(key).split(",", 1)[1]
        return "data:image/svg+xml," + b64

    def header(self, title: str, subtitle: str, x: float, y: float):
        cid = self._id()
        val = f"<b style='font-size:22px'>{escape(title)}</b><br>{escape(subtitle)}"
        style = f"text;html=1;whiteSpace=wrap;align=left;verticalAlign=top;fontSize=12;fontColor={SLATE};"
        self.mx_cells.append(
            f'<mxCell id="{cid}" value="{escape(val)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="1600" height="54" as="geometry"/></mxCell>'
        )
        self.svg_cards.append(
            f'<text x="{x}" y="{y + 22}" font-family="{FONT}" font-size="22" font-weight="700" fill="{SLATE}">{escape(title)}</text>'
            f'<text x="{x}" y="{y + 42}" font-family="{FONT}" font-size="12.5" fill="{MUTED}">{escape(subtitle)}</text>'
        )

    def group(self, label: str, x: float, y: float, w: float, h: float,
              stroke=BLUE, fill=BLUE_LIGHT, dashed=True, icon=None, sublabel=None):
        gid = self._id()
        mx_label = f"<b>{escape(label)}</b>" + (f" <font style='font-size:10px' color='{MUTED}'>— {escape(sublabel)}</font>" if sublabel else "")
        style = (
            f"rounded=1;arcSize=3;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};strokeWidth=1.5;"
            f"{'dashed=1;dashPattern=6 4;' if dashed else ''}verticalAlign=top;align=left;spacingLeft={38 if icon else 14};"
            f"spacingTop=9;fontSize=13;fontColor={SLATE};container=0;"
        )
        self.mx_cells.append(
            f'<mxCell id="{gid}" value="{escape(mx_label)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>'
        )
        dash_attr = ' stroke-dasharray="7 4"' if dashed else ""
        self.svg_groups.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" ry="10" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"{dash_attr}/>'
        )
        tx = x + (38 if icon else 14)
        if icon:
            self._place_icon(icon, x + 12, y + 9, 20, target_layer="group")
        if sublabel:
            self.svg_groups.append(
                f'<text x="{tx}" y="{y + 23}" font-family="{FONT}" font-size="13" font-weight="700" fill="{SLATE}">'
                f'{escape(label)} <tspan font-weight="400" font-size="11" fill="{MUTED}">— {escape(sublabel)}</tspan></text>'
            )
        else:
            self.svg_groups.append(
                f'<text x="{tx}" y="{y + 23}" font-family="{FONT}" font-size="13" font-weight="700" fill="{SLATE}">{escape(label)}</text>'
            )
        return gid

    def _place_icon(self, key: str, x: float, y: float, size: float, target_layer="card"):
        cid = self._id()
        style = f"shape=image;html=1;aspect=fixed;imageAspect=0;image={self._mx_img(key)};"
        self.mx_cells.append(
            f'<mxCell id="{cid}" value="" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{size}" height="{size}" as="geometry"/></mxCell>'
        )
        img = f'<image href="{self._icon_uri(key)}" x="{x}" y="{y}" width="{size}" height="{size}" preserveAspectRatio="xMidYMid meet"/>'
        if target_layer == "group":
            self.svg_groups.append(img)
        else:
            self.svg_cards.append(img)

    def card(self, key, title: str, lines: list[str], x: float, y: float, w: float, h: float,
             stroke=BORDER, fill="#FFFFFF", badge: str | None = None, badge_color=BLUE,
             badge_pos: str = "top", top=False):
        cid = self._id()
        self.nodes[cid] = (x, y, w, h)
        mx_sub = "<br>".join(_escape_mx_rich(l) for l in lines)
        mx_val = f"<b>{escape(title)}</b>" + (f"<br><font style='font-size:10px' color='{MUTED}'>{mx_sub}</font>" if lines else "")
        style = (
            f"rounded=1;arcSize=8;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};strokeWidth=1.2;"
            f"fontSize=12;fontColor={SLATE};align=left;verticalAlign={'top' if top else 'middle'};"
            f"spacingLeft={58 if key else 14};spacingRight=10;{'spacingTop=12;' if top else ''}"
        )
        self.mx_cells.append(
            f'<mxCell id="{cid}" value="{escape(mx_val)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>'
        )
        self.svg_cards.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" ry="8" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.2" filter="url(#shadow)"/>'
        )
        if key:
            icon_size = 36
            iy = (y + 14) if top else (y + (h - icon_size) / 2)
            self._place_icon(key, x + 12, iy, icon_size, target_layer="card")
        tx = x + (58 if key else 14)
        line_h = 14.8
        block_h = 16 + len(lines) * line_h
        ty = (y + 24) if top else (y + (h - block_h) / 2 + 13)
        self.svg_cards.append(
            f'<text x="{tx}" y="{ty}" font-family="{FONT}" font-size="12.4" font-weight="700" fill="{SLATE}">{escape(title)}</text>'
        )
        for i, raw in enumerate(lines):
            ly = ty + 16 + i * line_h
            parts = re.split(r"(<b>.*?</b>)", raw)
            tspans = []
            for part in parts:
                if part.startswith("<b>") and part.endswith("</b>"):
                    tspans.append(f'<tspan font-weight="700" fill="{SLATE}">{escape(part[3:-4])}</tspan>')
                elif part:
                    tspans.append(f'<tspan>{escape(part)}</tspan>')
            self.svg_cards.append(
                f'<text x="{tx}" y="{ly}" font-family="{FONT}" font-size="10.4" fill="{MUTED}">{"".join(tspans)}</text>'
            )
        if badge:
            bw = max(44, len(badge) * 6.4 + 14)
            bx = x + w - bw - 8
            by = (y + h - 25) if badge_pos == "bottom" else (y + 8)
            self.svg_cards.append(
                f'<rect x="{bx}" y="{by}" width="{bw}" height="17" rx="8.5" fill="{badge_color}" fill-opacity="0.12" stroke="{badge_color}" stroke-width="0.8"/>'
                f'<text x="{bx + bw/2}" y="{by + 12}" text-anchor="middle" font-family="{FONT}" font-size="9.3" font-weight="700" fill="{badge_color}">{escape(badge)}</text>'
            )
        return cid

    def note_lines(self, lines: list[str], x: float, y: float, w: float, size=10.2, color=MUTED):
        cid = self._id()
        mx_html = "<br>".join(escape(l) for l in lines)
        style = f"text;html=1;whiteSpace=wrap;align=left;verticalAlign=top;fontSize={size};fontColor={color};"
        self.mx_cells.append(
            f'<mxCell id="{cid}" value="{escape(mx_html)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{len(lines) * 16 + 6}" as="geometry"/></mxCell>'
        )
        for i, line in enumerate(lines):
            self.svg_cards.append(
                f'<text x="{x}" y="{y + 12 + i * 15}" font-family="{FONT}" font-size="{size}" fill="{color}">{escape(line)}</text>'
            )

    def pill_badge(self, num: str, cx: float, cy: float, color: str):
        self.svg_badges.append(
            f'<circle cx="{cx}" cy="{cy}" r="10.5" fill="{color}" stroke="#FFFFFF" stroke-width="2"/>'
            f'<text x="{cx}" y="{cy + 3.8}" text-anchor="middle" font-family="{FONT}" font-size="10.5" font-weight="700" fill="#FFFFFF">{escape(num)}</text>'
        )

    def edge(self, src: str, dst: str, num: str = "", color=SLATE, dashed=False,
             points: list[tuple[float, float]] | None = None,
             exit_pt=(1.0, 0.5), entry_pt=(0.0, 0.5), both=False, width=1.8,
             badge_pos: tuple[float, float] | None = None):
        eid = self._id()
        style = (
            f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;strokeColor={color};strokeWidth={width};"
            f"fontSize=11;fontStyle=1;fontColor={color};labelBackgroundColor=#FFFFFF;labelBorderColor=none;"
            f"{'dashed=1;' if dashed else ''}{'startArrow=block;startFill=1;' if both else ''}"
            f"exitX={exit_pt[0]};exitY={exit_pt[1]};exitDx=0;exitDy=0;"
            f"entryX={entry_pt[0]};entryY={entry_pt[1]};entryDx=0;entryDy=0;"
        )
        pts_xml = ""
        if points:
            pts_xml = '<Array as="points">' + "".join(f'<mxPoint x="{px}" y="{py}"/>' for px, py in points) + "</Array>"
        self.mx_cells.append(
            f'<mxCell id="{eid}" value="{escape(num)}" style="{style}" edge="1" parent="1" source="{src}" target="{dst}">'
            f'<mxGeometry relative="1" as="geometry">{pts_xml}</mxGeometry></mxCell>'
        )

        sx, sy, sw, sh = self.nodes[src]
        dx, dy, dw, dh = self.nodes[dst]
        p0 = (sx + sw * exit_pt[0], sy + sh * exit_pt[1])
        p1 = (dx + dw * entry_pt[0], dy + dh * entry_pt[1])
        poly = [p0] + (list(points) if points else []) + [p1]
        d_cmd = self._rounded_path(poly, radius=8)
        marker_id = f"arr-{color.lstrip('#')}"
        dash_attr = ' stroke-dasharray="5 4"' if dashed else ""
        start_attr = f' marker-start="url(#{marker_id}-start)"' if both else ""
        self.svg_edges.append(
            f'<path d="{d_cmd}" fill="none" stroke="{color}" stroke-width="{width}" '
            f'stroke-linejoin="round" stroke-linecap="round"{dash_attr}{start_attr} marker-end="url(#{marker_id})"/>'
        )
        if num:
            if badge_pos is None:
                mid = len(poly) // 2
                bx = (poly[mid - 1][0] + poly[mid][0]) / 2
                by = (poly[mid - 1][1] + poly[mid][1]) / 2
                badge_pos = (bx, by)
            self.pill_badge(num, badge_pos[0], badge_pos[1], color)

    @staticmethod
    def _rounded_path(pts: list[tuple[float, float]], radius=8.0) -> str:
        if len(pts) < 2:
            return ""
        out = [f"M {pts[0][0]:.1f} {pts[0][1]:.1f}"]
        for i in range(1, len(pts) - 1):
            ax, ay = pts[i - 1]
            bx, by = pts[i]
            cx, cy = pts[i + 1]
            v1x, v1y = bx - ax, by - ay
            v2x, v2y = cx - bx, cy - by
            l1 = (v1x * v1x + v1y * v1y) ** 0.5
            l2 = (v2x * v2x + v2y * v2y) ** 0.5
            if l1 < 1e-3 or l2 < 1e-3:
                continue
            r = min(radius, l1 / 2, l2 / 2)
            p_before = (bx - v1x / l1 * r, by - v1y / l1 * r)
            p_after = (bx + v2x / l2 * r, by + v2y / l2 * r)
            out.append(f"L {p_before[0]:.1f} {p_before[1]:.1f}")
            out.append(f"Q {bx:.1f} {by:.1f} {p_after[0]:.1f} {p_after[1]:.1f}")
        out.append(f"L {pts[-1][0]:.1f} {pts[-1][1]:.1f}")
        return " ".join(out)

    def legend_flows(self, x: float, y: float, w: float, h: float, items: list[tuple[str, str, str, str]], footer: list[str]):
        self.group("Data & Control Flows", x, y, w, h, stroke=BORDER, fill="#FFFFFF", dashed=False)
        cy = y + 43
        for num, color, lead, desc in items:
            self.pill_badge(num, x + 22, cy - 3.5, color)
            self.svg_cards.append(
                f'<text x="{x + 38}" y="{cy}" font-family="{FONT}" font-size="10.7" fill="{SLATE}">'
                f'<tspan font-weight="700">{escape(lead)}</tspan> '
                f'<tspan fill="{MUTED}">{escape(desc)}</tspan></text>'
            )
            cy += 21.5
        cy += 5
        for line in footer:
            self.svg_cards.append(
                f'<text x="{x + 14}" y="{cy}" font-family="{FONT}" font-size="10.2" font-weight="600" fill="{SLATE}">{escape(line)}</text>'
            )
            cy += 15
        mx_html = "<br>".join(f"<font color='{c}'><b>{n}</b></font> <b>{escape(l)}</b> {escape(d)}" for n, c, l, d in items)
        mx_html += "<br><br>" + "<br>".join(f"<b>{escape(f)}</b>" for f in footer)
        cid = self._id()
        style = f"text;html=1;whiteSpace=wrap;align=left;verticalAlign=top;fontSize=10.5;fontColor={SLATE};"
        self.mx_cells.append(
            f'<mxCell id="{cid}" value="{escape(mx_html)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x + 12}" y="{y + 32}" width="{w - 24}" height="{h - 38}" as="geometry"/></mxCell>'
        )

    def to_drawio(self) -> str:
        return (
            '<mxfile host="blueboard" type="device"><diagram id="azure" name="blueboard Solution Architecture">'
            f'<mxGraphModel dx="{self.w}" dy="{self.h}" grid="0" gridSize="10" guides="1" tooltips="1" '
            f'connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="{self.w}" pageHeight="{self.h}" '
            'background="#FFFFFF" math="0" shadow="0"><root>'
            '<mxCell id="0"/><mxCell id="1" parent="0"/>'
            + "".join(self.mx_cells)
            + "</root></mxGraphModel></diagram></mxfile>"
        )

    def to_svg(self) -> str:
        colors = {BLUE, SLATE, READ, WRITE, SYNC, "#64748B", VNET_COLOR}
        markers = []
        for col in sorted(colors):
            mid = f"arr-{col.lstrip('#')}"
            markers.append(
                f'<marker id="{mid}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto">'
                f'<path d="M 0 1 L 9 5 L 0 9 z" fill="{col}"/></marker>'
                f'<marker id="{mid}-start" viewBox="0 0 10 10" refX="1.5" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto">'
                f'<path d="M 10 1 L 1 5 L 10 9 z" fill="{col}"/></marker>'
            )
        defs = (
            "<defs>"
            '<filter id="shadow" x="-4%" y="-6%" width="108%" height="116%">'
            '<feDropShadow dx="0" dy="1.5" stdDeviation="2.2" flood-color="#0F172A" flood-opacity="0.06"/>'
            "</filter>"
            + "".join(markers)
            + "</defs>"
        )
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}">'
            + defs
            + f'<rect x="0" y="0" width="{self.w}" height="{self.h}" fill="#FFFFFF"/>'
            + "".join(self.svg_groups)
            + "".join(self.svg_edges)
            + "".join(self.svg_cards)
            + "".join(self.svg_badges)
            + "</svg>"
        )


def build(icon_dir: Path) -> Diagram:
    W, H = 1960, 1300
    d = Diagram(icon_dir, W, H)

    d.header(
        "blueboard Solution Architecture on Azure (Australia East / Australia Southeast)",
        "Zero-secret Entra ID & Entra Agent ID auth · 53 MCP tools & OpenAPI 3.1 · 30 policy-gated Defender/Entra/Sentinel/Intune/Okta actions · Purview DLP & Sentinel MCP ready",
        30, 16,
    )

    # ── Band 1: Microsoft Entra ID (Tenant Identity Plane) ───────────────────
    d.group(
        "Microsoft Entra ID (Tenant Identity & Trust Plane)",
        30, 82, 1900, 134,
        stroke=ENTRA, fill=ENTRA_LIGHT, dashed=True,
        sublabel="Zero stored secrets · JWT signature, issuer, audience & roles checked on every call",
    )
    d.card(
        "appreg", "App Registration · blueboard-<env>",
        ["API URI: api://blueboard-<env> · 5 app roles · scope Board.Access",
         "SPA /redirect · Auth Code + PKCE · no client secret, no implicit flow"],
        48, 118, 448, 82, stroke="#DDD6FE",
    )
    d.card(
        "entapp", "Enterprise Application",
        ["Assignment required: only assigned SOC groups & agents get tokens",
         "Conditional Access (phishing-resistant MFA) on Board.Approve / Admin"],
        514, 118, 448, 82, stroke="#DDD6FE",
    )
    d.card(
        "mi", "User-Assigned Managed Identity · blueboard-id-api",
        ["Single credential boundary for Graph, MDE, Sentinel & Log Analytics",
         "PostgreSQL Entra admin · Storage RBAC · Key Vault Secrets User"],
        980, 118, 476, 82, stroke="#DDD6FE",
    )
    d.card(
        "idprot", "Microsoft Entra ID Protection",
        ["Risky users & recent risk detections read via lookup_entity",
         "confirm_user_compromised & dismiss_user_risk (approval-gated)"],
        1474, 118, 438, 82, stroke="#DDD6FE",
    )

    # ── Left Column: SOC Participants & Multi-Agent Roster ───────────────────
    d.group("SOC Participants & Autonomous AI Agents", 30, 236, 290, 686, stroke="#94A3B8", fill="#F8FAFC")

    analysts = d.card(
        "users", "SOC Analysts & Approvers",
        ["Browser · MSAL PKCE sign-in",
         "Board.Post · Hunt · RequestActions",
         "Human-only Board.Approve & Admin",
         "No self-approval (SQL-enforced)"],
        46, 282, 258, 116, stroke=BLUE,
    )
    roster = d.card(
        "aca", "AI Agents · Entra Agent ID",
        ["Container Apps · Security Copilot",
         "Triage · Sentinel Hunter · Purview ·",
         "Threat Intel · Containment · Comms",
         "Dual-MCP (blueboard + Sentinel MCP)",
         "Signed push webhooks (HMAC)"],
        46, 440, 258, 134, stroke=BLUE,
    )
    coding = d.card(
        None, "External & Coding Agents",
        ["Python / TypeScript MCP starters",
         "Claude Code · Codex · Copilot",
         "skills/blueboard/SKILL.md",
         "Workload Identity Federation",
         "Board.Approve stripped in code"],
        46, 616, 258, 126, stroke="#94A3B8",
    )
    ref = d.card(
        "aca", "Reference Enrichment Agent",
        ["C# (.NET 10) · Blueboard.Agent.Sdk",
         "Anthropic SDK · Claude on Foundry",
         "Client-side refusal fallback model",
         "Holds zero Microsoft security creds"],
        46, 780, 258, 122, stroke=BLUE,
    )

    # ── Centre: Azure Resource Group (Australia East / Southeast) ────────────
    d.group(
        "Azure Resource Group · Australia East (or Australia Southeast)",
        360, 236, 860, 1006,
        stroke=BLUE, fill=BLUE_LIGHT, dashed=True, icon="rg",
        sublabel="Data residency enforced in infra/main.bicep",
    )

    web = d.card(
        "appsvc", "App Service Web App · blueboard-web",
        ["Linux .NET 10 host + React 19 SPA (B1 in mvp · P0v3 in production)",
         "Strict CSP · HSTS · X-Frame-Options · /config.json (public values only)",
         "Zero managed identity · zero secrets · zero direct database access"],
        384, 282, 812, 92, stroke=BLUE, badge="Public HTTPS", badge_color=BLUE,
    )

    api = d.card(
        "func", "Azure Functions · blueboard-api (Flex Consumption FC1)",
        ["<b>.NET 10 isolated</b> · 2 GB instances (max 40) · 1 always-ready http instance in production",
         "<b>REST + OpenAPI 3.1</b> /api/* (CORS: Web App origin only) · <b>MCP</b> /runtime/webhooks/mcp (<b>53 tools</b>)",
         "<b>Action Broker</b>: 21 Defender/Entra/Sentinel actions · policy.json · 1-/2-approver · post-pause recheck",
         "<b>Enrichment & Purview</b>: lookup_entity · lookup_purview_context · MDE/Sentinel KQL · token-free TI feeds",
         "<b>Advisory-locked Timers</b>: incident poller · recovery · notifier · webhooks · audit · secret/Purview guard",
         "<b>AuthN/Z</b>: Entra JWT checked per call · per-principal Postgres rate limits · identity: blueboard-id-api"],
        384, 410, 812, 186, stroke=BLUE, badge="TCB · Managed Identity", badge_color=BLUE, top=True,
    )

    # Inner VNet / Private Data Tier (Production Profile)
    d.group(
        "Virtual Network & Private Data Tier",
        384, 622, 812, 354,
        stroke=VNET_COLOR, fill=VNET_LIGHT, dashed=True, icon="vnet",
        sublabel="BB_PROFILE=production · VNet integration + Private Endpoints + Private DNS",
    )

    nat = d.card(
        "nat", "NAT Gateway",
        ["Static outbound IP for",
         "Function App VNet egress"],
        402, 664, 236, 74, stroke=VNET_COLOR, badge="Prod", badge_color=VNET_COLOR,
    )
    pe = d.card(
        "pe", "Private Endpoints + Private DNS",
        ["Private link to PostgreSQL, Key Vault & Storage (blob/queue/table)",
         "publicNetworkAccess: Disabled · AllowAzureServices removed"],
        654, 664, 524, 74, stroke=VNET_COLOR, badge="Prod", badge_color=VNET_COLOR,
    )
    pg = d.card(
        "postgres", "Azure Database for PostgreSQL Flexible Server 16",
        ["Entra auth only (passwordAuth: Disabled) · B1ms (mvp) / D2ds_v5 Zone-Redundant HA (prod)",
         "Messages, atomic claims, incidents, playbooks, actions, approvals, rate limits, GIN search, audit_log"],
        402, 760, 776, 86, stroke=VNET_COLOR, badge="Entra Only", badge_color=VNET_COLOR,
    )
    kv = d.card(
        "kv", "Azure Key Vault (RBAC)",
        ["policy.json · webhook signing key",
         "Notification URLs & HMAC · NVD key",
         "Purge protection (90d) · KV references"],
        402, 864, 380, 94, stroke=VNET_COLOR, badge="Prod", badge_color=VNET_COLOR,
    )
    storage = d.card(
        "storage", "Azure Storage Account",
        ["Functions host + deployment package",
         "allowSharedKeyAccess: false · TLS 1.2",
         "Blob Owner · Queue & Table Contributor"],
        798, 864, 380, 94, stroke=VNET_COLOR, badge="RBAC Only", badge_color=VNET_COLOR,
    )

    # Observability & Sentinel Audit Export band
    d.group(
        "Observability & Tamper-Evident Audit Export",
        384, 994, 812, 230,
        stroke="#64748B", fill="#FFFFFF", dashed=False,
        sublabel="All logs & audit streams stay in Australia",
    )
    appi = d.card(
        "appi", "Application Insights",
        ["Workspace-based telemetry",
         "Local auth disabled (Entra only)",
         "Monitoring Metrics Publisher"],
        402, 1034, 246, 94, stroke=BORDER,
    )
    dcr = d.card(
        "dcr", "Data Collection Rule",
        ["DCE + Logs Ingestion (1-min)",
         "Stream: Custom-BlueboardAudit_CL",
         "High-water mark (no skip/dup)"],
        666, 1034, 250, 94, stroke=SYNC, badge="Prod", badge_color=SYNC, badge_pos="bottom",
    )
    law = d.card(
        "law", "Log Analytics Workspace",
        ["90-day operational telemetry",
         "BlueboardAudit_CL (365-day)",
         "Feeds Microsoft Sentinel rules"],
        934, 1034, 244, 94, stroke=BORDER,
    )

    d.note_lines(
        [
            "Optional outbound sinks: Teams Workflows / HTTPS HMAC webhook / Graph Mail.Send (scoped via Exchange Application Access Policy)",
            "and token-free external TI feeds (pwn.watch, CISA KEV, FIRST EPSS, NVD, OSV via exact-host TiFetcher).",
        ],
        402, 1172, 776, size=10.0, color=MUTED,
    )

    # ── Right Column: Microsoft Security Tenant Services & Foundry ───────────
    RX = 1290
    d.group(
        "Microsoft Security Services (Tenant Plane)",
        RX, 236, 640, 566,
        stroke="#64748B", fill="#F8FAFC", dashed=True,
        sublabel="Origin-locked token guard in MsClient.BuildUri",
    )
    graph = d.card(
        None, "Microsoft Graph Security & Purview",
        ["incidents · alerts_v2 · runHuntingQuery",
         "Purview Labels / processContent · Entra"],
        RX + 18, 282, 290, 86, stroke=READ,
    )
    xdr = d.card(
        None, "Defender XDR & Microsoft Purview",
        ["Unified SOC · MDE/MDO/MDI · Purview",
         "DLP · Insider Risk · Sensitivity Labels"],
        RX + 332, 282, 290, 86, stroke="#94A3B8",
    )
    mdeapi = d.card(
        None, "Microsoft Defender for Endpoint API",
        ["api.security.microsoft.com",
         "Isolate, scan, forensics, restrict, IOCs"],
        RX + 18, 392, 290, 86, stroke=WRITE,
    )
    mdc = d.card(
        "mdc", "Microsoft Defender for Cloud",
        ["Azure RBAC & Key Vault alerts",
         "Unified into Defender XDR / Sentinel"],
        RX + 332, 392, 290, 86, stroke="#94A3B8",
    )
    sentinel = d.card(
        "sentinel", "Microsoft Sentinel + Sentinel MCP",
        ["api.loganalytics.io (run_sentinel_query) · Sentinel MCP (/triage, /graph, /data-exploration)",
         "STIX 2.1 TI upload · BlueboardAudit_CL · 9 scheduled board-integrity rules"],
        RX + 18, 504, 604, 96, stroke=BLUE, badge="SIEM + MCP + Graph", badge_color=BLUE,
    )
    logic = d.card(
        "logic", "Sentinel Automation Rule (Azure Logic App)",
        ["Real-time trigger on Incident Created / Updated → POST /api/incidents/{id}/sync",
         "Authenticates with System Managed Identity (Board.Post) · Graph fetch stays server-side"],
        RX + 18, 626, 604, 88, stroke=SYNC, badge="Real-Time Sync", badge_color=SYNC,
    )
    d.note_lines(
        [
            "Write permissions are opt-in per action via infra/grant-permissions.sh (ACTIONS=...).",
            "Default deploy is READ_ONLY=1 + BROKER_EXECUTE=false. Connector: templates/sentinel/automation-rule-logic-app.json.",
        ],
        RX + 18, 734, 604, size=10.0, color=MUTED,
    )

    # Microsoft Foundry (Agent LLM Plane)
    d.group(
        "Microsoft Foundry (Agent LLM Plane)",
        RX, 822, 640, 128,
        stroke="#64748B", fill="#F8FAFC", dashed=True,
        sublabel="Only agent prompts go here; blueboard never calls an LLM",
    )
    foundry = d.card(
        "foundry", "Microsoft Foundry",
        ["Claude Opus 5.5 + fallback model · Entra auth (Cognitive Services User)",
         "Swap for any Australian-hosted model if prompts must remain in-country"],
        RX + 18, 860, 604, 74, stroke="#94A3B8",
    )

    # Flows Legend
    d.legend_flows(
        RX, 968, 640, 274,
        items=[
            ("1", BLUE, "Analysts → Web App:", "HTTPS static React SPA + /config.json (no identity or secrets)"),
            ("2", BLUE, "Analysts → Function App:", "HTTPS /api/* with delegated Entra JWT (scope Board.Access)"),
            ("3", BLUE, "Agents ↔ MCP & Webhooks:", "/runtime/webhooks/mcp (Entra/Agent ID JWT, 53 tools) + HMAC wake-ups"),
            ("4", VNET_COLOR, "Private Data & Vault:", "VNet + Private Endpoints → Postgres (Entra), Key Vault & Storage"),
            ("5", READ, "Read-Only Ingest & Hunts:", "Graph incidents, Purview DLP/IRM/Labels, MDE & Sentinel KQL"),
            ("6", WRITE, "Brokered Containment:", "21 Defender/Entra/Sentinel writes ONLY after policy + human approval"),
            ("7", SYNC, "Audit Export → Sentinel:", "1-min DCE/DCR export to BlueboardAudit_CL + 9 analytics rules"),
            ("8", SYNC, "Sentinel Real-Time Sync:", "Automation Rule Logic App triggers POST /api/incidents/{id}/sync"),
            ("9", SLATE, "Reference Agent → Foundry:", "Entra-authenticated Messages API (prompts only)"),
        ],
        footer=[
            "Security invariant: agents hold zero Microsoft security permissions; no component stores secrets.",
        ],
    )

    # ── Orthogonal Routed Edges (dedicated non-overlapping corridors) ────────
    # Left gutter: x = 330..350
    d.edge(analysts, web, "1", color=BLUE, exit_pt=(1, 0.35), entry_pt=(0, 0.5),
           points=[(332, 323), (332, 328)], badge_pos=(332, 325))
    d.edge(analysts, api, "2", color=BLUE, exit_pt=(1, 0.78), entry_pt=(0, 0.16),
           points=[(342, 372), (342, 440)], badge_pos=(342, 412))
    d.edge(roster, api, "3", color=BLUE, exit_pt=(1, 0.42), entry_pt=(0, 0.46),
           both=True, badge_pos=(342, 496))
    d.edge(coding, api, "", color=BLUE, exit_pt=(1, 0.5), entry_pt=(0, 0.72),
           points=[(336, 679), (336, 544)])
    d.edge(ref, api, "", color=BLUE, exit_pt=(1, 0.35), entry_pt=(0, 0.88),
           points=[(348, 823), (348, 574)])

    # Centre VNet / Private Endpoints
    d.edge(api, pe, "4", color=VNET_COLOR, exit_pt=(0.68, 1), entry_pt=(0.5, 0),
           points=[(936, 610), (916, 610)], badge_pos=(926, 610))
    d.edge(api, nat, "", color=VNET_COLOR, exit_pt=(0.17, 1), entry_pt=(0.5, 0), dashed=True)
    d.edge(pe, pg, "", color=VNET_COLOR, exit_pt=(0.5, 1), entry_pt=(0.66, 0))
    d.edge(pg, kv, "", color=VNET_COLOR, exit_pt=(0.24, 1), entry_pt=(0.5, 0), dashed=True)
    d.edge(pg, storage, "", color=VNET_COLOR, exit_pt=(0.76, 1), entry_pt=(0.5, 0), dashed=True)

    # Right gutter (x = 1236..1276): cleanly separated lanes for flows 5, 6, 8, 9
    # 5: Read-only (x = 1240)
    d.edge(api, graph, "5", color=READ, exit_pt=(1, 0.20), entry_pt=(0, 0.5),
           points=[(1240, 447), (1240, 325)], badge_pos=(1240, 376))
    d.edge(api, sentinel, "", color=READ, exit_pt=(1, 0.62), entry_pt=(0, 0.30),
           points=[(1240, 525), (1240, 533)])

    # 6: Brokered Containment Writes (x = 1256)
    d.edge(api, mdeapi, "6", color=WRITE, width=2.4, exit_pt=(1, 0.42), entry_pt=(0, 0.5),
           points=[(1256, 488), (1256, 435)], badge_pos=(1256, 462))
    d.edge(api, sentinel, "", color=WRITE, width=2.0, dashed=True, exit_pt=(1, 0.76), entry_pt=(0, 0.68),
           points=[(1256, 551), (1256, 569)])

    # Internal Microsoft Security links (zero lines crossing over cards)
    d.edge(graph, xdr, "", color="#64748B", both=True, exit_pt=(1, 0.5), entry_pt=(0, 0.5))
    d.edge(mdeapi, xdr, "", color="#64748B", exit_pt=(1, 0.30), entry_pt=(0, 0.78),
           points=[(RX + 320, 418), (RX + 320, 349)])
    d.edge(xdr, mdc, "", color="#64748B", both=True, exit_pt=(0.5, 1), entry_pt=(0.5, 0))
    d.edge(mdc, sentinel, "", color="#64748B", both=True, exit_pt=(0.5, 1), entry_pt=(0.76, 0))
    d.edge(sentinel, logic, "", color=SYNC, exit_pt=(0.5, 1), entry_pt=(0.5, 0))

    # 7: Observability & Audit Export (DCR -> LAW, AppInsights -> LAW)
    d.edge(dcr, law, "7", color=SYNC, exit_pt=(1, 0.5), entry_pt=(0, 0.5), badge_pos=(925, 1081))
    d.edge(appi, law, "", color="#64748B", dashed=True, exit_pt=(0.5, 1), entry_pt=(0.5, 1),
           points=[(525, 1152), (1056, 1152)])

    # 8: Sentinel Automation Rule Logic App -> Function App (x = 1272)
    d.edge(logic, api, "8", color=SYNC, exit_pt=(0, 0.5), entry_pt=(1, 0.90),
           points=[(1272, 670), (1272, 577)], badge_pos=(1272, 636))

    # 9: Reference Agent -> Microsoft Foundry (bottom corridor y = 1262 -> x = 1254 -> foundry)
    d.edge(ref, foundry, "9", color=SLATE, exit_pt=(0.5, 1), entry_pt=(0, 0.5),
           points=[(175, 1262), (1254, 1262), (1254, 897)], badge_pos=(715, 1262))

    d.note_lines(
        [
            "Official Azure architecture icons (c) Microsoft, used unmodified under the Azure architecture icon terms. "
            "Microsoft Graph, Defender XDR and Defender for Endpoint API have no official Azure icon and are drawn as plain labelled cards.",
        ],
        30, H - 22, W - 60, size=9.6, color=MUTED,
    )
    return d


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    icon_dir = Path(sys.argv[1])
    drawio_out = Path(sys.argv[2])
    svg_out = Path(sys.argv[3]) if len(sys.argv) == 4 else drawio_out.with_suffix(".svg")
    missing = [p for p in ICONS.values() if not (icon_dir / p).exists()]
    if missing:
        sys.exit(f"missing icons: {missing}")
    diagram = build(icon_dir)
    drawio_out.write_text(diagram.to_drawio(), encoding="utf-8")
    svg_out.write_text(diagram.to_svg(), encoding="utf-8")
    print(f"wrote {drawio_out} and {svg_out}")
