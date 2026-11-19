#!/usr/bin/env python3
"""
Builds docs/architecture/azure-architecture.drawio from Microsoft's official Azure architecture icons.

    curl -L -o /tmp/az.zip https://arch-center.azureedge.net/icons/Azure_Public_Service_Icons_V25.zip
    unzip -q /tmp/az.zip -d /tmp/az
    python3 -I scripts/build-architecture-diagram.py /tmp/az/Azure_Public_Service_Icons/Icons docs/architecture/azure-architecture.drawio
    drawio -x -f svg -e -o docs/architecture/azure-architecture.svg docs/architecture/azure-architecture.drawio

Icons are © Microsoft and used under the Azure architecture icon terms (diagrams and documentation).
They are embedded unmodified (no crop, flip, rotation or distortion) and each is labelled with the
full service name. Microsoft Graph, Defender XDR and the Defender for Endpoint API have no Azure
architecture icon, so they are drawn as labelled boxes rather than borrowing another product's icon.
"""
import base64
import sys
from html import escape
from pathlib import Path

ICONS = {
    "users": "identity/10230-icon-service-Users.svg",
    "aca": "other/02884-icon-service-Worker-Container-App.svg",
    "aca_env": "other/02989-icon-service-Container-Apps-Environments.svg",
    "postgres": "databases/10131-icon-service-Azure-Database-PostgreSQL-Server.svg",
    "law": "monitor/00009-icon-service-Log-Analytics-Workspaces.svg",
    "mi": "identity/10227-icon-service-Managed-Identities.svg",
    "appreg": "identity/10232-icon-service-App-Registrations.svg",
    "entapp": "identity/10225-icon-service-Enterprise-Applications.svg",
    "sentinel": "security/10248-icon-service-Azure-Sentinel.svg",
    "foundry": "ai + machine learning/035746832-icon-service-AI-Foundry.svg",
    "rg": "general/10007-icon-service-Resource-Groups.svg",
    "acr": "containers/10105-icon-service-Container-Registries.svg",
    "swa": "web/01007-icon-service-Static-Apps.svg",
    "func": "compute/10029-icon-service-Function-Apps.svg",
    "storage": "storage/10086-icon-service-Storage-Accounts.svg",
    "appi": "monitor/00012-icon-service-Application-Insights.svg",
    "browser": "general/10783-icon-service-Browser.svg",
}

# Palette (Azure diagram conventions: light canvas, Azure blue groups, grey external groups).
BLUE = "#0078D4"
INK = "#1F2937"
MUTED = "#4B5563"
SEC = "#B91C1C"  # brokered write path
READ = "#0F766E"  # read path


class Diagram:
    def __init__(self, icon_dir: Path):
        self.icon_dir = icon_dir
        self.cells: list[str] = []
        self.n = 2

    def _id(self) -> str:
        self.n += 1
        return f"c{self.n}"

    def _img(self, key: str) -> str:
        data = (self.icon_dir / ICONS[key]).read_bytes()
        return "data:image/svg+xml," + base64.b64encode(data).decode()

    def group(self, label, x, y, w, h, stroke=BLUE, fill="#F3F8FD", dashed=True, icon=None, font=13):
        gid = self._id()
        style = (
            f"rounded=1;arcSize=3;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};strokeWidth=1.5;"
            f"{'dashed=1;dashPattern=6 4;' if dashed else ''}verticalAlign=top;align=left;spacingLeft={34 if icon else 12};"
            f"spacingTop=8;fontStyle=1;fontSize={font};fontColor={INK};container=0;"
        )
        self.cells.append(f'<mxCell id="{gid}" value="{escape(label)}" style="{style}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        if icon:
            self.icon(icon, x + 10, y + 8, 20)
        return gid

    def icon(self, key, x, y, size=36):
        """Unlabelled, undistorted icon (the label lives on the card beside it)."""
        cid = self._id()
        style = f"shape=image;html=1;aspect=fixed;imageAspect=0;image={self._img(key)};"
        self.cells.append(f'<mxCell id="{cid}" value="" style="{style}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{size}" height="{size}" as="geometry"/></mxCell>')
        return cid

    def card(self, key, title, sub, x, y, w, h, stroke="#C7CED9", fill="#FFFFFF", top=False):
        """A service card: icon on the left, full service name and details on the right."""
        cid = self._id()
        value = f"<b>{escape(title)}</b>" + (f"<br><font style='font-size:10px' color='{MUTED}'>{sub}</font>" if sub else "")
        style = (
            f"rounded=1;arcSize=6;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontSize=12;fontColor={INK};"
            f"align=left;verticalAlign={'top' if top else 'middle'};spacingLeft={60 if key else 14};spacingRight=10;"
            f"{'spacingTop=12;' if top else ''}"
        )
        self.cells.append(f'<mxCell id="{cid}" value="{escape(value)}" style="{style}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        if key:
            self.icon(key, x + 12, (y + 12) if top else (y + (h - 36) / 2), 36)
        return cid

    def box(self, label, x, y, w, h, sub=None, stroke="#6B7280", fill="#FFFFFF", bold=True):
        cid = self._id()
        value = (f"<b>{escape(label)}</b>" if bold else escape(label)) + (f"<br><font style='font-size:10px' color='{MUTED}'>{sub}</font>" if sub else "")
        style = f"rounded=1;arcSize=8;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontSize=11;fontColor={INK};spacing=6;"
        self.cells.append(f'<mxCell id="{cid}" value="{escape(value)}" style="{style}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def note(self, text, x, y, w, h, size=10, color=MUTED, align="left"):
        cid = self._id()
        style = f"text;html=1;whiteSpace=wrap;align={align};verticalAlign=top;fontSize={size};fontColor={color};"
        self.cells.append(f'<mxCell id="{cid}" value="{escape(text)}" style="{style}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def badge(self, n, x, y, color=INK):
        cid = self._id()
        style = f"ellipse;html=1;fillColor={color};strokeColor=none;fontColor=#FFFFFF;fontStyle=1;fontSize=10;"
        self.cells.append(f'<mxCell id="{cid}" value="{n}" style="{style}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="18" height="18" as="geometry"/></mxCell>')

    def edge(self, src, dst, label="", color=INK, dashed=False, points=None, exit=None, entry=None, both=False, width=1.5, at=0.0):
        eid = self._id()
        style = (
            f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;strokeColor={color};strokeWidth={width};"
            f"fontSize=12;fontStyle=1;fontColor={color};labelBackgroundColor=#FFFFFF;labelBorderColor=none;{'dashed=1;' if dashed else ''}"
            f"{'startArrow=block;startFill=1;' if both else ''}"
        )
        if exit:
            style += f"exitX={exit[0]};exitY={exit[1]};exitDx=0;exitDy=0;"
        if entry:
            style += f"entryX={entry[0]};entryY={entry[1]};entryDx=0;entryDy=0;"
        pts = ""
        if points:
            pts = '<Array as="points">' + "".join(f'<mxPoint x="{px}" y="{py}"/>' for px, py in points) + "</Array>"
        self.cells.append(
            f'<mxCell id="{eid}" value="{escape(label)}" style="{style}" edge="1" parent="1" source="{src}" target="{dst}">'
            f'<mxGeometry x="{at}" relative="1" as="geometry">{pts}</mxGeometry></mxCell>'
        )

    def xml(self, w, h) -> str:
        return (
            '<mxfile host="blueboard" type="device"><diagram id="azure" name="blueboard on Azure">'
            f'<mxGraphModel dx="{w}" dy="{h}" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" '
            f'page="1" pageScale="1" pageWidth="{w}" pageHeight="{h}" background="#FFFFFF" math="0" shadow="0"><root>'
            '<mxCell id="0"/><mxCell id="1" parent="0"/>' + "".join(self.cells) + "</root></mxGraphModel></diagram></mxfile>"
        )


def build(icon_dir: Path) -> str:
    """
    Layout rules that keep text readable:
      - every label sits on its own card; nothing is drawn as free text near a line
      - every line is a straight run through empty space between cards, never over a title
      - flows carry a number only; the legend explains them
    """
    d = Diagram(icon_dir)
    W, H = 1800, 1170

    d.note("<b style='font-size:20px'>blueboard on Azure</b><br>Static React front end · C# Azure Functions back end · Microsoft Defender XDR + Microsoft Sentinel", 30, 18, 1100, 50, size=12, color=INK)

    # ── Microsoft Entra ID (top band, no lines touch it) ──────────────────
    d.group("Microsoft Entra ID (tenant)", 290, 88, 1480, 140, stroke="#7C3AED", fill="#F7F3FE")
    d.card("appreg", "App registration", "api://blueboard-&lt;env&gt; · 5 app roles<br>no client secret: federated credential<br>trusts the Static Web App identity", 310, 122, 340, 88)
    d.card("entapp", "Enterprise application", "assignment required: only assigned<br>users and agents get a token", 670, 122, 330, 88)
    d.card("mi", "Managed identity · blueboard-id-api", "Graph + Defender application permissions<br>PostgreSQL Entra admin · storage data roles", 1020, 122, 360, 88)
    d.card("mi", "Managed identity · blueboard-id-swa", "federated credential on the app registration<br>(Static Web App sign-in, no secret)", 1395, 122, 355, 88)

    # ── Users and agents (left) ───────────────────────────────────────────
    d.group("Users and agents", 30, 270, 200, 460, stroke="#9CA3AF", fill="#F9FAFB")
    analysts = d.card("users", "SOC analysts", "browser · Entra sign-in<br>Board.* app roles", 42, 345, 176, 80)
    ext = d.card(None, "External agents", "any MCP client<br>app-only Entra token<br>never Board.Approve", 42, 485, 176, 80)
    ref = d.card(None, "Reference agent", "C# · Anthropic SDK<br>Claude on Foundry<br>runs anywhere with an<br>Entra workload identity", 42, 605, 176, 100)

    # ── Azure resource group ──────────────────────────────────────────────
    d.group("Azure resource group", 290, 252, 860, 840, stroke=BLUE, fill="#F3F8FD", icon="rg")

    web = d.card("swa", "Static Web App · blueboard-web", "React (Vite) static build · Standard plan<br>built-in Entra sign-in · rolesSource /api/swa-roles<br>proxies /api/* to the linked Function App<br>CSP, HSTS, frame-ancestors none", 320, 300, 520, 96, stroke=BLUE)

    api = d.card(
        "func",
        "Function App · blueboard-api (Flex Consumption)",
        ".NET 10 isolated · scales to zero · max 40 instances<br>"
        "<b>HTTP</b> /api/*: REST for the web app (Board.Post on every route)<br>"
        "<b>MCP</b> /runtime/webhooks/mcp: 14 tools, Entra bearer per call<br>"
        "<b>Action broker</b>: policy → human approval → execute<br>"
        "<b>Enrichment</b>: advanced hunting + entity lookups (read-only)<br>"
        "<b>Timers</b>: incident poller (1 min) · stuck-action recovery<br>"
        "built-in auth on: strips forged principal headers<br>"
        "migrations applied at start-up · identity: blueboard-id-api",
        320, 470, 520, 230, stroke=BLUE, top=True,
    )

    storage = d.card("storage", "Storage account", "Functions host + deployment package<br>shared keys disabled · identity only", 320, 780, 250, 84)
    appi = d.card("appi", "Application Insights", "Entra auth only (no ingestion key)<br>→ Log Analytics workspace", 590, 780, 250, 84)
    pg = d.card("postgres", "Azure Database for PostgreSQL", "Flexible Server 16 · B1ms · Entra auth only<br>full-text search (GIN) · advisory locks", 320, 900, 520, 84)
    d.note("Postgres firewall: AllowAzureServices (MVP). Production: VNet integration + private endpoint (docs/SECURITY.md).", 320, 1000, 800, 30, size=10)

    # ── Microsoft security (right) ────────────────────────────────────────
    d.group("Microsoft security", 1200, 270, 570, 340, stroke="#6B7280", fill="#F9FAFB")
    graph = d.card(None, "Microsoft Graph Security API", "/security/incidents · runHuntingQuery<br>/users · identityProtection · email remediation", 1220, 345, 270, 80)
    mdeapi = d.card(None, "Microsoft Defender for Endpoint API", "api.security.microsoft.com<br>machines · indicators · files · IPs", 1220, 485, 270, 80)
    xdr = d.card(None, "Microsoft Defender XDR", "incidents · alerts · advanced hunting", 1520, 345, 230, 80)
    sentinel = d.card("sentinel", "Microsoft Sentinel", "unified with Defender XDR<br>incidents", 1520, 485, 230, 80)

    d.group("Microsoft Foundry", 1200, 940, 570, 140, stroke="#6B7280", fill="#F9FAFB")
    foundry = d.card("foundry", "Microsoft Foundry", "Claude Opus 5.5 + fallback deployment<br>Messages API · Entra auth", 1220, 975, 310, 84)

    # ── Flows ─────────────────────────────────────────────────────────────
    d.edge(analysts, web, "1", color=BLUE, exit=(1, 0.5), entry=(0, 0.5), points=[(260, 385), (260, 348)], at=-0.6)
    d.edge(web, api, "2", color=BLUE, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(ext, api, "3", color=BLUE, exit=(1, 0.5), entry=(0, 55 / 230), at=-0.5)
    d.edge(ref, api, "3", color=BLUE, exit=(1, 0.5), entry=(0, 185 / 230), at=-0.5)
    d.edge(api, graph, "5", color=READ, exit=(1, 15 / 230), entry=(0, 0.5), points=[(1180, 485), (1180, 385)], at=0.1)
    d.edge(api, mdeapi, "6", color=SEC, exit=(1, 75 / 230), entry=(0, 0.5), width=2.5, at=0.3)
    d.edge(ref, foundry, "7", color=INK, exit=(0.5, 1), entry=(0, 0.5), points=[(130, 1117), (1170, 1117), (1170, 1017)], at=-0.2)
    d.edge(api, pg, "4", color=INK, exit=(0.5, 1), entry=(0.5, 0), at=-0.75)
    d.edge(graph, xdr, "", color="#6B7280", both=True, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(xdr, sentinel, "", color="#6B7280", both=True, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(mdeapi, sentinel, "", color="#6B7280", exit=(1, 0.5), entry=(0, 0.5))

    # ── Legend ────────────────────────────────────────────────────────────
    d.group("Flows", 1200, 630, 570, 290, stroke="#D1D5DB", fill="#FFFFFF", dashed=False, font=12)
    d.note(
        f"<font color='{BLUE}'><b>1</b></font>&nbsp; Analysts → Static Web App: HTTPS, Entra sign-in (built-in auth)<br>"
        f"<font color='{BLUE}'><b>2</b></font>&nbsp; Static Web App → Function App /api/*: linked backend,<br>&nbsp;&nbsp;&nbsp;&nbsp;signed-in principal forwarded by the platform<br>"
        f"<font color='{BLUE}'><b>3</b></font>&nbsp; Agents → MCP /runtime/webhooks/mcp with an Entra bearer token,<br>&nbsp;&nbsp;&nbsp;&nbsp;validated and role-checked on every tool call<br>"
        f"<b>4</b>&nbsp; Function App → PostgreSQL: TLS, Entra token as the password<br>"
        f"<font color='{READ}'><b>5</b></font>&nbsp; Read: incident poller, advanced hunting, entity lookups<br>"
        f"<font color='{SEC}'><b>6</b></font>&nbsp; Write: containment only after policy + human approval<br>"
        f"<b>7</b>&nbsp; Reference agent → Foundry Messages API with an Entra token<br>"
        "The Function App reaches storage and Application Insights with its<br>managed identity; no shared keys or connection secrets.<br>"
        "<br>Agents hold <b>no</b> Microsoft security permissions. No hop uses a stored secret.",
        1215,
        660,
        545,
        255,
        size=11,
        color=INK,
    )
    d.note(
        "Azure icons © Microsoft, used unmodified under the Azure architecture icon terms. "
        "Microsoft Graph, Defender XDR and the Defender for Endpoint API have no Azure architecture icon, so they are drawn as plain cards.",
        30,
        H - 30,
        1100,
        24,
        size=9,
    )
    return d.xml(W, H)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    icon_dir, out = Path(sys.argv[1]), Path(sys.argv[2])
    missing = [p for p in ICONS.values() if not (icon_dir / p).exists()]
    if missing:
        sys.exit(f"missing icons: {missing}")
    out.write_text(build(icon_dir))
    print(f"wrote {out}")
