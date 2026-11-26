import { useState } from "react";
import Layout from "@theme/Layout";
import Link from "@docusaurus/Link";
import useBaseUrl from "@docusaurus/useBaseUrl";
import CodeBlock from "@theme/CodeBlock";
import styles from "./index.module.css";

const COMMANDS = [
  {
    id: "demo",
    label: "2-minute local demo",
    language: "bash",
    code: `git clone https://github.com/jusso-dev/blueboard.git
cd blueboard
./scripts/demo.sh up   # Open http://localhost:8080 (zero Azure/Entra tenant needed)`,
    to: "/DEMO/",
    linkText: "Read the 5-minute demo walkthrough ->"
  },
  {
    id: "policy",
    label: "Validate policy.json",
    language: "bash",
    code: `cp policy.example.json policy.json
dotnet run --project api/Blueboard.Tools -- policy-check policy.json`,
    to: "/POLICY/",
    linkText: "Policy rules, protected lists & simulator ->"
  },
  {
    id: "deploy",
    label: "Deploy to Azure",
    language: "bash",
    code: `# Azure Cloud Shell: a verified release, no toolchain needed
BB_ENV=prod BB_RELEASE=vX.Y.Z POLICY_FILE=policy.json GROUP_ADD_ME=1 ./infra/up.sh
BB_ENV=prod CA_APPLY=1 ./infra/conditional-access.sh   # report-only`,
    to: "/QUICKSTART-AZURE/",
    linkText: "Quickstart & staged go-live ->"
  }
];

const STAGES = [
  { n: "01", name: "Ingest", text: "Defender XDR, Sentinel and Purview alerts sync automatically under blueboard-id-api." },
  { n: "02", name: "Collaborate", text: "Analysts and specialist AI agents claim asks atomically and post grounded findings via 34 MCP tools." },
  { n: "03", name: "Gate", text: "PolicyEngine checks alias-aware protected lists and queues destructive actions for an independent human approver." },
  { n: "04", name: "Execute & Audit", text: "The broker re-validates policy, executes once in MDE/Entra/MDO/Sentinel, and exports BlueboardAudit_CL." }
];

const ECOSYSTEM = [
  {
    title: "Microsoft Sentinel MCP & Graph",
    text: "Pair the read-only Microsoft Sentinel MCP Server (sentinel.microsoft.com/mcp) with blueboard's shared team timeline and human-gated containment.",
    to: "/INTEGRATIONS/"
  },
  {
    title: "Microsoft Purview DLP, IRM & Labels",
    text: "Ingests blobEvidence, teamsMessageEvidence and Purview DLP/Insider Risk alerts, plus lookup_purview_context and optional PURVIEW_CONTENT_GUARD.",
    to: "/guides/12-sentinel-mcp-purview-and-defender/"
  },
  {
    title: "Defender XDR Unified SOC",
    text: "21 brokered containment and recovery actions across MDE, Entra ID, Defender for Office 365 and Sentinel TI — dry-run by default.",
    to: "/guides/06-containment-and-approvals/"
  },
  {
    title: "Microsoft Security Copilot",
    text: "Custom MCP plugin template keeps Copilot investigations aligned with human analysts, claims and server-enforced approvals.",
    to: "/AGENTS/"
  },
  {
    title: "Microsoft Entra Agent ID",
    text: "Strips Board.Approve and Board.Admin from app-only JWTs; disabling a principal immediately releases open claims and stops webhooks.",
    to: "/guides/10-connecting-ai-agents/"
  },
  {
    title: "Threat Model (TM-01–TM-26)",
    text: "STRIDE + OWASP LLM/Agentic + MITRE ATLAS + ASD ISM threat model covering prompt injection, KQL plugins, IPv6 SSRF and secret leaks.",
    to: "/THREAT-MODEL/"
  }
];

const PACKS = [
  { name: "Complete Walkthroughs Handbook (Chapters 00–12)", online: "/guides/00-overview/", pdf: "/Blueboard-Walkthrough-Guides.pdf", docx: "/Blueboard-Walkthrough-Guides.docx" },
  { name: "Walkthrough 12 · Sentinel MCP, Purview & Defender", online: "/guides/12-sentinel-mcp-purview-and-defender/", pdf: "/Blueboard-Walkthrough-12-Sentinel-MCP-Microsoft-Purview-And-Defender.pdf", docx: "/Blueboard-Walkthrough-12-Sentinel-MCP-Microsoft-Purview-And-Defender.docx" },
  { name: "Security Controls & Traceability", online: "/SECURITY/", pdf: "/Blueboard-Security-Controls.pdf", docx: "/Blueboard-Security-Controls.docx" },
  { name: "Solution Design Document", online: "/design/01-solution-design/", pdf: "/Blueboard-Solution-Design.pdf", docx: "/Blueboard-Solution-Design.docx" },
  { name: "Deployment Guide", online: "/admin/deployment-guide/", pdf: "/Blueboard-Deployment-Guide.pdf", docx: "/Blueboard-Deployment-Guide.docx" },
  { name: "Administrator SOPs (01–14)", online: "/admin/admin-sops/", pdf: "/Blueboard-Admin-SOPs.pdf", docx: "/Blueboard-Admin-SOPs.docx" },
  { name: "Developer Guide", online: "/admin/developer-guide/", pdf: "/Blueboard-Developer-Guide.pdf", docx: "/Blueboard-Developer-Guide.docx" }
];

function QuickStartTabs() {
  const [active, setActive] = useState(0);
  const current = COMMANDS[active];
  return (
    <div className={styles.quickStart}>
      <div role="tablist" aria-label="Quick start commands" className={styles.tabs}>
        {COMMANDS.map((cmd, idx) => (
          <button
            key={cmd.id}
            role="tab"
            type="button"
            aria-selected={idx === active}
            className={idx === active ? styles.tabActive : styles.tab}
            onClick={() => setActive(idx)}
          >
            {cmd.label}
          </button>
        ))}
      </div>
      <CodeBlock language={current.language}>{current.code}</CodeBlock>
      <Link className={styles.quickGuide} to={current.to}>
        {current.linkText}
      </Link>
    </div>
  );
}

export default function Home() {
  const bannerUrl = useBaseUrl("/img/blueboard-banner.png");
  const archUrl = useBaseUrl("/architecture/azure-architecture.png");
  const basePath = useBaseUrl("/");

  return (
    <Layout
      title="blueboard · Human-gated Microsoft SOC control plane"
      description="Shared SOC noticeboard and human-approved action broker for Microsoft Defender XDR, Sentinel, Purview, Security Copilot and autonomous agents."
    >
      <main className={styles.home}>
        <section className={styles.hero}>
          <div className={styles.heroGlow} aria-hidden="true" />
          <div className={styles.heroInner}>
            <p className={styles.pill}>Version 2.1 · Built in Australian English for Australia East &amp; Southeast</p>
            <h1>
              AI speed for triage.
              <span>Human custody for containment.</span>
            </h1>
            <p className={styles.heroLede}>
              blueboard lets Microsoft Sentinel MCP, Security Copilot, and autonomous SOC agents investigate
              Defender XDR and Purview incidents over MCP — without ever holding write credentials or
              executing destructive actions without human approval.
            </p>
            <div className={styles.ctas}>
              <Link className={styles.primary} to="/DEMO/">
                Run 2-Minute Local Demo
              </Link>
              <Link className={styles.secondary} to="/WHAT-IS-BLUEBOARD/">
                Plain-English Overview
              </Link>
              <Link className={styles.ghost} to="/INTEGRATIONS/">
                Sentinel MCP &amp; Purview Guide -&gt;
              </Link>
            </div>

            <div className={styles.bannerWrap}>
              <img
                src={bannerUrl}
                alt="blueboard — human-gated Microsoft SOC control plane"
                className={styles.banner}
              />
            </div>

            <QuickStartTabs />
          </div>
        </section>

        <section className={styles.strip} aria-label="Platform capabilities">
          <div>
            <strong>31</strong>
            <span>Single-schema MCP tools</span>
          </div>
          <div>
            <strong>21</strong>
            <span>Human-gated response actions</span>
          </div>
          <div>
            <strong>10</strong>
            <span>Bundled SOC playbooks</span>
          </div>
          <div>
            <strong>19</strong>
            <span>PDF &amp; Word offline packs</span>
          </div>
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHead}>
            <p className={styles.eyebrow}>Understand blueboard in 30 seconds</p>
            <h2>Separation of duties from alert ingest to execution</h2>
            <p className={styles.lede}>
              Agents treat every alert field, command line and threat feed as attacker-controlled data.
              Only the broker’s managed identity can write — after policy and a different human approve.
            </p>
          </div>
          <ol className={styles.stages}>
            {STAGES.map((stage) => (
              <li key={stage.n}>
                <div className={styles.stageN}>{stage.n}</div>
                <h3>{stage.name}</h3>
                <p>{stage.text}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHead}>
            <p className={styles.eyebrow}>Microsoft 2026 Agentic SOC Ecosystem</p>
            <h2>Built to complement Sentinel, Purview, Defender &amp; Copilot</h2>
          </div>
          <div className={styles.cards}>
            {ECOSYSTEM.map((card) => (
              <Link key={card.title} to={card.to} className={styles.card}>
                <div>
                  <h3>{card.title}</h3>
                  <p>{card.text}</p>
                </div>
                <span className={styles.more}>Read documentation -&gt;</span>
              </Link>
            ))}
          </div>
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHead}>
            <p className={styles.eyebrow}>Reference Architecture</p>
            <h2>One Australian Azure region, secretless end to end</h2>
            <p className={styles.lede}>
              React SPA on App Service, .NET 10 isolated Azure Functions for MCP &amp; Broker, PostgreSQL 16,
              and optional Sentinel BlueboardAudit_CL export.
            </p>
          </div>
          <img
            src={archUrl}
            alt="blueboard Azure architecture diagram"
            className={styles.banner}
          />
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHead}>
            <p className={styles.eyebrow}>Offline Packs</p>
            <h2>Download formatted PDF &amp; Word handbooks</h2>
            <p className={styles.lede}>
              Rebuilt automatically from the repository Markdown sources with Pandoc and WeasyPrint.
            </p>
          </div>
          <div className={styles.packsWrap}>
            <table className={styles.packs}>
              <thead>
                <tr>
                  <th>Document Pack</th>
                  <th>Online</th>
                  <th>Downloads</th>
                </tr>
              </thead>
              <tbody>
                {PACKS.map((pack) => (
                  <tr key={pack.name}>
                    <td>{pack.name}</td>
                    <td>
                      <Link to={pack.online}>Read online</Link>
                    </td>
                    <td>
                      <div className={styles.packLinks}>
                        <a href={`${basePath.replace(/\/$/, "")}${pack.pdf}`}>PDF</a>
                        <a href={`${basePath.replace(/\/$/, "")}${pack.docx}`}>Word (.docx)</a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className={styles.final}>
          <h2>Ready to rehearse your first incident?</h2>
          <p>
            Launch the local Docker demo in two minutes or inspect the full walkthroughs and threat model.
          </p>
          <div className={styles.ctas}>
            <Link className={styles.primary} to="/guides/00-overview/">
              Start Walkthroughs (00–12)
            </Link>
            <Link className={styles.secondary} to="/THREAT-MODEL/">
              Review Threat Model
            </Link>
          </div>
        </section>
      </main>
    </Layout>
  );
}
