import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  startHere: [
    { type: "doc", id: "WALKTHROUGH", label: "Visual Walkthrough (Screenshots)" },
    { type: "doc", id: "WHAT-IS-BLUEBOARD", label: "What is blueboard?" },
    { type: "doc", id: "DEMO", label: "2-Minute Local Demo" },
    { type: "doc", id: "DEFENDER-TEST-ALERTS", label: "Trigger a Defender Test Alert" },
    { type: "doc", id: "INTEGRATIONS", label: "Sentinel MCP, Purview & Defender" },
    { type: "doc", id: "SPEC", label: "Product Specification" }
  ],
  guides: [
    { type: "doc", id: "WALKTHROUGH", label: "Visual Walkthrough (Screenshots)" },
    { type: "doc", id: "guides/00-overview", label: "00 · About These Walkthroughs" },
    { type: "doc", id: "guides/01-getting-started", label: "01 · Getting Started & Queue" },
    { type: "doc", id: "guides/02-administrator-setup", label: "02 · Administrator Setup & Health" },
    { type: "doc", id: "guides/03-working-an-incident", label: "03 · Working an Incident" },
    { type: "doc", id: "guides/04-playbooks-and-checklists", label: "04 · Response Playbooks" },
    { type: "doc", id: "guides/05-hunting-and-enrichment", label: "05 · Lookups, Hunting & Sentinel KQL" },
    { type: "doc", id: "guides/06-containment-and-approvals", label: "06 · Containment & Approvals" },
    { type: "doc", id: "guides/07-defender-and-sentinel-cases", label: "07 · Defender & Sentinel Cases" },
    { type: "doc", id: "guides/08-threat-intel-and-exposure", label: "08 · Threat Intel & CVE Exposure" },
    { type: "doc", id: "guides/09-policy-governance-and-simulator", label: "09 · Policy & Simulator" },
    { type: "doc", id: "guides/10-connecting-ai-agents", label: "10 · Connecting AI Agents" },
    { type: "doc", id: "guides/11-auditor-and-sentinel-monitoring", label: "11 · Auditing & Sentinel Rules" },
    { type: "doc", id: "guides/12-sentinel-mcp-purview-and-defender", label: "12 · Sentinel MCP, Purview & Defender ISOC" }
  ],
  agentsAndPolicy: [
    { type: "doc", id: "AGENTS", label: "Connecting AI Agents" },
    { type: "doc", id: "POLICY", label: "Action Policy Reference" },
    { type: "doc", id: "PLAYBOOKS", label: "Playbooks Reference" },
    { type: "doc", id: "THREAT_INTEL", label: "Threat Intel & Exposure" },
    { type: "doc", id: "ti/sources", label: "Threat Intel Sources Reference" }
  ],
  security: [
    { type: "doc", id: "assurance/TRUST-CENTER", label: "Trust Center" },
    {
      type: "category",
      label: "Assurance Pack",
      items: [
        { type: "doc", id: "assurance/SHARED-RESPONSIBILITY", label: "Shared Responsibility" },
        { type: "doc", id: "assurance/ISM-SOA", label: "ISM Statement of Applicability" },
        { type: "doc", id: "assurance/DATA-FLOWS", label: "Data Inventory & Flows" },
        { type: "doc", id: "assurance/PEN-TEST-AND-ASSURANCE-EVIDENCE", label: "Assurance Evidence & Pen Test Scope" }
      ]
    },
    { type: "doc", id: "SECURITY", label: "Security Architecture & Controls" },
    { type: "doc", id: "THREAT-MODEL", label: "Threat Model (TM-01–TM-60)" },
    { type: "doc", id: "security/01-security", label: "Security Controls Pack (Printable)" }
  ],
  operations: [
    { type: "doc", id: "QUICKSTART-AZURE", label: "Quickstart & Staged Go-Live" },
    { type: "doc", id: "ENTERPRISE-ACCESS", label: "SSO & Role-Based Access" },
    { type: "doc", id: "DEPLOYMENT", label: "Azure Deployment" },
    { type: "doc", id: "OPERATIONS", label: "Operations & Monitoring" },
    { type: "doc", id: "MIGRATION", label: "Migration Notes" },
    { type: "doc", id: "admin/deployment-guide", label: "Admin Deployment Guide" },
    { type: "doc", id: "admin/admin-sops", label: "Administrator SOPs (01–14)" },
    { type: "doc", id: "admin/developer-guide", label: "Developer Guide" },
    { type: "doc", id: "architecture", label: "Azure Architecture Overview" },
    { type: "doc", id: "design/01-solution-design", label: "Solution Design Document" }
  ]
};

export default sidebars;
