import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import { themes as prismThemes } from "prism-react-renderer";
import sourceLinks from "./plugins/remark-source-links.mjs";

const darkCode = {
  ...prismThemes.nightOwl,
  styles: prismThemes.nightOwl.styles.map((entry) =>
    entry.types.includes("comment") ? { ...entry, style: { ...entry.style, color: "rgb(137, 160, 160)" } }
    : entry.types.includes("deleted") ? { ...entry, style: { ...entry.style, color: "rgb(239, 115, 112)" } }
    : entry)
};

const config: Config = {
  title: "blueboard",
  tagline: "Human-gated Microsoft SOC control plane for Defender XDR, Sentinel, Purview & autonomous agents.",
  favicon: "img/blueboard-mark.svg",
  url: "https://jusso-dev.github.io",
  baseUrl: "/blueboard/",
  organizationName: "jusso-dev",
  projectName: "blueboard",
  trailingSlash: true,
  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",
  onDuplicateRoutes: "throw",
  future: { v4: { removeLegacyPostBuildHeadAttribute: true, useCssCascadeLayers: true }, faster: false },
  i18n: { defaultLocale: "en-AU", locales: ["en-AU"] },
  markdown: {
    format: "detect",
    mermaid: true,
    hooks: { onBrokenMarkdownLinks: "throw", onBrokenMarkdownImages: "throw" }
  },
  plugins: ["./plugins/docs-files.mjs"],
  themes: [
    "@docusaurus/theme-mermaid",
    [
      "@easyops-cn/docusaurus-search-local",
      {
        hashed: true,
        language: ["en"],
        docsDir: "../docs",
        docsRouteBasePath: "/",
        indexBlog: false,
        indexPages: true,
        highlightSearchTermsOnTargetPage: true,
        searchResultLimits: 10,
        explicitSearchResultPath: true
      }
    ]
  ],
  presets: [
    [
      "classic",
      {
        docs: {
          path: "../docs",
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
          editUrl: ({ docPath }) => `https://github.com/jusso-dev/blueboard/edit/main/docs/${docPath}`,
          exclude: ["**/_*.md"],
          showLastUpdateTime: false,
          numberPrefixParser: false,
          beforeDefaultRemarkPlugins: [sourceLinks]
        },
        blog: false,
        theme: { customCss: "./src/css/custom.css" }
      } satisfies Preset.Options
    ]
  ],
  themeConfig: {
    image: "img/blueboard-banner.png",
    colorMode: { defaultMode: "dark", respectPrefersColorScheme: true },
    docs: { sidebar: { hideable: true, autoCollapseCategories: true } },
    tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
    announcementBar: {
      id: "human-gated-containment-21",
      content:
        'Version 2.1: Now integrates Microsoft Sentinel MCP, Purview DLP/IRM &amp; processContent, Security Copilot and Entra Agent ID. <a href="/blueboard/INTEGRATIONS/">Read the integration guide</a>.',
      isCloseable: true
    },
    navbar: {
      title: "blueboard",
      logo: { alt: "", src: "img/blueboard-mark.svg" },
      hideOnScroll: false,
      items: [
        { type: "docSidebar", sidebarId: "startHere", position: "left", label: "Start Here" },
        { type: "docSidebar", sidebarId: "guides", position: "left", label: "Walkthroughs" },
        { type: "docSidebar", sidebarId: "agentsAndPolicy", position: "left", label: "Agents & Policy" },
        { type: "docSidebar", sidebarId: "security", position: "left", label: "Trust & Security" },
        { type: "docSidebar", sidebarId: "operations", position: "left", label: "Deploy & Ops" },
        { href: "https://github.com/jusso-dev/blueboard", position: "right", className: "header-github-link", "aria-label": "blueboard on GitHub" }
      ]
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Start",
          items: [
            { label: "Visual Walkthrough", to: "/WALKTHROUGH/" },
            { label: "What is blueboard?", to: "/WHAT-IS-BLUEBOARD/" },
            { label: "Azure Quickstart", to: "/QUICKSTART-AZURE/" },
            { label: "2-Minute Local Demo", to: "/DEMO/" },
            { label: "Sentinel MCP & Purview", to: "/INTEGRATIONS/" },
            { label: "Walkthroughs 00–12", to: "/guides/00-overview/" }
          ]
        },
        {
          title: "Governance & Agents",
          items: [
            { label: "Connecting AI Agents", to: "/AGENTS/" },
            { label: "Action Policy", to: "/POLICY/" },
            { label: "Response Playbooks", to: "/PLAYBOOKS/" },
            { label: "Threat Intel & CVE Exposure", to: "/THREAT_INTEL/" }
          ]
        },
        {
          title: "Security & Architecture",
          items: [
            { label: "Trust Center", to: "/assurance/TRUST-CENTER/" },
            { label: "Security Architecture", to: "/SECURITY/" },
            { label: "Threat Model (TM-01–TM-60)", to: "/THREAT-MODEL/" },
            { label: "Azure Architecture", to: "/architecture/" },
            { label: "Solution Design", to: "/design/01-solution-design/" }
          ]
        },
        {
          title: "Project",
          items: [
            { label: "GitHub Repository", href: "https://github.com/jusso-dev/blueboard" },
            { label: "Administrator SOPs", to: "/admin/admin-sops/" },
            { label: "Deployment Guide", to: "/DEPLOYMENT/" },
            { label: "Licence (MIT)", href: "https://github.com/jusso-dev/blueboard/blob/main/LICENSE" }
          ]
        }
      ],
      copyright: "blueboard · Human-gated Microsoft SOC control plane · MIT licence"
    },
    prism: {
      theme: prismThemes.vsLight,
      darkTheme: darkCode,
      additionalLanguages: ["bash", "powershell", "json", "yaml", "kusto", "csharp", "python", "typescript", "diff"]
    },
    mermaid: { theme: { light: "neutral", dark: "dark" } }
  } satisfies Preset.ThemeConfig
};

export default config;
