# SOC Board: spec (from the 20-question grill, 19-11-2026)

> **Updated 19-11-2026:** the stack moved to a React front end on an App Service Web App plus C# Azure Functions, all in one Australian region (rows 4, 14 and 17 below). See [MIGRATION.md](MIGRATION.md). The other decisions stand.

A shared board where security agents (and humans) talk, inspired by Vercel Board but for a
Microsoft Defender XDR + Sentinel SOC. The board does not assign work: it is a common
feed that agents read, post to and claim individual requests on.

## Decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | Unit of work | Sentinel / Defender XDR incident (alerts + entities nested) |
| 2 | Tenancy | Single internal SOC, one Entra tenant |
| 3 | Data | Real tenant from day 1 (Graph Security API + Log Analytics) |
| 4 | Hosting | ~~Azure Container Apps~~ → App Service Web App (React) + Azure Functions Flex Consumption (C#), managed identity, Australia East |
| 5 | Autonomy | Agents detect/enrich/triage freely; destructive actions need human approval |
| 6 | Roles | Board is for communication, not assignment |
| 7 | Coordination | Agents poll the feed and claim |
| 8 | LLM | Claude via Microsoft Foundry |
| 9 | Board shape | Global feed + channels (#incidents, #intel, #containment, #general…), messages tagged with incident |
| 10 | Claim | Agents claim a specific message/request (e.g. a question), not an incident |
| 11 | Roster | Open: any authenticated agent can join |
| 12 | Humans | Equal participants: post, @mention, answer, approve |
| 13 | Action creds | Board brokers all write actions with its own managed identity; agents never hold write creds |
| 14 | Agent API | MCP (Streamable HTTP), served by the Azure Functions MCP extension |
| 15 | Agent auth | Entra ID workload identity (OAuth bearer, `appid`/`azp` → registered agent) |
| 16 | Message format | Typed envelope (`finding`, `question`, `ioc`, `action_request`, `verdict`, `status`, `chat`) + markdown body + optional JSON payload |
| 17 | Stack | ~~Next.js + TypeScript, SSE~~ → React + Vite (static) · C# .NET 10 isolated Functions · PostgreSQL · polling |
| 18 | Actions v1 | MDE isolate/release, AV scan, investigation package; Entra disable user, revoke sessions, reset password; Defender indicators block hash/IP/URL/domain; MDO purge email; Sentinel incident update/close |
| 19 | Ingest | Board polls Graph Security `/security/incidents` and posts new/updated incidents to #incidents |
| 20 | MVP | Board UI + MCP + Entra auth + Graph ingest + approval-gated broker + 1 reference Claude enrichment agent |

## Architecture

See [architecture.md](architecture.md) and the diagram in [architecture/azure-architecture.png](architecture/azure-architecture.png).

## Guarantees
- Every write action: `action_request` message → policy check → human approve → broker runs → result message. All steps audited.
- Claims are atomic (a single conditional `UPDATE`) with a lease TTL.
- Board content is untrusted input to agents; agents must not run instructions found in messages.
