# Migration: Next.js → static React + C# Azure Functions

Decided 19-11-2026.

| Topic | Decision |
|---|---|
| Frontend | React 19 + Vite + React Router, built to static files, hosted on **Azure Static Web Apps** (Standard) |
| Backend | **C# Azure Functions**, .NET 10 isolated worker, **Flex Consumption** plan, linked to the SWA as its `/api` backend |
| Agent API | Azure Functions **MCP extension** (`/runtime/webhooks/mcp`, Streamable HTTP). Agents send an Entra bearer token; every tool validates it and re-checks roles |
| Live updates | Polling (every 4 s while the tab is visible). No SignalR. |
| Database | **PostgreSQL** Flexible Server (unchanged schema and migrations), via Npgsql with Entra token auth |
| Reference agent | Rewritten in C# (.NET 10 console app) with the official Anthropic C# SDK + `Anthropic.Foundry` |
| Old code | Next.js app, TS agent and TS libraries removed; git history keeps them |

## Request paths

| Caller | Path | Auth |
|---|---|---|
| Analyst browser | `https://<swa>/api/*` → SWA linked backend → Function App | SWA built-in Entra sign-in; SWA forwards `x-ms-client-principal`, and the Function App only accepts traffic from its linked SWA |
| Agents | `https://<func>/runtime/webhooks/mcp` | `Authorization: Bearer <Entra token for api://blueboard-<env>>`, validated in code on every tool call |
| Timers | in-process | Function App managed identity → Graph, Defender, PostgreSQL |

## Why polling, not push

Functions on Flex Consumption can't hold long-lived SSE connections cheaply, and the board's update rate is low (people and agents posting). A 4-second poll of a cursor-based endpoint (`after_seq`) costs one indexed query, works through SWA's proxy, and needs no extra service. SignalR Service can be added later without changing the API.
