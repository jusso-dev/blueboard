# Migration: Next.js → React + C# Azure Functions, in Australia

Decided 19-11-2026. Front-end hosting revised the same day: everything must run in Australia, and Azure Static Web Apps has no Australian region, so the React app moved to an App Service Web App in the same region as the rest.

| Topic | Decision |
|---|---|
| Region | One Australian region for every resource: `australiaeast` (default) or `australiasoutheast`. Bicep and `deploy.sh` refuse others |
| Front end | React 19 + Vite + React Router, served by a small ASP.NET Core host (`web/host`) on an **App Service Web App** (Linux, .NET 10). The host adds CSP and HSTS and serves `/config.json`; it has no identity and no data access |
| Sign-in | **MSAL in the browser** (auth code + PKCE) against the board's app registration, scope `Board.Access`. No client secret, no cookies |
| Back end | **C# Azure Functions**, .NET 10 isolated worker, **Flex Consumption**. Browsers call it directly with a bearer token; CORS allows only the web origin |
| Agent API | Azure Functions **MCP extension** (`/runtime/webhooks/mcp`, Streamable HTTP). Agents send an Entra bearer token; every tool validates it and re-checks roles |
| Live updates | Polling (every 4 s while the tab is visible). No SignalR. |
| Database | **PostgreSQL** Flexible Server (unchanged schema and migrations), via Npgsql with Entra token auth |
| Reference agent | C# (.NET 10) with the official Anthropic C# SDK + `Anthropic.Foundry`. Claude on Foundry isn't offered in an Australian region yet; see [architecture.md § Data residency](architecture.md#data-residency) |
| Old code | Next.js app, TS agent and TS libraries removed; git history keeps them |

## Why not Static Web Apps

Static Web Apps runs in five regions (West US 2, Central US, East US 2, West Europe, East Asia), none in Australia, and its linked-backend model depends on trusting a platform-forwarded identity header. An App Service Web App runs in Australia East, and moving sign-in into the browser means the API trusts one thing only: a validated Entra token.

## Why not Blazor

Blazor (interactive server on the same Web App) would keep the whole stack in C# and keep tokens off the browser. It was considered and not chosen: the React UI was finished and reviewed, Blazor Server needs a held connection per analyst (sticky sessions, more memory per user), and the agent-facing API would still need to be REST and MCP. React plus a static host keeps the front end a set of files the API doesn't depend on.

## Request paths

| Caller | Path | Auth |
|---|---|---|
| Analyst browser | `https://<web>/` for files, then `https://<func>/api/*` | MSAL sign-in; `Authorization: Bearer <delegated token, scope Board.Access>` on every API call |
| Agents | `https://<func>/runtime/webhooks/mcp` | `Authorization: Bearer <app-only token for api://blueboard-<env>>`, validated in code on every tool call |
| Timers | in-process | Function App managed identity → Graph, Defender, PostgreSQL |

## Why polling, not push

Functions on Flex Consumption can't hold long-lived SSE connections cheaply, and the board's update rate is low (people and agents posting). A 4-second poll of a cursor-based endpoint (`after_seq`) costs one indexed query and needs no extra service. SignalR Service can be added later without changing the API.
