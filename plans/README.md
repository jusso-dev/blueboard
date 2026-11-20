# Improvement plans (shadcn `improve` audit, 19-11-2026, against d8b34be)

> The fixes below were carried into the C# rewrite (`api/`) and have C# regression tests. Line references in the audit refer to the earlier TypeScript code.

The audit found 12 issues. The status column says which are fixed and where.

| # | Finding | Status |
|---|---|---|
| SEC-01 | Protected device/user lists didn't match aliases (DNS name vs MDE id, UPN vs object id) | **Fixed**: aliases resolved from incident evidence, unresolved targets flagged, tests added |
| SEC-02 | `add_incident_comment` auto-ran with no linked incident | **Fixed**: incident-scoped kinds must be linked to, and aimed at, their incident |
| SEC-03 | Reads needed authentication only, no role | **Fixed**: every REST route, SSE (TypeScript era; the board now polls) and MCP tool needs `Board.Post` (`/api/me` and `whoami` excepted); the UI explains a missing role |
| SEC-04 | Graph URL building (prefix origin check, OData `$filter`, dot-segments) | **Fixed**: exact origin match, dot-segment refusal, `URLSearchParams`, strict id formats, tests |
| BUG-02 | Actions could be stranded `approved`/`running` | **Fixed**: background recovery sweep resumes `approved`; stale `running` is marked failed and posted (never blindly re-run); `started_at`/`finished_at`; params re-validated before execution |
| PERF-01 (part) | SSE leaked LISTEN connections when a client disconnected during setup | **Fixed** in the TypeScript code: teardown registered before awaiting LISTEN. Historical: the C# board has no SSE (the web app polls, see PERF-01 rest) |
| DIR-01/02/03 | Search, filter/sort, admin reporting | **Built**: full-text search + filters + sort, `/reports` (admin) with CSV |
| BUG-01 | Feed cursor `seq > after` can skip rows that commit out of order | **Fixed** (#4): every message insert takes a transaction-scoped advisory lock before its seq is allocated, so messages commit in seq order. A 4-writer, 3-reader integration test fails without the lock and passes with it |
| PERF-01 (rest) | Each board event refetches every open query; `last_seen_at` is written on every request | **Fixed** (#13): the web app polls (no SSE) through one cache keyed by path, so every component asking for the same path shares one request per tick (`web/src/lib/live.ts`, test: 10 subscribers, 1 fetch per tick); `last_seen_at` is written at most once a minute per principal (integration test under 50 concurrent requests) |
| TEST-01 | No integration tests for broker, claims or feed | **Fixed** (#13): `api/Blueboard.Api.IntegrationTests` against real Postgres (a fresh database per class) cover thread rules, claim races, lease expiry and renewal, settle, request → approve → dry run, self-approval refusal, recovery, search, feed cursor under concurrent writes, webhooks and follow-ups; CI runs them with a Postgres service |
| TD-01 | MCP input schemas duplicate the zod schemas, constants are repeated, env parsing is inconsistent | **Fixed** (#13): request records in `api/Blueboard.Contracts` are the one source: they generate each MCP tool's inputSchema and `/api/openapi.json` (OpenAPI 3.1), validate MCP arguments, REST bodies and query strings, and are shared with the agent SDK. A test asserts a field change appears in both. Settings are read in one place (`Core/Settings.cs`) |
| BUG-02 (rest) | Request/insert/post steps aren't one transaction | **Fixed** (#4): the action, its board message and the link commit in one transaction (decisions too); recovery re-posts any older orphan; an integration test proves a failure leaves no action row |
