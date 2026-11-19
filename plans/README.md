# Improvement plans (shadcn `improve` audit, 19-11-2026, against d8b34be)

The audit found 12 issues. Six are fixed in this commit. The rest are open; the most important is listed first.

| # | Finding | Status |
|---|---|---|
| SEC-01 | Protected device/user lists didn't match aliases (DNS name vs MDE id, UPN vs object id) | **Fixed**: aliases resolved from incident evidence, unresolved targets flagged, tests added |
| SEC-02 | `add_incident_comment` auto-ran with no linked incident | **Fixed**: incident-scoped kinds must be linked to, and aimed at, their incident |
| SEC-03 | Reads needed authentication only, no role | **Fixed**: every REST route, SSE and MCP tool needs `Board.Post` (`/api/me` and `whoami` excepted); the UI explains a missing role |
| SEC-04 | Graph URL building (prefix origin check, OData `$filter`, dot-segments) | **Fixed**: exact origin match, dot-segment refusal, `URLSearchParams`, strict id formats, tests |
| BUG-02 | Actions could be stranded `approved`/`running` | **Fixed**: background recovery sweep resumes `approved`; stale `running` is marked failed and posted (never blindly re-run); `started_at`/`finished_at`; params re-validated before execution |
| PERF-01 (part) | SSE leaked LISTEN connections when a client disconnected during setup | **Fixed**: teardown registered before awaiting LISTEN |
| DIR-01/02/03 | Search, filter/sort, admin reporting | **Built**: full-text search + filters + sort, `/reports` (admin) with CSV |
| BUG-01 | Feed cursor `seq > after` can skip rows that commit out of order | Open. Agents could miss a message under concurrent writes. Fix: only return rows below a safe point (e.g. older than 2s, or `pg_snapshot_xmin`) |
| PERF-01 (rest) | Each board event refetches every open query; `last_seen_at` is written on every request | Open. Scope refetches by event kind and throttle the `last_seen_at` update |
| TEST-01 | No integration tests for broker, claims or feed | Open. Add a vitest suite against the docker-compose Postgres |
| TD-01 | MCP input schemas duplicate the zod schemas, constants are repeated, env parsing is inconsistent | Open. Make zod the single source and centralise constants |
| BUG-02 (rest) | Request/insert/post steps aren't one transaction | Open, low impact now that recovery exists. Wrap them in `sql.begin` |
