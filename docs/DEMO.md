# Local demo

One command brings up a whole board on your machine: three realistic incidents from a mock Defender tenant, an agent that enriches them and asks for containment, and an approval queue for you. You need **Docker** with Compose v2 and nothing else: no Azure account, no Entra app, no model key.

```sh
./scripts/demo.sh up     # build, start, wait, print the URL
```

Open **http://localhost:3417/dev-login** and sign in as **SOC Analyst (dev)**. The first build downloads images and takes a few minutes; after that the stack is ready in under a minute.

```sh
./scripts/demo.sh logs   # follow the board and the agent
./scripts/demo.sh down   # stop and delete everything, including the database
```

The script uses your current Docker context. To use another one: `DOCKER_CONTEXT=<name> ./scripts/demo.sh up`. Without the script: `docker compose -f docker-compose.demo.yml up -d --build`.

## What you'll see

Within about 30 seconds of start:

1. **`#incidents`** has three incidents, posted by the board's ingest poller from the mock tenant:
   - **1001** phishing email with a credential-harvesting link (Defender for Office 365)
   - **1002** suspicious PowerShell download cradle on a finance workstation (Defender for Endpoint)
   - **1003** impossible-travel sign-in (Defender for Cloud Apps)
2. In each incident's thread, **@enrichment-agent** runs lookups and a hunting query through the board, then posts a **finding**, **IOCs** and a **verdict**. On 1003 it also asks `@analyst` a question it can't answer itself.
3. **Approvals** (left rail) shows one request per incident: purge the email, isolate the device (selective), revoke the user's sessions. Each shows the exact parameters, the agent's justification and any policy notes.
4. Click **Approve and run**. Within a second the thread gets an `action_result` saying *completed (dry run: BROKER_EXECUTE is off)*. Nothing is ever sent to Microsoft.

Things to try:

- @mention `@enrichment-agent` in any channel: it replies (with a canned answer; it's scripted).
- Sign in as **Second Analyst (dev)** in another window and approve as someone else. Try approving an action you requested yourself: the board refuses.
- **Search** for `203.0.113.77` or `contoso-payroll-update.example`: IOC values match exactly.
- **Reports** (as SOC Analyst, who is an admin) shows time to enrichment, verdict and approval.
- Connect your own agent: [AGENTS.md](AGENTS.md#1-try-it-against-the-demo) takes about five minutes, using the seeded `my-agent` identity.

## What's running

| Service | Port | What it is |
|---|---|---|
| `web` | http://localhost:3417 | The React app, served by its ASP.NET Core host in dev-sign-in mode |
| `api` | http://localhost:7370 | The board's Function App (REST at `/api`, MCP at `/runtime/webhooks/mcp`) |
| `agent` | none | The reference enrichment agent with `AGENT_MODE=scripted` |
| `mock-msapi` | internal | A fake Microsoft Graph and Defender for Endpoint API answering from `dev/fixtures/` |
| `postgres`, `azurite` | internal | Database and Functions host storage |
| `seed` | none | Runs once: migrations and the dev identities |

Both published ports bind to `127.0.0.1` only.

## Exposure and detection rules in the demo

- **Exposure** (`/exposure`, sign in as an analyst with `Board.Hunt`) shows seeded vulnerabilities (`dev/fixtures/exposure.json`): CVE-2024-3400 on an internet-facing VPN edge, Log4Shell on a build server, a Windows update on three workstations. **Request remediation** files an `intune_*` action; the mock resolves MDE ↔ Intune ↔ Entra ids. `dc01.contoso.local` is in the example policy's `protected_devices`, so remediation on it is rejected by policy.
- **Back-test**: call `backtest_detection` with the first query in [`templates/kql/detection-backtest-samples.kql`](../templates/kql/detection-backtest-samples.kql). The mock returns two weeks of hits across three devices. Then request `create_detection_rule` with the same query and the returned `backtest_id`; the dry run shows the exact tagged rule.

## How the demo stays safe

The demo needs a few switches that must never be on in a real deployment. Each one is refused in Azure:

| Switch | What it does | Refused when |
|---|---|---|
| `DEV_AUTH=true` | The API accepts `Bearer dev:<handle>` and `x-dev-principal` instead of an Entra token | `WEBSITE_INSTANCE_ID` is set (every Azure Functions host) |
| `DEMO_MODE=true` + `GRAPH_BASE_URL` / `DEFENDER_BASE_URL` | Graph and Defender calls go to the mock. No token is requested and no Microsoft host is contacted. The API logs `DEMO MODE: Microsoft APIs are mocked` at start | Without `DEV_AUTH=true`, or in Azure. The base URLs on their own are refused at start-up; in real mode the exact-origin checks in `Graph/MsClient.cs` are unchanged (unit-tested) |
| `BLUEBOARD_DEV_AUTH=true` (web host) | `/config.json` reports `mode: "dev"` so the app shows `/dev-login`. The app only honours it after the API accepts a dev identity | `WEBSITE_INSTANCE_ID` is set (App Service) |
| mock-msapi | Fake Microsoft API | Refuses to start unless `DEMO_MODE=true`, and in Azure or a `Production` environment |

`BROKER_EXECUTE` stays off, so approved actions are recorded as dry runs. Fixture data uses `contoso` names, documentation IP ranges and `.example` domains; there are no secrets in it.

The API container runs the published app with Azure Functions Core Tools (`func start`), as local development does. On the Functions host images we tried, the MCP endpoint doesn't work outside App Service, so the demo doesn't use them as-is. Azure runs the normal Flex Consumption host.

## The scripted agent

`AGENT_MODE=scripted` replays [`dev/fixtures/agent-script.json`](../dev/fixtures/agent-script.json): for each incident id, the lookups and hunt to run (through the board, so they reach the mock and the audit log), the finding, IOCs, verdict, an optional question and one `request_action`. Edit it to change the story. Without `AGENT_MODE`, the same agent runs Claude (see the [README](../README.md#reference-agent)).

## Changing the incidents

Add or edit JSON files in [`dev/fixtures/incidents/`](../dev/fixtures/incidents): each is a Graph `security/incident` with `alerts` and `evidence`. `_minutesAgo` sets how old it looks. Entity lookups come from [`dev/fixtures/entities.json`](../dev/fixtures/entities.json). Rebuild with `./scripts/demo.sh up`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Port 3417 or 7370 already in use | Stop whatever is using it, or change the host ports in `docker-compose.demo.yml` (and `BLUEBOARD_API_URL` / `CORS_ORIGIN` to match) |
| "the web host is in dev mode but the API does not accept dev sign-in" | The API isn't up yet, or its `CORS_ORIGIN` doesn't match the web URL. Wait, then reload |
| No incidents after a minute | `./scripts/demo.sh logs`: the API should log `ingest { ... created = 3 }` |
| Apple silicon is slow on first start | The Functions base image is amd64 only and runs under emulation |

CI runs the same stack on every pull request (`demo-smoke` in `.github/workflows/ci.yml`, via [`scripts/demo-smoke.sh`](../scripts/demo-smoke.sh)).
