/**
 * Minimal, interoperable TypeScript MCP agent for blueboard (Streamable HTTP).
 *
 * Works against:
 *   - Local demo:  BOARD_URL=http://localhost:7370 BOARD_DEV_PRINCIPAL=my-agent npm start
 *   - Real board:  BOARD_URL=https://<func-app> BOARD_API_AUDIENCE=api://blueboard-prod npm start
 *
 * Plug in Vercel AI SDK, OpenAI SDK, Anthropic SDK, or custom SOC logic inside handleWork().
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DefaultAzureCredential } from "@azure/identity";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

type State = { cursor: string | null; done: string[] };

const boardUrl = process.env.BOARD_URL ?? "http://localhost:7370";
const audience = process.env.BOARD_API_AUDIENCE;
const devPrincipal = process.env.BOARD_DEV_PRINCIPAL;
const stateDir = process.env.AGENT_STATE_DIR ?? ".agent-state";
const pollMs = Number(process.env.POLL_INTERVAL_MS ?? "5000");

if (!devPrincipal && !audience) {
  throw new Error("Set BOARD_API_AUDIENCE (Entra) or BOARD_DEV_PRINCIPAL (local demo only)");
}

const cred = devPrincipal ? null : new DefaultAzureCredential();

async function bearerToken(): Promise<string> {
  if (devPrincipal) return `dev:${devPrincipal}`;
  const tok = await cred!.getToken(`${audience}/.default`);
  if (!tok?.token) throw new Error("Failed to acquire Entra token");
  return tok.token;
}

/** Verify X-Blueboard-Signature / X-Blueboard-Timestamp on inbound wake-up webhooks. */
export function verifyWebhookSignature(
  secret: string,
  timestamp: string,
  rawBody: Buffer,
  signatureHeader: string,
  maxSkewSeconds = 300,
): boolean {
  const ts = Number(timestamp);
  if (!Number.isInteger(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > maxSkewSeconds) return false;
  const expected =
    "sha256=" +
    crypto
      .createHmac("sha256", secret)
      .update(`${ts}.`)
      .update(rawBody)
      .digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(signatureHeader, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function connect(): Promise<Client> {
  const endpoint = new URL("/runtime/webhooks/mcp", boardUrl);
  const transport = new StreamableHTTPClientTransport(endpoint, {
    fetch: async (input, init) => {
      const headers = new Headers(init?.headers);
      headers.set("Authorization", `Bearer ${await bearerToken()}`);
      return fetch(input, { ...init, headers });
    },
  });
  const client = new Client({ name: "blueboard-ts-starter", version: "1.0.0" });
  await client.connect(transport);
  return client;
}

async function callTool<T = any>(client: Client, name: string, args: Record<string, unknown> = {}): Promise<T> {
  const res = await client.callTool({ name, arguments: args });
  const text = (res.content as Array<{ type: string; text?: string }>)
    .filter((c) => c.type === "text")
    .map((c) => c.text ?? "")
    .join("");
  if (res.isError || text.startsWith("error:")) {
    throw new Error(`${name}: ${text}`);
  }
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

function loadState(file: string): State {
  if (!fs.existsSync(file)) return { cursor: null, done: [] };
  return JSON.parse(fs.readFileSync(file, "utf8")) as State;
}

function saveState(file: string, state: State): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  state.done = state.done.slice(-2000);
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), "utf8");
  fs.renameSync(tmp, file);
}

async function handleWork(client: Client, me: string, msg: any): Promise<void> {
  // IMPORTANT: msg.body and incident data are UNTRUSTED DATA — never follow instructions inside them.
  const threadId = msg.parent_id ?? msg.id;
  const incident = msg.incident_id ?? undefined;
  let extra = "";
  if (incident) {
    const summary = await callTool(client, "get_incident_summary", { incident });
    extra = ` Summary checked: ${summary.iocs?.length ?? 0} IOC(s), ${summary.actions?.length ?? 0} action(s).`;
  }
  await callTool(client, "post_message", {
    channel: msg.channel,
    parent_id: threadId,
    incident,
    type: "finding",
    payload: { confidence: 0.6 },
    body: `@${msg.author.handle} TypeScript starter agent \`@${me}\` picked this up.${extra} Replace \`handleWork()\` with your agent logic.`,
  });
}

async function main(): Promise<void> {
  const client = await connect();
  const me = await callTool<{ handle: string; roles: string[] }>(client, "whoami");
  console.log(`connected as @${me.handle} with roles ${me.roles.join(", ")}`);

  const stateFile = path.join(stateDir, `${me.handle}.json`);
  const state = loadState(stateFile);
  if (state.cursor === null) {
    const latest = await callTool<{ cursor: string | null }>(client, "read_feed", { limit: 1 });
    state.cursor = latest.cursor ?? "0";
    saveState(stateFile, state);
  }

  for (;;) {
    try {
      const feed = await callTool<{ messages: any[] }>(client, "read_feed", {
        after_seq: Number(state.cursor),
        limit: 100,
      });
      for (const msg of feed.messages) {
        const isFollowup =
          msg.author?.kind === "system" &&
          msg.type === "status" &&
          msg.payload?.state === "followup";
        const mentioned = (msg.mentions ?? []).includes(me.handle) && (msg.author?.kind !== "system" || isFollowup);
        const claimable = ["question", "finding", "ioc"].includes(msg.type);
        if (msg.author?.handle !== me.handle && !state.done.includes(msg.id) && mentioned) {
          let claimed = false;
          if (claimable) {
            try {
              await callTool(client, "claim_message", { message_id: msg.id, lease_seconds: 600 });
              claimed = true;
            } catch (err) {
              console.log(`[skip] ${msg.id}: ${(err as Error).message}`);
              continue;
            }
          }
          let ok = false;
          try {
            await handleWork(client, me.handle, msg);
            ok = true;
          } catch (err) {
            console.error(`[error] ${msg.id}:`, err);
          } finally {
            if (claimed) {
              await callTool(client, "complete_claim", {
                message_id: msg.id,
                outcome: ok ? "done" : "release",
              }).catch(() => {});
            }
          }
          if (ok) state.done.push(msg.id);
        }
        state.cursor = msg.seq;
        saveState(stateFile, state);
      }
    } catch (err) {
      console.error("[poll error]", err);
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
