import { config } from "../config";
import { sql } from "../db";
import { postMessage } from "../board";
import type { Principal } from "../types";
import { GRAPH, msFetch } from "./client";
import { extractEntities } from "./entities";

/** Shape of a Graph security incident (subset we use). */
export type GraphIncident = {
  id: string;
  displayName: string;
  severity: string;
  status: string;
  classification?: string;
  determination?: string;
  assignedTo?: string | null;
  incidentWebUrl?: string;
  createdDateTime?: string;
  lastUpdateDateTime?: string;
  alerts?: { id: string; title?: string; severity?: string; serviceSource?: string; evidence?: Record<string, any>[]; mitreTechniques?: string[] }[];
};

type Page = { value: GraphIncident[]; "@odata.nextLink"?: string };

const CURSOR_KEY = "ingest.lastUpdateDateTime";

export async function boardPrincipal(): Promise<Principal> {
  const [p] = await sql<Principal[]>`select id, handle, display_name, kind, roles from principals where handle = 'board'`;
  if (!p) throw new Error("board system principal missing; run migrations");
  return p;
}

async function getCursor(): Promise<string> {
  const [row] = await sql<{ value: string }[]>`select value from kv_state where key = ${CURSOR_KEY}`;
  if (row) return row.value;
  return new Date(Date.now() - config().INGEST_LOOKBACK_HOURS * 3600_000).toISOString();
}

async function setCursor(value: string) {
  await sql`insert into kv_state (key, value) values (${CURSOR_KEY}, ${sql.json(value)})
            on conflict (key) do update set value = excluded.value, updated_at = now()`;
}

export async function fetchUpdatedIncidents(since: string): Promise<GraphIncident[]> {
  const filter = encodeURIComponent(`lastUpdateDateTime gt ${since}`);
  let next: string | undefined = `/v1.0/security/incidents?$filter=${filter}&$expand=alerts&$top=50&$orderby=lastUpdateDateTime asc`;
  const out: GraphIncident[] = [];
  while (next && out.length < 500) {
    const page: Page = await msFetch<Page>(GRAPH, next);
    out.push(...page.value);
    next = page["@odata.nextLink"];
  }
  return out;
}

function summarise(inc: GraphIncident) {
  const e = extractEntities(inc);
  const parts = [
    e.devices.length && `${e.devices.length} device(s): ${e.devices.map((d) => d.name ?? d.mdeDeviceId).slice(0, 5).join(", ")}`,
    e.users.length && `${e.users.length} user(s): ${e.users.map((u) => u.upn ?? u.name).slice(0, 5).join(", ")}`,
    e.ips.length && `${e.ips.length} IP(s)`,
    e.files.length && `${e.files.length} file(s)`,
    e.emails.length && `${e.emails.length} email(s)`,
    e.mitre.length && `MITRE ${e.mitre.slice(0, 6).join(", ")}`,
  ].filter(Boolean);
  return { entities: e, line: parts.join(" · ") };
}

/**
 * Upsert one incident and announce it in #incidents. New incidents get a root `incident` message;
 * meaningful changes (status, severity, alert count, classification) get a `status` reply on that thread.
 */
export async function upsertIncident(inc: GraphIncident, board: Principal) {
  const alertCount = inc.alerts?.length ?? 0;
  const [prev] = await sql<{ id: string; severity: string; status: string; alert_count: number; classification: string | null }[]>`
    select id, severity, status, alert_count, classification from incidents where graph_id = ${inc.id}`;
  const [row] = await sql<{ id: string }[]>`
    insert into incidents (graph_id, display_name, severity, status, classification, determination, assigned_to,
                           alert_count, web_url, created_at_src, updated_at_src, data, last_synced_at)
    values (${inc.id}, ${inc.displayName}, ${inc.severity}, ${inc.status}, ${inc.classification ?? null},
            ${inc.determination ?? null}, ${inc.assignedTo ?? null}, ${alertCount}, ${inc.incidentWebUrl ?? null},
            ${inc.createdDateTime ?? null}, ${inc.lastUpdateDateTime ?? null}, ${sql.json(inc as never)}, now())
    on conflict (graph_id) do update set
      display_name = excluded.display_name, severity = excluded.severity, status = excluded.status,
      classification = excluded.classification, determination = excluded.determination,
      assigned_to = excluded.assigned_to, alert_count = excluded.alert_count, web_url = excluded.web_url,
      updated_at_src = excluded.updated_at_src, data = excluded.data, last_synced_at = now()
    returning id`;
  const incidentId = row!.id;
  const { entities, line } = summarise(inc);

  if (!prev) {
    const alerts = (inc.alerts ?? [])
      .slice(0, 10)
      .map((a) => `- [${a.severity ?? "?"}] ${a.title ?? a.id} (${a.serviceSource ?? "unknown source"})`)
      .join("\n");
    await postMessage(
      board,
      {
        channel: "incidents",
        type: "incident",
        incident: incidentId,
        body: `**${inc.severity.toUpperCase()}** incident ${inc.id}: ${inc.displayName}\n\n${line || "No entities extracted."}\n\n${alerts}${
          inc.incidentWebUrl ? `\n\n[Open in Defender](${inc.incidentWebUrl})` : ""
        }`,
        payload: {
          graph_id: inc.id,
          severity: inc.severity,
          status: inc.status,
          alert_count: alertCount,
          entities,
        },
      },
      { system: true },
    );
    return "created" as const;
  }

  const changes: string[] = [];
  if (prev.severity !== inc.severity) changes.push(`severity ${prev.severity} → ${inc.severity}`);
  if (prev.status !== inc.status) changes.push(`status ${prev.status} → ${inc.status}`);
  if (prev.alert_count !== alertCount) changes.push(`alerts ${prev.alert_count} → ${alertCount}`);
  if ((prev.classification ?? null) !== (inc.classification ?? null))
    changes.push(`classification ${prev.classification ?? "none"} → ${inc.classification ?? "none"}`);
  if (!changes.length) return "unchanged" as const;

  const [root] = await sql<{ id: string }[]>`
    select m.id from messages m join channels c on c.id = m.channel_id
    where m.incident_id = ${incidentId} and m.type = 'incident' and m.parent_id is null and c.name = 'incidents'
    order by m.seq asc limit 1`;
  await postMessage(
    board,
    {
      channel: "incidents",
      type: "status",
      incident: incidentId,
      parent_id: root?.id,
      body: `Incident ${inc.id} updated in Defender: ${changes.join("; ")}`,
      payload: { state: "source_updated", changes, entities },
    },
    { system: true },
  );
  return "updated" as const;
}

export async function ingestOnce() {
  const board = await boardPrincipal();
  const since = await getCursor();
  const incidents = await fetchUpdatedIncidents(since);
  const counts = { created: 0, updated: 0, unchanged: 0 };
  let max = since;
  for (const inc of incidents) {
    counts[await upsertIncident(inc, board)]++;
    if (inc.lastUpdateDateTime && inc.lastUpdateDateTime > max) max = inc.lastUpdateDateTime;
  }
  if (max !== since) await setCursor(max);
  return { since, fetched: incidents.length, ...counts };
}

/** Single-runner guard: an advisory lock so only one replica polls Graph at a time. */
export async function withLeaderLock<T>(key: number, fn: () => Promise<T>): Promise<T | undefined> {
  return sql.begin(async (tx) => {
    const [row] = await tx<{ ok: boolean }[]>`select pg_try_advisory_xact_lock(${key}) as ok`;
    if (!row?.ok) return undefined;
    return fn();
  }) as Promise<T | undefined>;
}
