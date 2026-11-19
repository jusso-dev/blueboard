import { z } from "zod";
import { sql } from "./db";
import { BoardError, resolveIncident } from "./board";
import { audit } from "./auth";
import { DEFENDER, GRAPH, msFetch } from "./graph/client";
import { extractEntities } from "./graph/entities";
import type { Principal } from "./types";

/**
 * Read-only enrichment brokered by the board, so agents need no Microsoft credentials at all.
 * Every call is audited. Advanced hunting is read-only by design (KQL cannot write).
 */
function need(p: Principal) {
  if (!p.roles.includes("hunter")) throw new BoardError("missing role hunter", 403);
}

export async function getIncident(ref: string) {
  const id = await resolveIncident(ref);
  const [row] = await sql<{ id: string; graph_id: string; display_name: string; severity: string; status: string; classification: string | null; determination: string | null; assigned_to: string | null; web_url: string | null; data: any }[]>`
    select id, graph_id, display_name, severity, status, classification, determination, assigned_to, web_url, data from incidents where id = ${id}`;
  if (!row) throw new BoardError("incident not found", 404);
  const alerts = (row.data.alerts ?? []).map((a: any) => ({
    id: a.id,
    title: a.title,
    severity: a.severity,
    category: a.category,
    serviceSource: a.serviceSource,
    detectionSource: a.detectionSource,
    mitreTechniques: a.mitreTechniques,
    description: typeof a.description === "string" ? a.description.slice(0, 2000) : undefined,
    firstActivityDateTime: a.firstActivityDateTime,
    lastActivityDateTime: a.lastActivityDateTime,
  }));
  const { data, ...rest } = row;
  return { ...rest, alerts, entities: extractEntities(data) };
}

export const HuntInput = z.object({
  query: z.string().min(5).max(10000).describe("KQL advanced hunting query (Defender XDR / Sentinel tables)"),
  timespan: z.string().regex(/^P(T?\d+[DHM])+$/).default("P7D").describe("ISO-8601 duration, e.g. P7D, PT12H"),
});

export async function runHunt(p: Principal, input: z.input<typeof HuntInput>) {
  need(p);
  const { query, timespan } = HuntInput.parse(input);
  // Strip comments then refuse management commands; advanced hunting is read-only anyway.
  if (/^\s*\./m.test(query.replace(/\/\/.*$/gm, ""))) throw new BoardError("management commands are not allowed");
  await audit(p.id, "enrich.hunt", null, { query, timespan });
  const res = await msFetch<{ schema: { name: string; type: string }[]; results: Record<string, unknown>[] }>(
    GRAPH,
    "/v1.0/security/runHuntingQuery",
    { method: "POST", body: { query, timespan } },
  );
  const rows = res.results.slice(0, 200);
  return { columns: res.schema, rows, truncated: res.results.length > rows.length, total: res.results.length };
}

export const LookupInput = z.object({
  kind: z.enum(["user", "device", "ip", "file", "url"]),
  value: z.string().min(1).max(2048),
});

export async function lookupEntity(p: Principal, input: z.input<typeof LookupInput>) {
  need(p);
  const { kind, value } = LookupInput.parse(input);
  await audit(p.id, "enrich.lookup", `${kind}:${value}`);
  const e = encodeURIComponent(value);
  switch (kind) {
    case "user": {
      const user = await msFetch<any>(
        GRAPH,
        `/v1.0/users/${e}?$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,officeLocation,createdDateTime,userType,onPremisesSyncEnabled,signInActivity`,
      ).catch(() =>
        msFetch<any>(GRAPH, `/v1.0/users/${e}?$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,userType`),
      );
      const [roles, risky] = await Promise.all([
        msFetch<{ value: any[] }>(GRAPH, `/v1.0/users/${e}/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName`).catch(() => ({ value: [] })),
        msFetch<any>(GRAPH, `/v1.0/identityProtection/riskyUsers/${user.id}`).catch(() => null),
      ]);
      return {
        user,
        directoryRoles: roles.value.map((r) => r.displayName),
        risk: risky ? { level: risky.riskLevel, state: risky.riskState, detail: risky.riskDetail } : null,
      };
    }
    case "device": {
      const isId = /^[0-9a-f]{40}$/i.test(value);
      const machine = isId
        ? await msFetch<any>(DEFENDER, `/api/machines/${value}`)
        : (await msFetch<{ value: any[] }>(DEFENDER, `/api/machines?$filter=computerDnsName eq '${value.replace(/'/g, "''")}'`)).value[0];
      if (!machine) return { found: false };
      const pick = (({ id, computerDnsName, osPlatform, osVersion, healthStatus, riskScore, exposureLevel, isolationState, lastSeen, lastIpAddress, machineTags, onboardingStatus }) => ({ id, computerDnsName, osPlatform, osVersion, healthStatus, riskScore, exposureLevel, isolationState, lastSeen, lastIpAddress, machineTags, onboardingStatus }))(machine);
      const users = await msFetch<{ value: any[] }>(DEFENDER, `/api/machines/${machine.id}/logonusers`).catch(() => ({ value: [] }));
      return { device: pick, recentLogonUsers: users.value.slice(0, 10).map((u) => ({ accountName: u.accountName, domain: u.accountDomain, isDomainAdmin: u.isDomainAdmin, lastSeen: u.lastSeen })) };
    }
    case "ip": {
      const [stats, alerts] = await Promise.all([
        msFetch<any>(DEFENDER, `/api/ips/${e}/stats?lookBackHours=720`).catch((err) => ({ error: String(err.message) })),
        msFetch<{ value: any[] }>(DEFENDER, `/api/ips/${e}/alerts`).catch(() => ({ value: [] })),
      ]);
      return { stats, relatedAlerts: alerts.value.slice(0, 10).map((a) => ({ id: a.id, title: a.title, severity: a.severity, status: a.status })) };
    }
    case "file": {
      const [info, stats] = await Promise.all([
        msFetch<any>(DEFENDER, `/api/files/${e}`).catch((err) => ({ error: String(err.message) })),
        msFetch<any>(DEFENDER, `/api/files/${e}/stats?lookBackHours=720`).catch(() => null),
      ]);
      return { file: info, stats };
    }
    case "url": {
      let host: string;
      try {
        host = new URL(value.includes("://") ? value : `https://${value}`).hostname;
      } catch {
        throw new BoardError("invalid url");
      }
      const stats = await msFetch<any>(DEFENDER, `/api/domains/${encodeURIComponent(host)}/stats?lookBackHours=720`).catch((err) => ({ error: String(err.message) }));
      return { domain: host, stats };
    }
  }
}
