import { readFileSync, existsSync } from "node:fs";
import { z } from "zod";
import { entityKeys, extractEntities } from "../graph/entities";
import type { ActionDef } from "./catalog";

/**
 * Policy decides, per request, whether it is rejected outright, needs a human, or may run on its own.
 * The default is conservative: every destructive action needs approval, and nothing touches a
 * protected asset. Override with BLUEBOARD_POLICY_FILE (JSON, same shape as PolicySchema).
 */
export const PolicySchema = z.object({
  /** Non-destructive kinds that may run without approval (e.g. AV scan, investigation package, comment). */
  auto_approve: z.array(z.string()).default(["run_av_scan", "collect_investigation_package", "add_incident_comment"]),
  /** Kinds that are always rejected (turned off for this deployment). */
  disabled: z.array(z.string()).default([]),
  /** Users (UPN or object id, case-insensitive) that may never be disabled/reset by the board: break-glass, admins. */
  protected_users: z.array(z.string()).default([]),
  /** Device MDE ids or DNS names that may never be isolated by the board: DCs, critical servers. */
  protected_devices: z.array(z.string()).default([]),
  /** Require action targets to appear in the linked incident's evidence. */
  require_target_in_incident: z.boolean().default(true),
  /** Indicator values that may never be blocked (your own domains, CDNs, resolvers). */
  protected_indicators: z.array(z.string()).default([]),
});
export type Policy = z.infer<typeof PolicySchema>;

let cached: Policy | undefined;
export function loadPolicy(): Policy {
  if (cached) return cached;
  const file = process.env.BLUEBOARD_POLICY_FILE;
  const raw = file && existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
  cached = PolicySchema.parse(raw);
  return cached;
}
export function setPolicyForTests(p: Partial<Policy>) {
  cached = PolicySchema.parse(p);
}

export type PolicyDecision =
  | { outcome: "reject"; notes: string[] }
  | { outcome: "needs_approval" | "auto"; notes: string[] };

const lower = (xs: string[]) => new Set(xs.map((x) => x.toLowerCase()));

/** Actions that write to a specific Defender incident. They must be linked to that incident. */
const INCIDENT_SCOPED = new Set(["update_incident", "add_incident_comment"]);

type Aliases = { users: Map<string, string[]>; devices: Map<string, string[]> };

/**
 * Every name a target is known by in the incident's evidence: a device's MDE id and DNS name (plus its
 * short host name), a user's object id and UPN. Protected lists can be written with either form.
 */
function aliasesFrom(incident: { data: unknown } | null): Aliases {
  const a: Aliases = { users: new Map(), devices: new Map() };
  if (!incident) return a;
  const e = extractEntities(incident.data as never);
  const link = (map: Map<string, string[]>, names: (string | undefined)[]) => {
    const all = names.filter((n): n is string => !!n).map((n) => n.toLowerCase());
    for (const n of all) map.set(n, [...new Set([...(map.get(n) ?? []), ...all])]);
  };
  for (const d of e.devices) link(a.devices, [d.mdeDeviceId, d.name, d.name?.split(".")[0]]);
  for (const u of e.users) link(a.users, [u.aadUserId, u.upn]);
  return a;
}

const namesFor = (map: Map<string, string[]>, t: string) => map.get(t.toLowerCase()) ?? [t.toLowerCase()];

export function evaluate(
  def: ActionDef,
  params: unknown,
  incident: { graph_id: string; data: unknown } | null,
  policy: Policy = loadPolicy(),
): PolicyDecision {
  const notes: string[] = [];
  if (policy.disabled.includes(def.kind)) return { outcome: "reject", notes: [`${def.kind} is disabled by policy`] };

  const targets = def.targets(params as never);
  const pu = lower(policy.protected_users);
  const pd = lower(policy.protected_devices);
  const pi = lower(policy.protected_indicators);
  const aliases = aliasesFrom(incident);
  for (const u of targets.users ?? []) {
    if (namesFor(aliases.users, u).some((n) => pu.has(n))) return { outcome: "reject", notes: [`${u} is a protected user`] };
    if (pu.size && !aliases.users.has(u.toLowerCase()) && !u.includes("@"))
      notes.push(`${u} could not be matched to a UPN, so the protected-user list was checked by object id only`);
  }
  for (const d of targets.devices ?? []) {
    if (namesFor(aliases.devices, d).some((n) => pd.has(n))) return { outcome: "reject", notes: [`${d} is a protected device`] };
    if (pd.size && !aliases.devices.has(d.toLowerCase()))
      notes.push(`${d} is not in the incident evidence, so its host name is unknown and the protected-device list was checked by id only`);
  }
  for (const o of targets.other ?? []) {
    const v = o.toLowerCase();
    if (pi.has(v) || [...pi].some((p) => v.endsWith(`.${p}`) || v.includes(`://${p}`)))
      return { outcome: "reject", notes: [`${o} matches a protected indicator`] };
  }

  const all = [...(targets.users ?? []), ...(targets.devices ?? []), ...(targets.other ?? [])];
  if (all.length) {
    if (!incident) {
      notes.push("not linked to an incident: targets cannot be checked against evidence");
    } else if (policy.require_target_in_incident) {
      const keys = entityKeys(extractEntities(incident.data as never));
      const missing = all.filter((t) => !keys.has(t.toLowerCase()));
      if (missing.length) notes.push(`not in incident ${incident.graph_id} evidence: ${missing.join(", ")}`);
    }
  }

  // Incident writes must be linked to, and aimed at, that same incident.
  if (INCIDENT_SCOPED.has(def.kind)) {
    const id = (params as { incident_id: string }).incident_id;
    if (!incident) return { outcome: "reject", notes: [`${def.kind} must be linked to the incident it changes`] };
    if (incident.graph_id !== id) return { outcome: "reject", notes: [`incident_id ${id} does not match linked incident ${incident.graph_id}`] };
  }

  const auto = !def.destructive && policy.auto_approve.includes(def.kind) && notes.length === 0;
  return { outcome: auto ? "auto" : "needs_approval", notes };
}
