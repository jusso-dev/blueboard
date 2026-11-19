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
  for (const u of targets.users ?? []) if (pu.has(u.toLowerCase())) return { outcome: "reject", notes: [`${u} is a protected user`] };
  for (const d of targets.devices ?? []) if (pd.has(d.toLowerCase())) return { outcome: "reject", notes: [`${d} is a protected device`] };
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

  // update_incident must reference its own linked incident.
  if (def.kind === "update_incident" || def.kind === "add_incident_comment") {
    const id = (params as { incident_id: string }).incident_id;
    if (incident && incident.graph_id !== id) return { outcome: "reject", notes: [`incident_id ${id} does not match linked incident ${incident.graph_id}`] };
  }

  const auto = !def.destructive && policy.auto_approve.includes(def.kind) && notes.length === 0;
  return { outcome: auto ? "auto" : "needs_approval", notes };
}
