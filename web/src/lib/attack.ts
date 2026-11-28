import type { ActionTarget } from "./actions";
import { targetFromIoc } from "./actions";

/** GET /api/incidents/{id}/timeline (IncidentTimelineResult). */
export type TimelineRef = { type: "alert" | "message" | "action" | "incident" | "ref"; id: string; label: string | null };
export type TimelineEvent = {
  id: string;
  ts: string;
  kind: "alert" | "evidence" | "finding" | "ioc" | "verdict" | "action";
  lane: "attack" | "detection" | "response";
  action: string;
  entities: string[];
  source: string;
  refs: TimelineRef[];
  reported_by: string[];
  reported: boolean;
  in_evidence: boolean | null;
  thread_id: string | null;
  /** Reported events only: the source the participant claimed (untrusted). `source` is always "reported by @handle". */
  claimed_source?: string | null;
};
export type Timeline = { incident_id: string; graph_id: string; events: TimelineEvent[]; total: number; truncated: boolean; notice: string };

/** GET /api/incidents/{id}/graph (IncidentGraphResult). */
export type GraphNodeKind =
  | "user" | "device" | "ip" | "domain" | "url" | "file" | "process" | "mailbox" | "email" | "cloud_app" | "service_principal" | "azure_resource";
export type GraphNode = {
  id: string;
  kind: GraphNodeKind;
  label: string;
  keys: string[];
  alert_ids: string[];
  in_evidence: boolean;
  verdict: "malicious" | "suspicious" | "benign" | null;
  compromised: boolean;
  protected: boolean;
  protected_as: string | null;
  pending_actions: string[];
  executed_actions: string[];
};
export type GraphEdge = { from: string; to: string; relation: string; alert_ids: string[]; inferred: boolean };
export type AttackGraph = { incident_id: string; graph_id: string; nodes: GraphNode[]; edges: GraphEdge[]; truncated: boolean; notice: string };

export const KIND_LABEL: Record<TimelineEvent["kind"], string> = {
  alert: "Alert", evidence: "Evidence", finding: "Finding", ioc: "IOC", verdict: "Verdict", action: "Action",
};

/** Events touching a graph node (any of its keys) or matching free text, and of the chosen kinds. Pure: unit-tested. */
export function filterTimeline(events: TimelineEvent[], opts: { keys?: string[] | null; text?: string; kinds?: Set<string> | null }): TimelineEvent[] {
  const keys = (opts.keys ?? []).map((k) => k.toLowerCase());
  const text = (opts.text ?? "").trim().toLowerCase();
  return events.filter((e) => {
    if (opts.kinds && opts.kinds.size > 0 && !opts.kinds.has(e.kind)) return false;
    const ents = e.entities.map((x) => x.toLowerCase());
    if (keys.length > 0 && !ents.some((x) => keys.some((k) => x === k || x.includes(k)))) return false;
    if (text && !ents.some((x) => x.includes(text)) && !e.action.toLowerCase().includes(text) && !e.source.toLowerCase().includes(text)) return false;
    return true;
  });
}

/** Where a timeline reference leads in the app. Messages open their thread; actions open Approvals at the action. */
export function refLink(r: TimelineRef, threadId: string | null): { to: string; label: string } | { thread: string; label: string } | null {
  switch (r.type) {
    case "message":
      return { thread: threadId ?? r.id, label: r.label ?? "message" };
    case "action":
      return { to: `/approvals#action-${r.id}`, label: r.label ?? "action" };
    case "alert":
      return { to: `/search?q=${encodeURIComponent(r.id)}`, label: `alert ${r.id}` };
    default:
      return null;
  }
}

/** The "request action" shortcut for a graph node: the same pre-filled targets the incident page uses. */
export function targetsForNode(n: GraphNode, all: ActionTarget[]): ActionTarget[] {
  const keys = new Set(n.keys.map((k) => k.toLowerCase()));
  const matched = all.filter(
    (t) => t.type !== "incident" && Object.values(t.params).some((v) => typeof v === "string" && keys.has(v.toLowerCase())),
  );
  if (matched.length > 0) return matched;
  const iocKind: Partial<Record<GraphNodeKind, string>> = { ip: "ip", domain: "domain", url: "url", user: "user", mailbox: "email", device: "device" };
  if (n.kind === "file") {
    const hash = n.keys.find((k) => /^[0-9a-f]{64}$/i.test(k)) ?? n.keys.find((k) => /^[0-9a-f]{40}$/i.test(k));
    const t = hash ? targetFromIoc(hash.length === 64 ? "sha256" : "sha1", hash) : null;
    return t ? [t] : [];
  }
  const k = iocKind[n.kind];
  if (!k) return [];
  for (const key of n.keys) {
    const t = targetFromIoc(k, key);
    if (t) return [t];
  }
  return [];
}

/** Column per kind, left to right roughly in attack order: identities, endpoints, processes and files, network. */
const COLUMN: Record<GraphNodeKind, number> = {
  mailbox: 0, email: 0, user: 1, cloud_app: 1, service_principal: 1, device: 2, azure_resource: 2, process: 3, file: 3, url: 4, domain: 4, ip: 5,
};

export type Positioned = GraphNode & { x: number; y: number };

/**
 * Deterministic layered layout: a column per entity kind, rows ordered by a few barycentre sweeps so connected nodes
 * line up and edges cross less. No physics, so the picture is the same on every render and in tests. Pure.
 */
export function layoutGraph(g: Pick<AttackGraph, "nodes" | "edges">, opts = { colGap: 190, rowGap: 64, pad: 40 }): { nodes: Positioned[]; width: number; height: number } {
  const usedCols = [...new Set(g.nodes.map((n) => COLUMN[n.kind] ?? 5))].sort((a, b) => a - b);
  const colIndex = new Map(usedCols.map((c, i) => [c, i]));
  const cols: GraphNode[][] = usedCols.map(() => []);
  for (const n of g.nodes) cols[colIndex.get(COLUMN[n.kind] ?? 5)!]!.push(n);
  for (const c of cols) c.sort((a, b) => a.kind.localeCompare(b.kind) || a.label.localeCompare(b.label));

  const neighbours = new Map<string, string[]>();
  for (const e of g.edges) {
    neighbours.set(e.from, [...(neighbours.get(e.from) ?? []), e.to]);
    neighbours.set(e.to, [...(neighbours.get(e.to) ?? []), e.from]);
  }
  const row = new Map<string, number>();
  const assign = () => cols.forEach((c) => c.forEach((n, i) => row.set(n.id, i)));
  assign();
  for (let sweep = 0; sweep < 4; sweep++) {
    for (const c of cols) {
      const bary = new Map(
        c.map((n) => {
          const ns = (neighbours.get(n.id) ?? []).map((id) => row.get(id)).filter((r): r is number => r !== undefined);
          return [n.id, ns.length ? ns.reduce((a, b) => a + b, 0) / ns.length : row.get(n.id)!];
        }),
      );
      c.sort((a, b) => bary.get(a.id)! - bary.get(b.id)! || a.label.localeCompare(b.label));
    }
    assign();
  }
  const tallest = Math.max(1, ...cols.map((c) => c.length));
  const height = opts.pad * 2 + (tallest - 1) * opts.rowGap;
  const nodes: Positioned[] = [];
  cols.forEach((c, ci) => {
    const offset = ((tallest - c.length) * opts.rowGap) / 2;
    c.forEach((n, ri) => nodes.push({ ...n, x: opts.pad + ci * opts.colGap, y: opts.pad + offset + ri * opts.rowGap }));
  });
  return { nodes, width: opts.pad * 2 + Math.max(0, cols.length - 1) * opts.colGap, height };
}

export const NODE_GLYPH: Record<GraphNodeKind, string> = {
  user: "U", mailbox: "@", email: "✉", device: "D", ip: "IP", domain: "DN", url: "⇗", file: "F", process: "P",
  cloud_app: "A", service_principal: "SP", azure_resource: "R",
};
