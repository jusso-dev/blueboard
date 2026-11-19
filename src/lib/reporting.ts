import { z } from "zod";
import { sql } from "./db";

/**
 * Response metrics, per incident and in aggregate, all measured from when the board first saw the
 * incident (`first_seen_at`):
 *
 *   enrichment  first finding / ioc / verdict posted by an agent or human (not the board)
 *   verdict     first verdict message
 *   containment first containment-stage action that succeeded
 *   approval    per action: request -> human decision (actions that needed approval)
 *
 * Durations are seconds. Missing milestones are null and excluded from percentiles.
 */
export const ReportQuery = z.object({
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  severity: z.string().max(20).optional(),
});
export type ReportQuery = z.input<typeof ReportQuery>;

const CONTAIN_KINDS = ["isolate_device", "disable_user", "revoke_sessions", "block_indicator"];

export type IncidentTiming = {
  id: string;
  graph_id: string;
  display_name: string;
  severity: string;
  status: string;
  first_seen_at: string;
  enrichment_s: number | null;
  verdict_s: number | null;
  containment_s: number | null;
  messages: number;
  actions: number;
};

export type Stat = { median: number | null; p90: number | null; n: number };

export type Report = {
  range: { from: string; to: string };
  incidents: { total: number; enriched: number; with_verdict: number; contained: number };
  enrichment: Stat;
  verdict: Stat;
  containment: Stat;
  approval: Stat;
  actions: { status: string; n: number }[];
  rows: IncidentTiming[];
};

function window(input: ReportQuery) {
  const f = ReportQuery.parse(input);
  const to = f.to ?? new Date();
  const from = f.from ?? new Date(to.getTime() - 30 * 86400_000);
  if (from >= to) throw new Error("from must be before to");
  return { from, to, severity: f.severity };
}

export async function buildReport(input: ReportQuery): Promise<Report> {
  const { from, to, severity } = window(input);
  const sevCond = severity ? sql`and lower(i.severity) = lower(${severity})` : sql``;

  const rows = await sql<IncidentTiming[]>`
    with inc as (
      select i.id, i.graph_id, i.display_name, i.severity, i.status, i.first_seen_at
      from incidents i
      where i.first_seen_at >= ${from} and i.first_seen_at < ${to} ${sevCond}
    )
    select inc.id, inc.graph_id, inc.display_name, inc.severity, inc.status, inc.first_seen_at,
      extract(epoch from (
        select min(m.created_at) from messages m join principals p on p.id = m.author_id
        where m.incident_id = inc.id and m.type in ('finding','ioc','verdict') and p.kind <> 'system'
      ) - inc.first_seen_at)::float8 as enrichment_s,
      extract(epoch from (
        select min(m.created_at) from messages m where m.incident_id = inc.id and m.type = 'verdict'
      ) - inc.first_seen_at)::float8 as verdict_s,
      extract(epoch from (
        select min(a.updated_at) from actions a
        where a.incident_id = inc.id and a.status = 'succeeded' and a.kind = any(${CONTAIN_KINDS})
      ) - inc.first_seen_at)::float8 as containment_s,
      (select count(*)::int from messages m where m.incident_id = inc.id) as messages,
      (select count(*)::int from actions a where a.incident_id = inc.id) as actions
    from inc
    order by inc.first_seen_at desc
    limit 500`;

  const [approval] = await sql<Stat[]>`
    select
      percentile_cont(0.5) within group (order by s)::float8 as median,
      percentile_cont(0.9) within group (order by s)::float8 as p90,
      count(*)::int as n
    from (
      select extract(epoch from (a.decided_at - a.created_at)) as s
      from actions a
      where a.requires_approval and a.decided_at is not null
        and a.created_at >= ${from} and a.created_at < ${to}
    ) t`;

  const actions = await sql<{ status: string; n: number }[]>`
    select status, count(*)::int as n from actions
    where created_at >= ${from} and created_at < ${to}
    group by status order by n desc`;

  const stat = (key: "enrichment_s" | "verdict_s" | "containment_s"): Stat => {
    const xs = rows.map((r) => r[key]).filter((v): v is number => v !== null && v >= 0);
    return { median: percentile(xs, 0.5), p90: percentile(xs, 0.9), n: xs.length };
  };

  return {
    range: { from: from.toISOString(), to: to.toISOString() },
    incidents: {
      total: rows.length,
      enriched: rows.filter((r) => r.enrichment_s !== null).length,
      with_verdict: rows.filter((r) => r.verdict_s !== null).length,
      contained: rows.filter((r) => r.containment_s !== null).length,
    },
    enrichment: stat("enrichment_s"),
    verdict: stat("verdict_s"),
    containment: stat("containment_s"),
    approval: approval ?? { median: null, p90: null, n: 0 },
    actions,
    rows,
  };
}

/** Linear-interpolated percentile (same method as Postgres percentile_cont). */
export function percentile(values: number[], p: number): number | null {
  if (!values.length) return null;
  const xs = [...values].sort((a, b) => a - b);
  const idx = (xs.length - 1) * p;
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  return xs[lo]! + (xs[hi]! - xs[lo]!) * (idx - lo);
}

export function reportCsv(r: Report): string {
  const head = ["incident", "name", "severity", "status", "first_seen_at", "enrichment_s", "verdict_s", "containment_s", "messages", "actions"];
  const esc = (v: unknown) => {
    if (v === null || v === undefined) return "";
    let s = String(v);
    // Neutralise spreadsheet formula injection from attacker-influenced incident titles.
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = r.rows.map((x) =>
    [x.graph_id, x.display_name, x.severity, x.status, new Date(x.first_seen_at).toISOString(), round(x.enrichment_s), round(x.verdict_s), round(x.containment_s), x.messages, x.actions]
      .map(esc)
      .join(","),
  );
  return [head.join(","), ...lines].join("\n") + "\n";
}

const round = (v: number | null) => (v === null ? null : Math.round(v));
