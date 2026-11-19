"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { PageHeader, useMe } from "../../components/shell";
import { useLiveQuery } from "../../components/data";
import { cx, Empty, fmtDuration, Segmented, Select, Severity } from "../../components/ui";

type Stat = { median: number | null; p90: number | null; n: number };
type Row = {
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
type Report = {
  range: { from: string; to: string };
  incidents: { total: number; enriched: number; with_verdict: number; contained: number };
  enrichment: Stat;
  verdict: Stat;
  containment: Stat;
  approval: Stat;
  actions: { status: string; n: number }[];
  rows: Row[];
};

const RANGES = [
  { value: "1", label: "24h" },
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
] as const;

/** Stat tile: label · median (the value) · p90 and sample size as context. No chart: four headline numbers. */
function Tile({ label, stat, hint }: { label: string; stat: Stat; hint: string }) {
  return (
    <div className="min-w-0 border-rule px-5 py-4 [&:not(:first-child)]:border-l max-lg:[&:nth-child(3)]:border-l-0 max-lg:[&:nth-child(n+3)]:border-t">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-[28px] font-semibold leading-none tracking-tight text-ink">{fmtDuration(stat.median)}</p>
      <p className="label tnum mt-2">
        p90 {fmtDuration(stat.p90)} · n={stat.n}
      </p>
      <p className="mt-1 text-[11px] text-faint">{hint}</p>
    </div>
  );
}

/** Meter: share of incidents that reached a milestone. Track is a lighter step of the same hue. */
function Meter({ label, value, total }: { label: string; value: number; total: number }) {
  const pct = total ? Math.round((value / total) * 100) : 0;
  return (
    <div className="grid grid-cols-[8.5rem_minmax(0,1fr)_4.5rem] items-center gap-3 text-[13px]">
      <span className="text-ink-2">{label}</span>
      <span
        className="h-2 overflow-hidden rounded-full bg-accent-soft"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={value}
        aria-valuetext={`${value} of ${total} (${pct}%)`}
      >
        <span className="block h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </span>
      <span className="label tnum text-right text-ink-2">
        {value}/{total}
      </span>
    </div>
  );
}

type SortKey = "first_seen_at" | "enrichment_s" | "verdict_s" | "containment_s" | "messages";

export default function ReportsPage() {
  const me = useMe();
  const [days, setDays] = useState<(typeof RANGES)[number]["value"]>("30");
  const [severity, setSeverity] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "first_seen_at", dir: -1 });

  // The window is computed on the client after mount, so server and client HTML agree.
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => setNow(Date.now()), [days, severity]);
  const query = useMemo(() => {
    if (now === null) return null;
    const p = new URLSearchParams({ from: new Date(now - Number(days) * 86400_000).toISOString(), to: new Date(now).toISOString() });
    if (severity) p.set("severity", severity);
    return p.toString();
  }, [now, days, severity]);

  const isAdmin = me?.roles.includes("admin");
  const { data: r, error } = useLiveQuery<Report>(isAdmin && query ? `/api/reports?${query}` : null);

  const rows = useMemo(() => {
    if (!r) return [];
    const val = (x: Row) => (sort.key === "first_seen_at" ? new Date(x.first_seen_at).getTime() : x[sort.key]);
    return [...r.rows].sort((a, b) => {
      const va = val(a);
      const vb = val(b);
      if (va === null) return 1; // missing milestones always sink
      if (vb === null) return -1;
      return (va - vb) * sort.dir;
    });
  }, [r, sort]);

  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Reports" />
        <Empty title="Reports are for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }

  const th = (key: SortKey, label: string, right = true) => {
    const active = sort.key === key;
    return (
      <th className={cx("py-2 pr-4 font-normal", right && "text-right")} aria-sort={active ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
        <button
          className={cx("inline-flex items-center gap-1 transition-colors duration-150 hover:text-ink", active && "text-ink")}
          onClick={() => setSort({ key, dir: active ? (sort.dir === 1 ? -1 : 1) : key === "first_seen_at" ? -1 : 1 })}
        >
          {label}
          <span aria-hidden className={cx(!active && "invisible")}>
            {sort.dir === 1 ? "↑" : "↓"}
          </span>
        </button>
      </th>
    );
  };

  return (
    <>
      <PageHeader title="Reports" sub="Response times, measured from when the board first saw each incident. Median, with p90 for the slow tail.">
        <Select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </Select>
        <Segmented label="Date range" value={days} onChange={setDays} options={RANGES.map((x) => ({ ...x }))} />
        <a
          href={query ? `/api/reports?${query}&format=csv` : undefined}
          aria-disabled={!query || undefined}
          className="inline-flex h-8 items-center rounded-[var(--radius-control)] border border-control bg-paper-2 px-3 text-[13px] text-ink transition-colors duration-150 hover:border-ink-2 hover:bg-paper-3 aria-disabled:pointer-events-none aria-disabled:opacity-50"
        >
          Export CSV
        </a>
      </PageHeader>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't build the report">{error}</Empty>}
        {r && (
          <>
            <section aria-label="Response times" className="grid grid-cols-4 border-b border-rule max-lg:grid-cols-2">
              <Tile label="Time to first enrichment" stat={r.enrichment} hint="First finding, IOC or verdict" />
              <Tile label="Time to verdict" stat={r.verdict} hint="First TP / FP call" />
              <Tile label="Time to containment" stat={r.containment} hint="First successful containment action" />
              <Tile label="Approval wait" stat={r.approval} hint="Request to human decision" />
            </section>

            <section aria-label="Coverage" className="grid gap-8 border-b border-rule px-5 py-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <div className="space-y-2.5">
                <h2 className="text-sm font-semibold">
                  Coverage <span className="label tnum ml-1">{r.incidents.total} incidents</span>
                </h2>
                <Meter label="Enriched" value={r.incidents.enriched} total={r.incidents.total} />
                <Meter label="Verdict reached" value={r.incidents.with_verdict} total={r.incidents.total} />
                <Meter label="Contained" value={r.incidents.contained} total={r.incidents.total} />
              </div>
              <div>
                <h2 className="text-sm font-semibold">Action outcomes</h2>
                {r.actions.length === 0 ? (
                  <p className="mt-2 text-[13px] text-muted">No actions requested in this range.</p>
                ) : (
                  <table className="mt-2 w-full max-w-sm text-[13px]">
                    <tbody>
                      {r.actions.map((a) => (
                        <tr key={a.status} className="border-b border-rule last:border-0">
                          <td className="py-1.5 text-ink-2">{a.status.replace("_", " ")}</td>
                          <td className="tnum py-1.5 text-right text-ink">{a.n}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>

            <section aria-label="Incidents" className="overflow-x-auto">
              {rows.length === 0 ? (
                <Empty title="No incidents in this range" />
              ) : (
                <table className="w-full min-w-[46rem] text-left text-[13px]">
                  <caption className="sr-only">Response times per incident</caption>
                  <thead className="label sticky top-0 z-10 bg-paper">
                    <tr className="border-b border-rule">
                      <th className="px-5 py-2 font-normal">Incident</th>
                      <th className="py-2 pr-4 font-normal">Severity</th>
                      {th("first_seen_at", "First seen", false)}
                      {th("enrichment_s", "Enrichment")}
                      {th("verdict_s", "Verdict")}
                      {th("containment_s", "Containment")}
                      {th("messages", "Messages")}
                    </tr>
                  </thead>
                  <tbody className="tnum">
                    {rows.map((x) => (
                      <tr key={x.id} className="border-b border-rule hover:bg-paper-2/60">
                        <td className="w-[38%] max-w-0 px-5 py-2">
                          <Link href={`/incidents/${x.id}`} className="block truncate text-ink hover:text-accent">
                            <span className="label mr-2 text-ink-2">{x.graph_id}</span>
                            {x.display_name}
                          </Link>
                        </td>
                        <td className="py-2 pr-4">
                          <Severity value={x.severity} />
                        </td>
                        <td className="whitespace-nowrap py-2 pr-4 text-muted">
                          {new Date(x.first_seen_at).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}
                        </td>
                        <td className="py-2 pr-4 text-right text-ink-2">{fmtDuration(x.enrichment_s)}</td>
                        <td className="py-2 pr-4 text-right text-ink-2">{fmtDuration(x.verdict_s)}</td>
                        <td className="py-2 pr-4 text-right text-ink-2">{fmtDuration(x.containment_s)}</td>
                        <td className="py-2 pr-5 text-right text-muted">{x.messages}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          </>
        )}
      </div>
    </>
  );
}
