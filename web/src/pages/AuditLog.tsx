import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { PageHeader, useMe } from "../components/shell";
import { ApiError, download, useLiveQuery } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Input, Select, Tag, Time } from "../components/ui";

type Row = { id: number; at: string; actor: string | null; actor_kind: string | null; event: string; subject: string | null; detail: unknown };
type Page = { rows: Row[]; next: number | null; events: string[] };

/** Event families, for the quick filter. Tone only where it changes what a reviewer should do. */
const FAMILIES: { value: string; label: string }[] = [
  { value: "", label: "All events" },
  { value: "action.", label: "Actions and approvals" },
  { value: "principal.", label: "People and agents" },
  { value: "broker.", label: "Broker pause" },
  { value: "audit.", label: "Audit exports" },
  { value: "report.", label: "Report exports" },
  { value: "retention.", label: "Retention" },
  { value: "enrich.", label: "Hunts and lookups" },
  { value: "notify.", label: "Notifications" },
  { value: "webhook.", label: "Webhooks" },
  { value: "limit.", label: "Rate limits" },
];

function tone(event: string): "critical" | "warning" | "accent" | "neutral" {
  if (/\.(rejected|rejected_on_recheck|interrupted|failed|disabled|paused|guard_error|content_flagged)$/.test(event)) return "critical";
  if (/^(principal\.roles_changed|audit\.exported|report\.exported|retention\.purged|limit\.hit)$/.test(event)) return "warning";
  if (event.startsWith("action.")) return "accent";
  return "neutral";
}

/** Query string for the API from the page's URL filters (kept in the URL so a view can be shared). */
export function queryOf(p: URLSearchParams, extra: Record<string, string> = {}) {
  const q = new URLSearchParams();
  for (const k of ["event", "actor", "subject", "from", "to"]) {
    const v = p.get(k);
    if (v) {
      const date = k === "from" || k === "to" ? new Date(v) : null;
      // Keep malformed shared-link values for API validation instead of crashing the console.
      q.set(k, date && Number.isFinite(date.getTime()) ? date.toISOString() : v);
    }
  }
  for (const [k, v] of Object.entries(extra)) q.set(k, v);
  return q.toString();
}

function Detail({ value }: { value: unknown }) {
  if (value == null) return null;
  const text = JSON.stringify(value, null, 1).replace(/\n\s*/g, " ");
  return <span className="font-mono text-xs text-muted [overflow-wrap:anywhere]">{text.length > 400 ? `${text.slice(0, 400)}…` : text}</span>;
}

/**
 * Admin → Audit log (Board.Admin): every audit_log row, newest first, filterable, exportable. The table is append-only
 * for every database role; exports are themselves audited (audit.exported).
 */
export default function AuditLogPage() {
  const me = useMe();
  const isAdmin = me?.roles.includes("admin");
  const [params, setParams] = useSearchParams();
  const [before, setBefore] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportErr, setExportErr] = useState<string | null>(null);
  const path = useMemo(() => `/manage/audit?${queryOf(params, { limit: "100", ...(before ? { before: String(before) } : {}) })}`, [params, before]);
  const { data, error } = useLiveQuery<Page>(isAdmin ? path : null);

  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Audit log" />
        <Empty title="The audit log is for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setBefore(null);
    setParams(next, { replace: true });
  };

  const exportCsv = async () => {
    setExporting(true);
    setExportErr(null);
    try {
      await download(`/manage/audit?${queryOf(params, { format: "csv" })}`, `blueboard-audit-${new Date().toISOString().slice(0, 10)}.csv`);
    } catch (e) {
      setExportErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <PageHeader title="Audit log" sub="Append-only for the application role. Who did what, when. CSV includes at most 50,000 matching rows; exports are audited.">
        <Button onClick={() => void exportCsv()} loading={exporting} title="Up to 50,000 rows matching the filters; the export is audited">
          Export CSV
        </Button>
      </PageHeader>
      <form className="flex shrink-0 flex-wrap items-end gap-2 border-b border-rule px-5 py-2" onSubmit={(e) => e.preventDefault()} aria-label="Filters">
        <label className="grid gap-0.5">
          <span className="label">Event</span>
          <Select value={params.get("event") ?? ""} onChange={(e) => set("event", e.target.value)} aria-label="Event family">
            {FAMILIES.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
            {data?.events
              .filter((e) => !FAMILIES.some((f) => f.value === e))
              .map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
          </Select>
        </label>
        <label className="grid gap-0.5">
          <span className="label">Actor</span>
          <Input defaultValue={params.get("actor") ?? ""} placeholder="@handle" onBlur={(e) => set("actor", e.target.value.trim())} className="w-36" />
        </label>
        <label className="grid gap-0.5">
          <span className="label">Subject contains</span>
          <Input defaultValue={params.get("subject") ?? ""} placeholder="device, user, handle…" onBlur={(e) => set("subject", e.target.value.trim())} className="w-48" />
        </label>
        <label className="grid gap-0.5">
          <span className="label">From</span>
          <Input type="datetime-local" defaultValue={params.get("from") ?? ""} onChange={(e) => set("from", e.target.value)} />
        </label>
        <label className="grid gap-0.5">
          <span className="label">To</span>
          <Input type="datetime-local" defaultValue={params.get("to") ?? ""} onChange={(e) => set("to", e.target.value)} />
        </label>
        {exportErr && <ErrorLine>{exportErr}</ErrorLine>}
      </form>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't load the audit log">{error.message}</Empty>}
        {data && data.rows.length === 0 && <Empty title="No audit rows match these filters" />}
        {data && data.rows.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[60rem] text-left text-[13px]">
              <thead className="label sticky top-0 bg-paper">
                <tr className="border-b border-rule">
                  <th className="px-5 py-2 font-normal">When</th>
                  <th className="py-2 pr-4 font-normal">Actor</th>
                  <th className="py-2 pr-4 font-normal">Event</th>
                  <th className="py-2 pr-4 font-normal">Subject</th>
                  <th className="py-2 pr-5 font-normal">Detail</th>
                </tr>
              </thead>
              <tbody>
                {data.rows.map((r) => (
                  <tr key={r.id} className="border-b border-rule align-top">
                    <td className="whitespace-nowrap px-5 py-2">
                      <Time iso={r.at} />
                      <span className="label ml-2 font-mono">#{r.id}</span>
                    </td>
                    <td className="py-2 pr-4">
                      {r.actor ? <span className={cx(r.actor_kind === "agent" && "text-accent")}>@{r.actor}</span> : <span className="label">system</span>}
                    </td>
                    <td className="py-2 pr-4">
                      <Tag tone={tone(r.event)}>{r.event}</Tag>
                    </td>
                    <td className="max-w-64 py-2 pr-4 [overflow-wrap:anywhere]">{r.subject}</td>
                    <td className="py-2 pr-5">
                      <Detail value={r.detail} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {(before || data?.next) && (
          <div className="flex gap-2 px-5 py-3">
            {before && (
              <Button variant="ghost" onClick={() => setBefore(null)}>
                Newest
              </Button>
            )}
            {data?.next && <Button onClick={() => setBefore(data.next)}>Older</Button>}
          </div>
        )}
      </div>
    </>
  );
}
