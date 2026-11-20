import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router";
import { useMemo, type RefObject } from "react";
import { PageHeader } from "../components/shell";
import { useListNav, type NavRowProps } from "../components/shortcuts";
import { useLiveQuery, type QueueRow } from "../lib/api";
import { ageText, CHIPS, chipsFrom, filterQueue, statusWords, VERDICT_LABEL, type Chip } from "../lib/queue";
import { cx, Empty, Severity, Tag, Time } from "../components/ui";

/** Home: open incidents, "needs a human" first. Rows refresh with the shared 4 s poll. */
export default function QueuePage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const { hash } = useLocation();
  const { data, error } = useLiveQuery<QueueRow[]>("/incidents?view=queue");
  const chips = chipsFrom(params);
  const rows = useMemo(() => (data ? filterQueue(data, chips) : undefined), [data, chips.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps
  const nav = useListNav(rows, (r) => r.id, { onOpen: (r) => navigate(`/incidents/${r.id}`) });

  // Old links (/?channel=triage) land on the channel, keeping any #m-<id> so the feed opens that message.
  const legacy = params.get("channel");
  if (legacy) return <Navigate to={`/channels/${encodeURIComponent(legacy)}${hash}`} replace />;

  const toggle = (c: Chip) => {
    const next = new URLSearchParams(params);
    next.delete("f");
    for (const x of chips.includes(c) ? chips.filter((y) => y !== c) : [...chips, c]) next.append("f", x);
    setParams(next, { replace: true });
  };
  const waiting = data?.filter((r) => r.needs_human).length ?? 0;

  return (
    <>
      <PageHeader
        title="Queue"
        sub={data ? `${data.length} open ${data.length === 1 ? "incident" : "incidents"}${waiting ? ` · ${waiting} need a person` : ""}` : " "}
      >
        <div role="group" aria-label="Quick filters" className="flex flex-wrap items-center gap-1">
          {CHIPS.map((c) => {
            const on = chips.includes(c.id);
            return (
              <button
                key={c.id}
                type="button"
                aria-pressed={on}
                onClick={() => toggle(c.id)}
                className={cx(
                  "h-7 whitespace-nowrap rounded-[var(--radius-control)] border px-2.5 text-xs transition-colors duration-150",
                  on ? "border-accent bg-accent-soft text-ink" : "border-control text-muted hover:border-ink-2 hover:text-ink",
                )}
              >
                {c.label}
              </button>
            );
          })}
        </div>
      </PageHeader>
      <div className="min-h-0 flex-1 overflow-auto" aria-busy={!data && !error}>
        {error && <Empty title="Couldn't load the queue">{error.message}</Empty>}
        {rows && <QueueTable rows={rows} rowProps={nav.rowProps} containerRef={nav.container} onOpen={(r) => navigate(`/incidents/${r.id}`)} />}
        {rows?.length === 0 && (
          <Empty title={chips.length ? "No open incidents match these filters" : "No open incidents"}>
            {chips.length ? "Clear a filter to see more." : "New incidents from Defender appear here within a minute."}
          </Empty>
        )}
      </div>
    </>
  );
}

/** The queue table. Below md only severity, the incident and "needs approval" stay visible. */
export function QueueTable({
  rows,
  rowProps,
  containerRef,
  onOpen,
}: {
  rows: QueueRow[];
  rowProps?: (r: QueueRow) => NavRowProps;
  containerRef?: RefObject<HTMLElement | null>;
  onOpen?: (r: QueueRow) => void;
}) {
  if (rows.length === 0) return null;
  return (
    <table className="w-full table-fixed text-left text-[13px]" aria-label="Open incidents">
      <colgroup>
        <col className="w-[5.5rem]" />
        <col />
        <col className="w-28 max-lg:hidden" />
        <col className="w-36 max-md:hidden" />
        <col className="w-16" />
        <col className="w-24" />
        <col className="w-32 max-lg:hidden" />
        <col className="w-20 max-md:hidden" />
        <col className="w-14 max-md:hidden" />
      </colgroup>
      <thead className="label sticky top-0 z-10 bg-paper">
        <tr className="border-b border-rule">
          <th scope="col" className="py-2 pl-5 pr-2 font-normal">Severity</th>
          <th scope="col" className="py-2 pr-3 font-normal">Incident</th>
          <th scope="col" className="py-2 pr-3 font-normal max-lg:hidden">Defender</th>
          <th scope="col" className="py-2 pr-3 font-normal max-md:hidden">Verdict</th>
          <th scope="col" className="py-2 pr-3 text-right font-normal">Asks</th>
          <th scope="col" className="py-2 pr-3 font-normal">Approval</th>
          <th scope="col" className="py-2 pr-3 font-normal max-lg:hidden">Working</th>
          <th scope="col" className="py-2 pr-3 text-right font-normal max-md:hidden">Activity</th>
          <th scope="col" className="py-2 pr-5 text-right font-normal max-md:hidden">Age</th>
        </tr>
      </thead>
      <tbody ref={containerRef as RefObject<HTMLTableSectionElement>}>
        {rows.map((r) => {
          const p = rowProps?.(r);
          return (
            <tr
              key={r.id}
              {...p}
              aria-label={`${r.severity} incident ${r.graph_id}: ${r.display_name}`}
              onClick={(e) => {
                if (!(e.target as HTMLElement).closest("a")) onOpen?.(r);
              }}
              className={cx(
                "h-11 cursor-pointer border-b border-rule transition-colors duration-150 hover:bg-paper-2/60 focus-visible:bg-paper-2 focus-visible:outline-offset-[-2px]",
                p?.["data-selected"] && "bg-paper-2",
              )}
            >
              <td className="py-2 pl-5 pr-2">
                <Severity value={r.severity} />
              </td>
              <td className="min-w-0 py-2 pr-3">
                <Link to={`/incidents/${r.id}`} tabIndex={-1} className="flex min-w-0 items-baseline gap-2 hover:text-accent">
                  <span className="label tnum shrink-0 text-ink-2">{r.graph_id}</span>
                  <span className="truncate text-ink">{r.display_name}</span>
                </Link>
              </td>
              <td className="py-2 pr-3 text-ink-2 max-lg:hidden">
                <span className="truncate">{statusWords(r.status)}</span>
              </td>
              <td className="truncate py-2 pr-3 max-md:hidden">
                {r.verdict ? (
                  <span className="text-ink-2" title={r.verdict_by ? `by @${r.verdict_by}` : undefined}>
                    {VERDICT_LABEL[r.verdict] ?? r.verdict}
                    {r.verdict_confidence !== null && <span className="tnum text-muted"> · {Math.round(r.verdict_confidence * 100)}%</span>}
                  </span>
                ) : (
                  <span className="text-faint">no verdict</span>
                )}
              </td>
              <td className={cx("tnum py-2 pr-3 text-right", r.open_asks ? "text-ink" : "text-faint")} title={r.human_asks ? `${r.human_asks} ask a person` : undefined}>
                {r.open_asks}
                {r.human_asks > 0 && <span className="sr-only">, {r.human_asks} ask a person</span>}
              </td>
              <td className="py-2 pr-3">
                {r.pending_actions > 0 ? <Tag tone="warning">{r.pending_actions} waiting</Tag> : <span className="text-faint">none</span>}
              </td>
              <td className="truncate py-2 pr-3 text-ink-2 max-lg:hidden">
                {r.active_claims.length ? r.active_claims.map((h) => `@${h}`).join(", ") : <span className="text-faint">nobody</span>}
              </td>
              <td className="py-2 pr-3 text-right max-md:hidden">
                <Time iso={r.last_activity_at} />
              </td>
              <td className="label tnum py-2 pr-5 text-right max-md:hidden">{ageText(r.created_at)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
