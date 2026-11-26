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
                  "h-9 whitespace-nowrap rounded-[var(--radius-control)] border px-3 text-ui transition-colors duration-150",
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

/** Secondary columns yield to the incident title; phones show outstanding work beneath it. */
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
    <table className="w-full table-fixed text-left text-ui" aria-label="Open incidents">
      <colgroup>
        <col className="w-[5.5rem] max-sm:w-20" />
        <col />
        <col className="w-28 max-xl:hidden" />
        <col className="w-36 max-xl:hidden" />
        <col className="w-16 max-lg:hidden" />
        <col className="w-24 max-sm:hidden" />
        <col className="w-32 max-xl:hidden" />
        <col className="w-20 max-xl:hidden" />
        <col className="w-14 max-xl:hidden" />
      </colgroup>
      <thead className="label sticky top-0 z-10 bg-paper">
        <tr className="border-b border-rule">
          <th scope="col" className="py-3 pl-6 pr-2 max-sm:pl-4 font-normal">Severity</th>
          <th scope="col" className="py-2 pr-3 font-normal">Incident</th>
          <th scope="col" className="py-2 pr-3 font-normal max-xl:hidden">Defender</th>
          <th scope="col" className="py-2 pr-3 font-normal max-xl:hidden">Verdict</th>
          <th scope="col" className="py-2 pr-3 text-right font-normal max-lg:hidden">Asks</th>
          <th scope="col" className="py-2 pr-3 font-normal max-sm:hidden">Approval</th>
          <th scope="col" className="py-2 pr-3 font-normal max-xl:hidden">Working</th>
          <th scope="col" className="py-2 pr-3 text-right font-normal max-xl:hidden">Activity</th>
          <th scope="col" className="py-2 pr-6 max-sm:pr-4 text-right font-normal max-xl:hidden">Age</th>
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
                "h-14 cursor-pointer border-b border-rule transition-colors duration-150 hover:bg-paper-2/60 focus-visible:bg-paper-2 focus-visible:outline-offset-[-2px]",
                p?.["data-selected"] && "bg-paper-2",
              )}
            >
              <td className="py-3 pl-6 pr-2 max-sm:pl-4">
                <Severity value={r.severity} />
              </td>
              <td className="min-w-0 py-2 pr-3">
                <Link to={`/incidents/${r.id}`} tabIndex={-1} className="flex min-w-0 items-baseline gap-2 hover:text-accent">
                  <span className="label tnum shrink-0 text-ink-2">{r.graph_id}</span>
                  <span className="truncate text-ink">{r.display_name}</span>
                </Link>
                {(r.pending_actions > 0 || r.human_asks > 0) && (
                  <p className="mt-1 hidden text-meta text-warning max-sm:block">
                    {[r.pending_actions > 0 && `${r.pending_actions} awaiting approval`, r.human_asks > 0 && `${r.human_asks} ask a person`].filter(Boolean).join(" · ")}
                  </p>
                )}
              </td>
              <td className="py-2 pr-3 text-ink-2 max-xl:hidden">
                <span className="truncate">{statusWords(r.status)}</span>
              </td>
              <td className="truncate py-2 pr-3 max-xl:hidden">
                {r.verdict ? (
                  <span className="text-ink-2" title={r.verdict_by ? `by @${r.verdict_by}` : undefined}>
                    {VERDICT_LABEL[r.verdict] ?? r.verdict}
                    {r.verdict_confidence !== null && <span className="tnum text-muted"> · {Math.round(r.verdict_confidence * 100)}%</span>}
                  </span>
                ) : (
                  <span className="text-faint">no verdict</span>
                )}
              </td>
              <td className={cx("tnum py-2 pr-3 text-right max-lg:hidden", r.open_asks ? "text-ink" : "text-faint")} title={r.human_asks ? `${r.human_asks} ask a person` : undefined}>
                {r.open_asks}
                {r.human_asks > 0 && <span className="sr-only">, {r.human_asks} ask a person</span>}
              </td>
              <td className="py-2 pr-3 max-sm:hidden">
                {r.pending_actions > 0 ? <Tag tone="warning">{r.pending_actions} waiting</Tag> : <span className="text-faint">none</span>}
              </td>
              <td className="truncate py-2 pr-3 text-ink-2 max-xl:hidden">
                {r.active_claims.length ? r.active_claims.map((h) => `@${h}`).join(", ") : <span className="text-faint">nobody</span>}
              </td>
              <td className="py-2 pr-3 text-right max-xl:hidden">
                <Time iso={r.last_activity_at} />
              </td>
              <td className="label tnum py-2 pr-6 max-sm:pr-4 text-right max-xl:hidden">{ageText(r.created_at)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
