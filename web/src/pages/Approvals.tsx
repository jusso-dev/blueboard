import { useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, refreshAll, useLiveQuery, type Action } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Input, Segmented, Tag, Time } from "../components/ui";

const STATUS_TONE: Record<string, "good" | "critical" | "warning" | "neutral" | "accent"> = {
  succeeded: "good",
  failed: "critical",
  rejected: "critical",
  denied: "neutral",
  pending_approval: "warning",
  approved: "accent",
  running: "accent",
};

function title(kind: string) {
  return kind.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
}

function Pending({ a, canDecide, mine }: { a: Action; canDecide: boolean; mine: boolean }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const decide = async (decision: "approve" | "deny") => {
    setBusy(decision);
    setErr(null);
    try {
      await api(`/actions/${a.id}`, { method: "POST", body: JSON.stringify({ decision, note: note || undefined }) });
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(null);
    }
  };
  return (
    <article className="border-b border-rule px-5 py-4">
      <header className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">{title(a.kind)}</h2>
        {a.incident_graph_id && <span className="label tnum text-ink-2">INC {a.incident_graph_id}</span>}
        <span className="label">requested by @{a.requested_by}</span>
        <span className="ml-auto">
          <Time iso={a.created_at} />
        </span>
      </header>

      <dl className="mt-2 grid max-w-3xl grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-0.5 font-mono text-xs">
        {Object.entries(a.params).map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-faint">{k}</dt>
            <dd className="text-ink-2 [overflow-wrap:anywhere]">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
          </div>
        ))}
      </dl>

      <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-ink-2">{a.justification}</p>

      {a.policy_notes.length > 0 && (
        <ul className="mt-2 max-w-3xl space-y-0.5">
          {a.policy_notes.map((n, i) => (
            <li key={i} className="flex gap-2 text-xs text-warning">
              <span aria-hidden>⚠</span>
              <span>{n}</span>
            </li>
          ))}
        </ul>
      )}

      {canDecide && !mine ? (
        <form
          className="mt-3 flex max-w-3xl flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void decide("approve");
          }}
        >
          <label className="sr-only" htmlFor={`note-${a.id}`}>
            Decision note
          </label>
          <Input id={`note-${a.id}`} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note for the record (optional)" className="min-w-48 flex-1" />
          <Button type="submit" variant="primary" loading={busy === "approve"} disabled={!!busy}>
            Approve and run
          </Button>
          <Button type="button" loading={busy === "deny"} disabled={!!busy} onClick={() => decide("deny")}>
            Deny
          </Button>
        </form>
      ) : (
        <p className="label mt-3">{mine ? "You requested this, so someone else has to approve it." : "Only human approvers can decide."}</p>
      )}
      {err && (
        <div className="mt-1.5">
          <ErrorLine>{err}</ErrorLine>
        </div>
      )}
    </article>
  );
}

export default function ApprovalsPage() {
  const me = useMe();
  const [view, setView] = useState<"pending" | "history">("pending");
  const { data: pending, error } = useLiveQuery<Action[]>("/actions?status=pending_approval");
  const { data: all } = useLiveQuery<Action[]>(view === "history" ? "/actions" : null);
  const canDecide = me?.kind === "human" && me.roles.includes("approver");
  const history = all?.filter((a) => a.status !== "pending_approval");

  return (
    <>
      <PageHeader title="Approvals" sub="Containment and eradication actions wait here for a person before the board runs them.">
        <Segmented
          label="View"
          value={view}
          onChange={setView}
          options={[
            { value: "pending", label: `Pending${pending?.length ? ` · ${pending.length}` : ""}` },
            { value: "history", label: "History" },
          ]}
        />
      </PageHeader>
      <div className="min-h-0 flex-1 overflow-y-auto" aria-live="polite">
        {error && <Empty title="Couldn't load actions">{error.message}</Empty>}
        {view === "pending" && pending?.length === 0 && <Empty title="Nothing waiting for approval" />}
        {view === "pending" && pending?.map((a) => <Pending key={a.id} a={a} canDecide={!!canDecide} mine={a.requested_by === me?.handle} />)}

        {view === "history" && (
          <div className="overflow-x-auto"><table className="w-full min-w-[40rem] text-left text-[13px]">
            <thead className="label sticky top-0 bg-paper">
              <tr className="border-b border-rule">
                <th className="px-5 py-2 font-normal">Action</th>
                <th className="py-2 pr-4 font-normal">Status</th>
                <th className="py-2 pr-4 font-normal">Incident</th>
                <th className="py-2 pr-4 font-normal">Requested by</th>
                <th className="py-2 pr-4 font-normal">Decided by</th>
                <th className="py-2 pr-5 text-right font-normal">When</th>
              </tr>
            </thead>
            <tbody>
              {history?.map((a) => (
                <tr key={a.id} className="border-b border-rule hover:bg-paper-2/60">
                  <td className="px-5 py-2 text-ink">{title(a.kind)}</td>
                  <td className="py-2 pr-4">
                    <Tag tone={STATUS_TONE[a.status] ?? "neutral"}>{a.status.replace("_", " ")}</Tag>
                  </td>
                  <td className="label tnum py-2 pr-4 text-ink-2">{a.incident_graph_id ?? "—"}</td>
                  <td className="py-2 pr-4 text-ink-2">@{a.requested_by}</td>
                  <td className={cx("py-2 pr-4", a.decided_by ? "text-ink-2" : "text-faint")}>{a.decided_by ? `@${a.decided_by}` : "policy"}</td>
                  <td className="py-2 pr-5 text-right">
                    <Time iso={a.created_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
        {view === "history" && history?.length === 0 && <Empty title="No decided actions yet" />}
      </div>
    </>
  );
}
