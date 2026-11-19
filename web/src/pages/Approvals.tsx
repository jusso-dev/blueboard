import { useEffect, useState } from "react";
import { useLocation } from "react-router";
import { PageHeader, useMe } from "../components/shell";
import { api, refreshAll, useLiveQuery, type Action, type BoardStatus } from "../lib/api";
import { actionTitle } from "../lib/actions";
import { ActionStatusTag } from "../components/request-action";
import { Button, cx, Empty, ErrorLine, Input, Segmented, Tag, Time, fmtDuration } from "../components/ui";

/** "expires in 3.2h" / "expired": time left is a word, not a colour. */
function Expiry({ iso }: { iso: string }) {
  const left = (new Date(iso).getTime() - Date.now()) / 1000;
  return (
    <span className={cx("label tnum", left < 1800 && "text-warning")} title={new Date(iso).toLocaleString()}>
      {left <= 0 ? "expired" : `expires in ${fmtDuration(left)}`}
    </span>
  );
}

/**
 * Deep links from notifications: /approvals#<action-id> scrolls to that action and highlights it until the next
 * navigation. Returns the id being targeted.
 */
function useTargetAction(ready: boolean) {
  const { hash } = useLocation();
  const id = /^#[0-9a-f-]{36}$/i.test(hash) ? hash.slice(1) : null;
  useEffect(() => {
    if (!id || !ready) return;
    const el = document.getElementById(`action-${id}`);
    if (!el) return;
    el.scrollIntoView({ block: "center", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    el.focus({ preventScroll: true });
  }, [id, ready]);
  return id;
}

/** Approved while the broker was paused: an approver (not the requester) sends it with Run now once resumed. */
function Held({ a, canRun, mine, paused, target }: { a: Action; canRun: boolean; mine: boolean; paused: boolean; target: boolean }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/actions/${a.id}/run`, { method: "POST" });
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <article id={`action-${a.id}`} tabIndex={-1} aria-current={target || undefined} className={cx("border-b border-rule px-5 py-4 focus:outline-none", target && "bg-accent-soft/30 shadow-[inset_2px_0_0_var(--color-accent)]")}>
      <header className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">{actionTitle(a.kind)}</h2>
        <Tag tone="warning">held</Tag>
        {a.incident_graph_id && <span className="label tnum text-ink-2">INC {a.incident_graph_id}</span>}
        <span className="label">
          requested by @{a.requested_by} · approved by @{a.decided_by ?? "policy"}
        </span>
        <span className="ml-auto">
          <Time iso={a.created_at} />
        </span>
      </header>
      <p className="mt-1 text-[13px] text-muted">
        Approved while the broker was paused, so it hasn't run. {paused ? "Resume the broker first." : "Check it still makes sense, then run it."}
      </p>
      {canRun && !mine ? (
        <div className="mt-2">
          <Button variant="primary" loading={busy} disabled={paused} onClick={() => void run()}>
            Run now
          </Button>
        </div>
      ) : (
        <p className="label mt-2">{mine ? "You requested this, so someone else has to run it." : "Only human approvers can run held actions."}</p>
      )}
      {err && (
        <div className="mt-1.5">
          <ErrorLine>{err}</ErrorLine>
        </div>
      )}
    </article>
  );
}

function Pending({ a, canDecide, me, target }: { a: Action; canDecide: boolean; me: string | undefined; target: boolean }) {
  const [note, setNote] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const required = a.approvals_required ?? 1;
  const approvals = a.approvals ?? [];
  const mine = a.requested_by === me;
  const approvedByMe = !!me && approvals.includes(me);
  const needsConfirm = !!a.confirm_prompt;
  const decide = async (decision: "approve" | "deny") => {
    setBusy(decision);
    setErr(null);
    try {
      await api(`/actions/${a.id}`, { method: "POST", body: JSON.stringify({ decision, note: note || undefined, confirm: confirm || undefined }) });
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(null);
    }
  };
  const confirmed = !needsConfirm || confirm.trim().length > 0;
  return (
    <article
      id={`action-${a.id}`}
      tabIndex={-1}
      aria-current={target || undefined}
      className={cx("border-b border-rule px-5 py-4 focus:outline-none", target && "bg-accent-soft/30 shadow-[inset_2px_0_0_var(--color-accent)]")}
    >
      <header className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">{actionTitle(a.kind)}</h2>
        {target && <Tag tone="accent">linked</Tag>}
        {a.incident_graph_id && <span className="label tnum text-ink-2">INC {a.incident_graph_id}</span>}
        <span className="label">requested by @{a.requested_by}</span>
        {required > 1 && (
          <span className="label tnum text-ink-2" aria-label={`${approvals.length} of ${required} approvals`}>
            {approvals.length} of {required} approvals{approvals.length > 0 ? ` (@${approvals.join(", @")})` : ""}
          </span>
        )}
        <span className="ml-auto flex items-center gap-3">
          {a.expires_at && <Expiry iso={a.expires_at} />}
          <span className="label">
            age <Time iso={a.created_at} />
          </span>
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

      {canDecide && !mine && !approvedByMe ? (
        <form
          className="mt-3 flex max-w-3xl flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (confirmed) void decide("approve");
          }}
        >
          {needsConfirm && (
            <>
              <label className="sr-only" htmlFor={`confirm-${a.id}`}>
                Type {a.confirm_prompt} to confirm
              </label>
              <Input
                id={`confirm-${a.id}`}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder={`Type ${a.confirm_prompt} to confirm`}
                autoComplete="off"
                spellCheck={false}
                className="min-w-64 flex-1 font-mono"
              />
            </>
          )}
          <label className="sr-only" htmlFor={`note-${a.id}`}>
            Decision note
          </label>
          <Input id={`note-${a.id}`} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note for the record (optional)" className="min-w-48 flex-1" />
          <Button type="submit" variant="primary" loading={busy === "approve"} disabled={!!busy || !confirmed}>
            {required > 1 && approvals.length + 1 < required ? `Approve (1 of ${required})` : "Approve and run"}
          </Button>
          <Button type="button" loading={busy === "deny"} disabled={!!busy} onClick={() => decide("deny")}>
            Deny
          </Button>
        </form>
      ) : (
        <p className="label mt-3">
          {mine
            ? "You requested this, so a different approver has to approve it."
            : approvedByMe
              ? "You approved this. A second, different approver must complete it."
              : "Only human approvers can decide."}
        </p>
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
  const { data: pending, error } = useLiveQuery<Action[]>("/actions?status=open");
  const { data: held } = useLiveQuery<Action[]>("/actions?status=held");
  const { data: status } = useLiveQuery<BoardStatus>("/status");
  const { data: all } = useLiveQuery<Action[]>(view === "history" ? "/actions" : null);
  const canDecide = me?.kind === "human" && me.roles.includes("approver");
  const history = all?.filter((a) => a.status !== "pending_approval" && a.status !== "approved_once" && !a.held_at);
  const target = useTargetAction(pending !== undefined && held !== undefined && (view === "pending" || all !== undefined));
  // A link to an action that's already decided opens History with that row highlighted.
  useEffect(() => {
    if (target && pending && held && !pending.some((a) => a.id === target) && !held.some((a) => a.id === target)) setView("history");
  }, [target, pending, held]);

  return (
    <>
      <PageHeader title="Approvals" sub="Containment and eradication actions wait here for a person before the board runs them. Requests expire if nobody decides.">
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
        {view === "pending" && held && held.length > 0 && (
          <section aria-label="Held actions">
            {held.map((a) => (
              <Held key={a.id} a={a} canRun={!!canDecide} mine={a.requested_by === me?.handle} paused={status?.broker === "paused"} target={target === a.id} />
            ))}
          </section>
        )}
        {view === "pending" && pending?.length === 0 && !held?.length && <Empty title="Nothing waiting for approval" />}
        {view === "pending" && pending?.map((a) => <Pending key={a.id} a={a} canDecide={!!canDecide} me={me?.handle} target={target === a.id} />)}

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
                <tr
                  key={a.id}
                  id={`action-${a.id}`}
                  tabIndex={-1}
                  aria-current={target === a.id || undefined}
                  className={cx("border-b border-rule hover:bg-paper-2/60 focus:outline-none", target === a.id && "bg-accent-soft/30")}
                >
                  <td className="px-5 py-2 text-ink">{actionTitle(a.kind)}</td>
                  <td className="py-2 pr-4">
                    <ActionStatusTag status={a.status} />
                  </td>
                  <td className="label tnum py-2 pr-4 text-ink-2">{a.incident_graph_id ?? "—"}</td>
                  <td className="py-2 pr-4 text-ink-2">@{a.requested_by}</td>
                  <td className={cx("py-2 pr-4", a.decided_by ? "text-ink-2" : "text-faint")}>
                    {a.approvals && a.approvals.length > 1 ? a.approvals.map((h) => `@${h}`).join(", ") : a.decided_by ? `@${a.decided_by}` : a.status === "expired" ? "nobody (expired)" : "policy"}
                  </td>
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
