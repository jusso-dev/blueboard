/**
 * Approve / Deny for one pending action, shared by the Approvals page and the inline card under an `action_request`
 * chat message. Approving is always an explicit click (or Enter in this form); no shortcut decides anything.
 */
import { useState } from "react";
import { Link } from "react-router";
import { api, refreshAll, useLiveQuery, OPEN_STATUSES, type Action } from "../lib/api";
import { actionTitle } from "../lib/actions";
import { useMe } from "./shell";
import { ActionStatusTag } from "./request-action";
import { Button, cx, ErrorLine, Input } from "./ui";

/** Approvers are human principals with the approver role (the API enforces the same). */
export function useCanDecide() {
  const me = useMe();
  return me?.kind === "human" && !!me.roles.includes("approver");
}

export function DecisionForm({ a, canDecide, me, compact = false }: { a: Action; canDecide: boolean; me: string | undefined; compact?: boolean }) {
  const [note, setNote] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const required = a.approvals_required ?? 1;
  const approvals = a.approvals ?? [];
  const mine = a.requested_by === me;
  const approvedByMe = !!me && approvals.includes(me);
  const needsConfirm = !!a.confirm_prompt;
  const confirmed = !needsConfirm || confirm.trim().length > 0;
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
  const size = compact ? "sm" : "md";

  return (
    <>
      {canDecide && !mine && !approvedByMe ? (
        <form
          aria-label={`Decide: ${actionTitle(a.kind)}`}
          className={cx("flex max-w-3xl flex-wrap gap-2", compact ? "mt-2" : "mt-3")}
          onSubmit={(e) => {
            e.preventDefault();
            if (confirmed && !busy) void decide("approve");
          }}
        >
          {needsConfirm && (
            <>
              <label className="sr-only" htmlFor={`confirm-${compact ? "c-" : ""}${a.id}`}>
                Type {a.confirm_prompt} to confirm
              </label>
              <Input
                id={`confirm-${compact ? "c-" : ""}${a.id}`}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder={`Type ${a.confirm_prompt} to confirm`}
                autoComplete="off"
                spellCheck={false}
                className={cx("min-w-0 flex-1 basis-56 font-mono", compact && "h-7 text-xs")}
              />
            </>
          )}
          {!compact && (
            <>
              <label className="sr-only" htmlFor={`note-${a.id}`}>
                Decision note
              </label>
              <Input id={`note-${a.id}`} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note for the record (optional)" className="min-w-48 flex-1" />
            </>
          )}
          <Button type="submit" size={size} variant="primary" loading={busy === "approve"} disabled={!!busy || !confirmed}>
            {required > 1 && approvals.length + 1 < required ? `Approve (1 of ${required})` : "Approve and run"}
          </Button>
          <Button type="button" size={size} loading={busy === "deny"} disabled={!!busy} onClick={() => decide("deny")}>
            Deny
          </Button>
        </form>
      ) : (
        <p className={cx("label", compact ? "mt-1.5" : "mt-3")}>
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
    </>
  );
}

/**
 * Under an `action_request` message: the action's current status (read live from /actions/{id}, not from the message
 * payload, which is a snapshot) and, for an approver while it is still open, Approve and Deny.
 */
export function InlineApproval({ actionId }: { actionId: string }) {
  const me = useMe();
  const canDecide = useCanDecide();
  const { data: a } = useLiveQuery<Action>(canDecide ? `/actions/${actionId}` : null);
  if (!canDecide || !a) return null;
  const open = OPEN_STATUSES.includes(a.status) && !a.held_at;
  const required = a.approvals_required ?? 1;
  const approvals = a.approvals ?? [];
  return (
    <section aria-label={`${actionTitle(a.kind)}: ${open ? "waiting for approval" : a.status.replace("_", " ")}`} className="mt-1.5 max-w-2xl rounded-[var(--radius-control)] border border-rule bg-paper px-3 py-2">
      <header className="flex flex-wrap items-center gap-2">
        <span className="text-[13px] font-semibold text-ink">{actionTitle(a.kind)}</span>
        <ActionStatusTag status={a.status} />
        {required > 1 && (
          <span className="label tnum text-ink-2">
            {approvals.length} of {required} approvals
          </span>
        )}
        <Link to={`/approvals#${a.id}`} className="label ml-auto hover:text-accent hover:underline">
          Open in Approvals
        </Link>
      </header>
      {open ? (
        <DecisionForm a={a} canDecide={canDecide} me={me?.handle} compact />
      ) : (
        a.decided_by && <p className="label mt-1">decided by @{a.decided_by}</p>
      )}
    </section>
  );
}
