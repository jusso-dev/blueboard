import { useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, ApiError, download, refreshAll, useLiveQuery } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Input, Tag, Time } from "../components/ui";

type Participant = {
  id: string;
  handle: string;
  display_name: string;
  kind: "agent" | "human";
  roles: string[];
  last_seen_at: string | null;
  posts24h: number;
  actions24h: number;
  enabled: boolean;
  disabled_reason: string | null;
  disabled_by: string | null;
  disabled_at: string | null;
  rate_limit: unknown;
};
type Pause = { paused: boolean; by: string | null; at: string | null; reason: string | null };

/** A change that needs a reason: the form opens inline, next to the control (design.md: errors next to the cause). */
function ReasonForm({ label, verb, danger, onSubmit, onCancel }: { label: string; verb: string; danger?: boolean; onSubmit: (reason: string) => Promise<void>; onCancel: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <form
      className="mt-2 flex max-w-xl flex-wrap items-start gap-2"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setErr(null);
        try {
          await onSubmit(reason);
        } catch (x) {
          setErr(x instanceof ApiError ? x.message : String(x));
          setBusy(false);
        }
      }}
    >
      <label className="sr-only" htmlFor={`reason-${label}`}>
        Reason
      </label>
      <Input id={`reason-${label}`} autoFocus required minLength={5} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (required, kept in the audit log)" className="min-w-56 flex-1" />
      <Button type="submit" variant={danger ? "danger" : "primary"} loading={busy}>
        {verb}
      </Button>
      <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>
        Cancel
      </Button>
      {err && (
        <div className="basis-full">
          <ErrorLine>{err}</ErrorLine>
        </div>
      )}
    </form>
  );
}

function BrokerCard() {
  const { data: pause } = useLiveQuery<Pause>("/manage/broker");
  const [open, setOpen] = useState(false);
  if (!pause) return null;
  const set = async (paused: boolean, reason: string) => {
    await api("/manage/broker", { method: "POST", body: JSON.stringify({ paused, reason }) });
    setOpen(false);
    refreshAll();
  };
  return (
    <section aria-labelledby="broker" className="border-b border-rule px-5 py-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="broker" className="text-sm font-semibold">
          Broker
        </h2>
        <Tag tone={pause.paused ? "critical" : "good"}>{pause.paused ? "paused" : "running"}</Tag>
        {pause.by && pause.at && (
          <span className="label">
            {pause.paused ? "paused" : "resumed"} by @{pause.by} <Time iso={pause.at} />
          </span>
        )}
      </div>
      <p className="mt-1 max-w-2xl text-[13px] text-muted">
        {pause.paused
          ? `Nothing runs in the tenant. Approvals are still recorded; approved actions are held until an approver chooses Run now after you resume.${pause.reason ? ` Reason: ${pause.reason}` : ""}`
          : "Pausing stops every brokered write on every instance at once, without touching Azure settings. BROKER_EXECUTE=false still turns execution off for good."}
      </p>
      {!open && (
        <div className="mt-2">
          <Button variant={pause.paused ? "primary" : "danger"} onClick={() => setOpen(true)}>
            {pause.paused ? "Resume broker" : "Pause broker"}
          </Button>
        </div>
      )}
      {open && <ReasonForm label="broker" verb={pause.paused ? "Resume broker" : "Pause broker"} danger={!pause.paused} onSubmit={(r) => set(!pause.paused, r)} onCancel={() => setOpen(false)} />}
    </section>
  );
}

const DAY = 86_400_000;

/** What an access reviewer should look at: privileged roles, inactivity, never signed in. Words, not colour alone. */
export function reviewFlags(p: Pick<Participant, "kind" | "roles" | "last_seen_at" | "enabled">, now = Date.now()): string[] {
  if (!p.enabled) return [];
  const flags: string[] = [];
  if (!p.last_seen_at) flags.push("never signed in");
  else if (now - Date.parse(p.last_seen_at) > 30 * DAY) flags.push(`inactive ${Math.floor((now - Date.parse(p.last_seen_at)) / DAY)} days`);
  if (p.kind === "human" && p.roles.includes("admin")) flags.push("privileged: admin");
  else if (p.kind === "human" && p.roles.includes("approver")) flags.push("privileged: approver");
  if (p.kind === "agent" && p.roles.includes("requester")) flags.push("can request actions");
  return flags;
}

function Review({ p }: { p: Participant }) {
  const flags = reviewFlags(p);
  if (flags.length === 0) return <span className="label">{p.enabled ? "no flags" : "disabled"}</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {flags.map((f) => (
        <Tag key={f} tone={f.startsWith("inactive") || f === "never signed in" ? "warning" : "neutral"}>
          {f}
        </Tag>
      ))}
    </div>
  );
}

function ParticipantRow({ p, self }: { p: Participant; self: boolean }) {
  const [open, setOpen] = useState(false);
  const toggle = async (reason: string) => {
    await api(`/manage/participants/${encodeURIComponent(p.handle)}`, { method: "POST", body: JSON.stringify({ enabled: !p.enabled, reason }) });
    setOpen(false);
    refreshAll();
  };
  return (
    <>
      <tr className={cx("border-b border-rule align-top", !p.enabled && "text-muted")}>
        <td className="px-5 py-2">
          <p className="text-ink">@{p.handle}</p>
          <p className="truncate text-xs text-muted">{p.display_name}</p>
        </td>
        <td className="py-2 pr-4">
          <Tag tone={p.kind === "agent" ? "accent" : "neutral"}>{p.kind}</Tag>
        </td>
        <td className="py-2 pr-4 font-mono text-xs text-ink-2">{p.roles.length ? p.roles.join(", ") : "none"}</td>
        <td className="py-2 pr-4">{p.last_seen_at ? <Time iso={p.last_seen_at} /> : <span className="label">never</span>}</td>
        <td className="tnum py-2 pr-4 text-right">{p.posts24h}</td>
        <td className="tnum py-2 pr-4 text-right">{p.actions24h}</td>
        <td className="py-2 pr-4">
          <Review p={p} />
        </td>
        <td className="py-2 pr-5">
          <div className="flex items-center justify-end gap-2">
            {p.enabled ? <Tag tone="good">enabled</Tag> : <Tag tone="critical">disabled</Tag>}
            {!self && !open && (
              <Button size="sm" variant={p.enabled ? "danger" : "secondary"} onClick={() => setOpen(true)} aria-label={`${p.enabled ? "Disable" : "Enable"} @${p.handle}`}>
                {p.enabled ? "Disable" : "Enable"}
              </Button>
            )}
          </div>
          {!p.enabled && p.disabled_reason && (
            <p className="mt-1 max-w-64 text-right text-xs text-muted">
              by @{p.disabled_by}: {p.disabled_reason}
            </p>
          )}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-rule">
          <td colSpan={8} className="px-5 pb-3">
            <ReasonForm label={p.handle} verb={p.enabled ? `Disable @${p.handle}` : `Enable @${p.handle}`} danger={p.enabled} onSubmit={toggle} onCancel={() => setOpen(false)} />
          </td>
        </tr>
      )}
    </>
  );
}

/** Admin → Participants (Board.Admin): every agent and person, activity, enable/disable, and the broker pause. */
export default function ParticipantsPage() {
  const me = useMe();
  const isAdmin = me?.roles.includes("admin");
  const { data: list, error } = useLiveQuery<Participant[]>(isAdmin ? "/manage/participants" : null);
  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Access review" />
        <Empty title="Participants are for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Access review"
        sub="People and agents on the board. Roles are as last seen in Entra: grant or remove them in Entra (groups, PIM). Disable here to cut access at once."
      >
        <Button onClick={() => void download("/manage/audit?event=principal.&format=csv", `blueboard-access-changes-${new Date().toISOString().slice(0, 10)}.csv`)}>
          Export access changes
        </Button>
      </PageHeader>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {isAdmin && <BrokerCard />}
        {error && <Empty title="Couldn't load participants">{error.message}</Empty>}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[56rem] text-left text-[13px]">
            <thead className="label sticky top-0 bg-paper">
              <tr className="border-b border-rule">
                <th className="px-5 py-2 font-normal">Principal</th>
                <th className="py-2 pr-4 font-normal">Kind</th>
                <th className="py-2 pr-4 font-normal">Roles (last seen)</th>
                <th className="py-2 pr-4 font-normal">Last seen</th>
                <th className="py-2 pr-4 text-right font-normal">Posts 24h</th>
                <th className="py-2 pr-4 text-right font-normal">Actions 24h</th>
                <th className="py-2 pr-4 font-normal">Review</th>
                <th className="py-2 pr-5 text-right font-normal">Access</th>
              </tr>
            </thead>
            <tbody>
              {list?.map((p) => (
                <ParticipantRow key={p.id} p={p} self={p.handle === me?.handle} />
              ))}
            </tbody>
          </table>
        </div>
        {list?.length === 0 && <Empty title="Nobody has signed in yet" />}
      </div>
    </>
  );
}
