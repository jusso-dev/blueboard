import { Link } from "react-router";
import { PageHeader, useMe } from "../components/shell";
import { useLiveQuery, type BoardStatus } from "../lib/api";
import { Empty, Tag } from "../components/ui";

type Setup = { ok: boolean; checks: { status: "ok" | "warning" | "failed" }[] };
type Posture = { score: number; max_score: number; controls: { state: string }[] };
type Participant = { kind: string; enabled: boolean; roles: string[]; last_seen_at: string | null };

type Tone = "good" | "warning" | "critical" | "neutral";

function Tile({ to, title, summary, status, tone, detail }: { to: string; title: string; summary: string; status?: string; tone?: Tone; detail?: string }) {
  return (
    <Link
      to={to}
      className="group flex min-h-32 flex-col rounded-[var(--radius-control)] border border-rule bg-paper px-4 py-3 transition-colors duration-150 hover:border-control hover:bg-paper-2 focus-visible:border-accent focus-visible:outline-none"
    >
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold group-hover:text-accent">{title}</h2>
        {status && <Tag tone={tone ?? "neutral"}>{status}</Tag>}
      </div>
      <p className="mt-1 text-[13px] text-muted">{summary}</p>
      {detail && <p className="mt-auto pt-2 text-xs text-ink-2">{detail}</p>}
    </Link>
  );
}

const DAY = 86_400_000;

/**
 * Admin centre (Board.Admin): one place for running the board, in the shape of the Microsoft 365 / Entra admin
 * centres. Each tile shows its live state and links to the page that changes it.
 */
export default function AdminCenterPage() {
  const me = useMe();
  const isAdmin = me?.roles.includes("admin");
  const { data: setup } = useLiveQuery<Setup>(isAdmin ? "/setup" : null);
  const { data: posture } = useLiveQuery<Posture>(isAdmin ? "/manage/posture" : null);
  const { data: people } = useLiveQuery<Participant[]>(isAdmin ? "/manage/participants" : null);
  const { data: status } = useLiveQuery<BoardStatus>("/status");

  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Admin centre" />
        <Empty title="The admin centre is for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }

  const failed = setup?.checks.filter((c) => c.status === "failed").length ?? 0;
  const warned = setup?.checks.filter((c) => c.status === "warning").length ?? 0;
  const gaps = posture?.controls.filter((c) => (c.state === "not_met" || c.state === "partial")).length ?? 0;
  const enabled = people?.filter((p) => p.enabled) ?? [];
  const approvers = enabled.filter((p) => p.kind === "human" && p.roles.includes("approver")).length;
  const stale = enabled.filter((p) => !p.last_seen_at || Date.now() - Date.parse(p.last_seen_at) > 30 * DAY).length;
  const agents = enabled.filter((p) => p.kind === "agent").length;

  return (
    <>
      <PageHeader title="Admin centre" sub="Run, secure and evidence the board. Every change here is in the audit log." />
      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        <div className="grid grid-cols-3 gap-3 max-lg:grid-cols-2 max-sm:grid-cols-1">
          <Tile
            to="/setup"
            title="Setup and readiness"
            summary="Health checks and the go-live stages: deployed, connected, governed, live."
            status={setup ? (failed ? `${failed} failed` : warned ? `${warned} to review` : "All OK") : undefined}
            tone={failed ? "critical" : warned ? "warning" : "good"}
          />
          <Tile
            to="/admin/posture"
            title="Posture"
            summary="Configured enterprise controls, their evidence limits and the next step for each gap."
            status={posture ? `${posture.score} / ${posture.max_score}` : undefined}
            tone={gaps ? "warning" : "good"}
            detail={posture ? (gaps ? `${gaps} control(s) need review` : "Scored settings met; external checks remain") : undefined}
          />
          <Tile
            to="/admin/participants"
            title="Access review"
            summary="People and agents, their roles from Entra, last activity, and disable with a reason."
            status={people ? (approvers < 2 ? "Too few approvers" : stale ? `${stale} inactive` : "Current") : undefined}
            tone={approvers < 2 ? "critical" : stale ? "warning" : "good"}
            detail={people ? `${enabled.length - agents} people · ${agents} agents · ${approvers} approvers` : undefined}
          />
          <Tile to="/admin/audit" title="Audit log" summary="Every approval, action, role change, export and admin change. Filter and export CSV." detail="Append-only for the application role" />
          <Tile to="/policy" title="Action policy" summary="Protected assets, approval rules and the simulator, before anything runs." />
          <Tile
            to="/admin/participants"
            title="Broker"
            summary="Pause every brokered write at once, or see why it is in dry run."
            status={status ? (status.broker === "paused" ? "Paused" : status.broker === "dry_run" ? "Dry run" : "Live") : undefined}
            tone={status?.broker === "paused" ? "critical" : status?.broker === "dry_run" ? "warning" : "good"}
          />
          <Tile to="/settings/notifications" title="Notifications" summary="Who hears about approvals, questions and results, on Teams, email, webhook or ntfy." />
          <Tile to="/reports" title="Reports" summary="Response times, coverage and dry-run evidence for the go-live decision. CSV exports are audited." />
          <Tile
            to="/admin/posture"
            title="Session and lifecycle"
            summary="Idle sign-out, inactive-account disable and data retention."
            status={status ? (status.session_idle_minutes ? `Idle ${status.session_idle_minutes} min` : "Idle sign-out off") : undefined}
            tone={status?.session_idle_minutes ? "good" : "warning"}
          />
        </div>
      </div>
    </>
  );
}
