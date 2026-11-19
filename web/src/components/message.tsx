import { Link } from "react-router";
import { useState } from "react";
import { Markdown } from "./markdown";
import { api, refreshAll, type Message } from "../lib/api";
import { useMe } from "./shell";
import type { NavRowProps } from "./shortcuts";
import { Button, cx, ErrorLine, Tag, Time } from "./ui";

const CLAIMABLE = new Set(["question", "finding", "ioc"]);

/** Only the few types that change what a reader should do get a tone; the rest stay neutral. */
const TYPE_TONE: Record<string, "critical" | "warning" | "accent" | "good" | "neutral"> = {
  incident: "critical",
  action_request: "warning",
  action_result: "good",
  question: "accent",
};

const TYPE_LABEL: Record<string, string> = { action_request: "action", action_result: "result" };

const VERDICT_LABEL: Record<string, string> = {
  truePositive: "true positive",
  falsePositive: "false positive",
  informationalExpectedActivity: "expected activity",
  unknown: "unknown",
};

function Author({ m }: { m: Message }) {
  return (
    <span className="flex min-w-0 items-baseline gap-1.5">
      <span className={cx("truncate text-[13px] font-medium", m.author.kind === "system" ? "text-muted" : "text-ink")}>
        {m.author.display_name}
      </span>
      {m.author.kind === "agent" && <span className="label max-sm:hidden">agent</span>}
    </span>
  );
}

export function MessageRow({
  m,
  onOpenThread,
  showChannel,
  showIncident = true,
  selected,
  navProps,
}: {
  m: Message;
  onOpenThread?: (m: Message) => void;
  showChannel?: boolean;
  showIncident?: boolean;
  selected?: boolean;
  navProps?: NavRowProps;
}) {
  const me = useMe();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const claimable = CLAIMABLE.has(m.type);
  const iocs: { kind: string; value: string; verdict: string }[] = m.type === "ioc" ? m.payload?.indicators ?? [] : [];

  const claim = async (op: "claim" | "done" | "release") => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/claims/${m.id}`, { method: "POST", body: JSON.stringify({ op }) });
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const tone = TYPE_TONE[m.type];
  return (
    <article
      {...navProps}
      aria-label={`${m.author.display_name}: ${TYPE_LABEL[m.type] ?? m.type}`}
      className={cx(
        "group border-b border-rule px-5 py-3 transition-colors duration-150 focus-visible:outline-offset-[-2px]",
        selected ? "bg-paper-2" : "hover:bg-paper-2/60",
      )}
    >
      <header className="flex min-w-0 items-center gap-2">
        <Author m={m} />
        {m.type !== "chat" && (
          <span className="shrink-0">
            <Tag tone={tone ?? "neutral"}>{TYPE_LABEL[m.type] ?? m.type}</Tag>
          </span>
        )}
        {showIncident && m.incident_graph_id && m.incident_id && (
          <Link to={`/incidents/${m.incident_id}`} className="label tnum shrink-0 whitespace-nowrap hover:text-accent">
            INC {m.incident_graph_id}
          </Link>
        )}
        {showChannel && (
          <Link to={`/channels/${encodeURIComponent(m.channel)}`} className="label shrink-0 whitespace-nowrap hover:text-accent max-sm:hidden">
            #{m.channel}
          </Link>
        )}
        <span className="ml-auto shrink-0 pl-2">
          <Time iso={m.created_at} />
        </span>
      </header>

      <div className="mt-1">
        <Markdown text={m.snippet ?? m.body} />

        {iocs.length > 0 && (
          <table className="mt-2 w-full max-w-2xl text-xs">
            <tbody className="font-mono">
              {iocs.map((i, k) => (
                <tr key={k} className="border-t border-rule first:border-t-0">
                  <td className="w-16 py-1 pr-3 text-faint">{i.kind}</td>
                  <td className="py-1 pr-3 text-ink-2 [overflow-wrap:anywhere]">{i.value}</td>
                  <td className={cx("w-20 py-1 text-right", i.verdict === "malicious" ? "text-critical" : i.verdict === "suspicious" ? "text-warning" : "text-muted")}>
                    {i.verdict}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {m.type === "verdict" && m.payload?.classification && (
          <p className="label mt-1.5 text-ink-2">
            {VERDICT_LABEL[m.payload.classification] ?? m.payload.classification} · {Math.round((m.payload.confidence ?? 0) * 100)}% confidence
          </p>
        )}
      </div>

      {(onOpenThread || claimable) && (
        <footer className="mt-1.5 flex min-h-6 items-center gap-1">
          {onOpenThread && !m.parent_id && (
            <Button size="sm" variant="ghost" className="-ml-2.5" onClick={() => onOpenThread(m)}>
              {m.reply_count ? `${m.reply_count} ${m.reply_count === 1 ? "reply" : "replies"}` : "Reply"}
            </Button>
          )}
          {claimable && m.claim_state === "open" && (
            <Button size="sm" variant="ghost" loading={busy} onClick={() => claim("claim")}>
              Claim
            </Button>
          )}
          {claimable && m.claim_state === "claimed" && (
            <span className="flex items-center gap-1">
              <span className="label px-1">claimed by @{m.claimed_by}</span>
              {me && m.claimed_by === me.handle && (
                <>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => claim("done")}>
                    Mark done
                  </Button>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => claim("release")}>
                    Release
                  </Button>
                </>
              )}
            </span>
          )}
          {claimable && m.claim_state === "done" && <span className="label px-1 text-good">✓ handled by @{m.claimed_by}</span>}
          {err && <ErrorLine>{err}</ErrorLine>}
        </footer>
      )}
    </article>
  );
}
