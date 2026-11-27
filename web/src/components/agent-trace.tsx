import { useEffect, useState } from "react";
import { api, ApiError, useLiveQuery, type Message } from "../lib/api";
import { argLine, FEEDBACK_TYPES, reasoningOf, TRACE_STATUS, type MessageFeedback, type TraceCall } from "../lib/agents";
import { Button, cx, ErrorLine, Input, Select, Tag } from "./ui";

/** The trace as a list: one row per MCP call, KQL shown in full for hunting queries. Arguments are redacted server-side. */
export function TraceList({ calls, showAgent }: { calls: TraceCall[]; showAgent?: boolean }) {
  if (calls.length === 0) return <p className="text-xs text-muted">No tool calls recorded for this.</p>;
  return (
    <ol className="space-y-1.5">
      {calls.map((c) => {
        const s = TRACE_STATUS[c.status] ?? { label: c.status, tone: "neutral" as const };
        return (
          <li key={c.id} className="rounded-[4px] border border-rule bg-paper px-2 py-1.5 text-xs">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
              <time dateTime={c.at} title={new Date(c.at).toLocaleString()} className="label tnum">
                {new Date(c.at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </time>
              {showAgent && <span className="text-ink-2">@{c.handle}</span>}
              <span className="font-mono text-ink">{c.tool}</span>
              <Tag tone={s.tone}>{s.label}</Tag>
              <span className="label tnum">
                {c.duration_ms} ms · {c.result_bytes.toLocaleString()} B
              </span>
              {c.incident_inferred && <span className="label" title="Linked through the claim the agent held at the time">via claim</span>}
            </div>
            {argLine(c.args) && <p className="mt-0.5 font-mono text-muted [overflow-wrap:anywhere]">{argLine(c.args)}</p>}
            {c.kql && (
              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap rounded-[4px] bg-paper-2 p-1.5 font-mono text-[11px] text-ink-2">{c.kql}</pre>
            )}
            {c.error && <p className="mt-0.5 text-critical">{c.error}</p>}
          </li>
        );
      })}
    </ol>
  );
}

/** "Agent trace" under an agent message: fetched only when opened. */
export function MessageTrace({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const { data, error } = useLiveQuery<TraceCall[]>(open ? `/messages/${id}/trace` : null);
  return (
    <details className="mt-1" onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="cursor-pointer text-xs text-muted hover:text-ink">Agent trace{data ? ` (${data.length} calls)` : ""}</summary>
      <div className="mt-1 max-w-3xl">
        {error && <ErrorLine>{error.message}</ErrorLine>}
        {data && <TraceList calls={data} />}
      </div>
    </details>
  );
}

/** An agent's optional `reasoning` payload field, collapsed. Untrusted text: shown as plain text. */
export function Reasoning({ payload }: { payload: unknown }) {
  const r = reasoningOf(payload);
  if (!r) return null;
  return (
    <details className="mt-1">
      <summary className="cursor-pointer text-xs text-muted hover:text-ink">Reasoning</summary>
      <p className="mt-1 max-w-3xl whitespace-pre-wrap rounded-[4px] border border-rule bg-paper-2 p-2 text-xs text-ink-2">{r}</p>
    </details>
  );
}

const CLASSIFICATIONS = [
  { value: "truePositive", label: "true positive" },
  { value: "falsePositive", label: "false positive" },
  { value: "informationalExpectedActivity", label: "expected activity" },
  { value: "unknown", label: "unknown" },
];

/** Correct / incorrect on an agent's verdict, finding or ioc (people only; the API refuses agents). */
export function FeedbackBar({ m }: { m: Message }) {
  // Fetched once, not polled: a feed can show many agent verdicts. Writes return the new state.
  const [data, setData] = useState<MessageFeedback | null>(null);
  useEffect(() => {
    let live = true;
    api<MessageFeedback>(`/messages/${m.id}/feedback`).then((d) => live && setData(d), () => {});
    return () => void (live = false);
  }, [m.id]);
  const [form, setForm] = useState(false);
  const [reason, setReason] = useState("");
  const [corrected, setCorrected] = useState("falsePositive");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const isVerdict = m.type === "verdict";

  const send = async (verdict: "correct" | "incorrect" | null) => {
    setBusy(true);
    setErr(null);
    try {
      if (verdict === null) setData(await api<MessageFeedback>(`/messages/${m.id}/feedback`, { method: "DELETE" }));
      else
        setData(await api<MessageFeedback>(`/messages/${m.id}/feedback`, {
          method: "POST",
          body: JSON.stringify({ verdict, reason: reason.trim() || null, corrected_classification: verdict === "incorrect" && isVerdict ? corrected : null }),
        }));
      setForm(false);
      setReason("");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const overturn = data?.items.find((i) => i.source === "resolution");
  return (
    <div className="mt-1 text-xs">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-muted">Was this right?</span>
        <button
          type="button"
          disabled={busy}
          aria-pressed={data?.mine === "correct"}
          onClick={() => void (data?.mine === "correct" ? send(null) : send("correct"))}
          className={cx("rounded-[4px] border px-1.5 py-0.5 transition-colors", data?.mine === "correct" ? "border-good text-good" : "border-rule text-ink-2 hover:border-ink-2")}
        >
          ✓ Correct{data && data.correct > 0 ? ` ${data.correct}` : ""}
        </button>
        <button
          type="button"
          disabled={busy}
          aria-pressed={data?.mine === "incorrect"}
          aria-expanded={form}
          onClick={() => (data?.mine === "incorrect" ? void send(null) : setForm((x) => !x))}
          className={cx("rounded-[4px] border px-1.5 py-0.5 transition-colors", data?.mine === "incorrect" ? "border-critical text-critical" : "border-rule text-ink-2 hover:border-ink-2")}
        >
          ✗ Incorrect{data && data.incorrect > 0 ? ` ${data.incorrect}` : ""}
        </button>
        {overturn && (
          <Tag tone={overturn.verdict === "incorrect" ? "critical" : "good"} title={overturn.reason ?? undefined}>
            {overturn.verdict === "incorrect" ? `overturned: resolved as ${overturn.corrected_classification}` : "confirmed at resolution"}
          </Tag>
        )}
      </div>
      {form && (
        <form
          className="mt-1.5 flex max-w-2xl flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void send("incorrect");
          }}
        >
          {isVerdict && (
            <label className="flex items-center gap-1 text-muted">
              Should be
              <Select aria-label="Corrected classification" value={corrected} onChange={(e) => setCorrected(e.target.value)}>
                {CLASSIFICATIONS.filter((c) => c.value !== m.payload?.classification).map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </Select>
            </label>
          )}
          <Input aria-label="Reason" maxLength={1000} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why (optional; the agent can read this)" className="min-w-56 flex-1" />
          <Button type="submit" size="sm" variant="danger" loading={busy}>
            Mark incorrect
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={() => setForm(false)} disabled={busy}>
            Cancel
          </Button>
        </form>
      )}
      {err && <ErrorLine>{err}</ErrorLine>}
    </div>
  );
}

/** Everything WS3 adds under an agent's message: reasoning, feedback (people, typed messages) and the trace. */
export function AgentMessageExtras({ m, human }: { m: Message; human: boolean }) {
  if (m.author.kind !== "agent") return null;
  return (
    <>
      <Reasoning payload={m.payload} />
      {human && FEEDBACK_TYPES.has(m.type) && <FeedbackBar m={m} />}
      <MessageTrace id={m.id} />
    </>
  );
}
