import { useState, type ReactNode } from "react";
import { Link } from "react-router";
import type { IncidentSummary, SummaryEntity } from "../lib/api";
import { ageText, VERDICT_LABEL } from "../lib/queue";
import { Button, cx, Tag, Time } from "./ui";

/**
 * The incident summary: a deterministic roll-up from the API (never model-written), above the thread.
 *
 * Extension point: `entityAction` renders next to each user and device chip. The action-request workstream passes
 * a "Request action" button here, e.g. `entityAction={(e) => <RequestActionButton entity={e} />}`, without touching
 * this file.
 */
export function SummaryPanel({
  s,
  onOpenThread,
  entityAction,
}: {
  s: IncidentSummary;
  onOpenThread: (rootId: string) => void;
  entityAction?: (e: SummaryEntity) => ReactNode;
}) {
  const v = s.verdict;
  return (
    <section aria-label="Incident summary" className="shrink-0 border-b border-rule">
      <div className="grid gap-x-6 gap-y-3 px-6 max-sm:px-4 py-3 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <div className="min-w-0 space-y-3">
          <Block title="Verdict">
            {v ? (
              <div className="space-y-1">
                <p className="text-ui">
                  <button type="button" onClick={() => onOpenThread(v.thread_id)} className="font-medium text-ink hover:text-accent">
                    {VERDICT_LABEL[v.classification] ?? v.classification}
                  </button>
                  <span className="tnum text-ink-2"> · {Math.round(v.confidence * 100)}% confidence</span>
                  {v.determination && <span className="text-muted"> · {v.determination}</span>}
                </p>
                <p className="label">
                  @{v.author}
                  {v.author_kind === "agent" && " (agent)"} · <Time iso={v.at} />
                </p>
                {v.not_in_evidence.length > 0 && (
                  <p className="text-xs text-warning">
                    <span aria-hidden>⚠ </span>Not in evidence: <span className="font-mono [overflow-wrap:anywhere]">{v.not_in_evidence.join(", ")}</span>
                  </p>
                )}
                {s.verdicts_disagree && (
                  <p className="text-xs text-warning">
                    <span aria-hidden>⚠ </span>Verdicts disagree:{" "}
                    {s.verdicts.map((x) => `@${x.author} ${VERDICT_LABEL[x.classification] ?? x.classification}`).join(", ")}
                  </p>
                )}
              </div>
            ) : (
              <p className="text-ui text-faint">No verdict yet.</p>
            )}
          </Block>

          {s.entities.length > 0 && (
            <Block title="Entities">
              <ul className="flex flex-wrap gap-1.5">
                {s.entities.map((e) => (
                  <li key={`${e.kind}:${e.id}`} className="flex items-center gap-1">
                    <span className="inline-flex h-6 max-w-64 items-center gap-1.5 rounded-[var(--radius-control)] border border-rule px-2 text-xs" title={e.id}>
                      <span className="label">{e.kind}</span>
                      <span className="truncate text-ink-2">{e.label}</span>
                    </span>
                    {entityAction?.(e)}
                  </li>
                ))}
              </ul>
            </Block>
          )}

          {s.playbook && <PlaybookBlock p={s.playbook} onOpenThread={onOpenThread} />}
        </div>

        <div className="min-w-0 space-y-3">
          <Block title={`Indicators${s.iocs.length ? ` · ${s.iocs.length}` : ""}`}>
            {s.iocs.length === 0 ? (
              <p className="text-ui text-faint">None reported.</p>
            ) : (
              <div className="max-h-36 overflow-auto">
                <table className="w-full min-w-[30rem] text-xs">
                  <thead className="sr-only">
                    <tr>
                      <th scope="col">Kind</th>
                      <th scope="col">Value</th>
                      <th scope="col">Verdict</th>
                      <th scope="col">Evidence</th>
                      <th scope="col">Reported by</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono">
                    {s.iocs.map((i) => (
                      <tr key={`${i.kind}:${i.value}`} className="border-t border-rule first:border-t-0">
                        <td className="w-14 py-1 pr-2 text-faint">{i.kind}</td>
                        <td className="py-1 pr-2 text-ink-2 [overflow-wrap:anywhere]">
                          <button type="button" className="text-left hover:text-accent" onClick={() => onOpenThread(i.thread_id)}>
                            {i.value}
                          </button>
                        </td>
                        <td className={cx("w-20 py-1 pr-2", i.verdict === "malicious" ? "text-critical" : i.verdict === "suspicious" ? "text-warning" : "text-muted")}>{i.verdict}</td>
                        <td className="w-28 whitespace-nowrap py-1 pr-2">
                          {i.in_evidence ? (
                            <span className="text-good">✓ in evidence</span>
                          ) : i.not_in_evidence ? (
                            <span className="text-warning">not in evidence</span>
                          ) : (
                            <span className="text-muted">in a finding</span>
                          )}
                        </td>
                        <td className="truncate py-1 text-muted" title={`first seen ${new Date(i.first_seen).toLocaleString()}`}>
                          {i.reporters.map((r) => `@${r}`).join(", ")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Block>

          <div className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
            <Block title={`Actions${s.actions.length ? ` · ${s.actions.length}` : ""}`}>
              {s.actions.length === 0 ? (
                <p className="text-ui text-faint">None requested.</p>
              ) : (
                <ul className="max-h-28 space-y-0.5 overflow-auto">
                  {s.actions.map((a) => (
                    <li key={a.id} className="flex min-w-0 items-center gap-2 text-ui">
                      {a.status === "pending_approval" ? (
                        <Link to="/approvals" className="min-w-0 flex-1 truncate text-ink hover:text-accent">
                          {a.title}
                        </Link>
                      ) : a.request_message_id ? (
                        <button type="button" onClick={() => onOpenThread(a.request_message_id!)} className="min-w-0 flex-1 truncate text-left text-ink-2 hover:text-accent">
                          {a.title}
                        </button>
                      ) : (
                        <span className="min-w-0 flex-1 truncate text-ink-2">{a.title}</span>
                      )}
                      <Tag tone={a.status === "pending_approval" ? "warning" : a.status === "succeeded" ? "good" : a.status === "failed" || a.status === "rejected" ? "critical" : "neutral"}>
                        {a.status_text}
                      </Tag>
                    </li>
                  ))}
                </ul>
              )}
            </Block>

            <Block title={`Open asks${s.open_asks.length ? ` · ${s.open_asks.length}` : ""}`}>
              {s.open_asks.length === 0 ? (
                <p className="text-ui text-faint">None.</p>
              ) : (
                <ul className="max-h-28 space-y-0.5 overflow-auto">
                  {s.open_asks.map((q) => (
                    <li key={q.message_id} className="flex min-w-0 items-baseline gap-2 text-ui">
                      <button type="button" onClick={() => onOpenThread(q.thread_id)} className="min-w-0 flex-1 truncate text-left text-ink-2 hover:text-accent">
                        {q.excerpt}
                      </button>
                      <span className="label tnum shrink-0">open {ageText(q.created_at)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Block>
          </div>
        </div>
      </div>
    </section>
  );
}

const STEP_STATE: Record<string, string> = { done: "done", claimed: "claimed", open: "open", hidden: "waiting" };

function PlaybookBlock({ p, onOpenThread }: { p: NonNullable<IncidentSummary["playbook"]>; onOpenThread: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
  return (
    <Block title={`Playbook · ${p.title}`}>
      <div className="flex items-center gap-2">
        <div className="h-1 w-24 overflow-hidden rounded-full bg-paper-3" role="progressbar" aria-label={`${p.title} progress`} aria-valuemin={0} aria-valuemax={p.total} aria-valuenow={p.done}>
          <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
        </div>
        <span className="tnum text-ui text-ink-2">
          {p.done} of {p.total} steps done
        </span>
        <Button size="sm" variant="ghost" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          {open ? "Hide steps" : "Show steps"}
        </Button>
      </div>
      {open && (
        <ol className="mt-1.5 space-y-0.5">
          {p.steps.map((st, n) => (
            <li key={st.id} className="flex min-w-0 items-baseline gap-2 text-ui">
              <span className="label tnum w-4 shrink-0 text-right">{n + 1}</span>
              {st.thread_id ? (
                <button type="button" onClick={() => onOpenThread(st.thread_id!)} className={cx("min-w-0 flex-1 truncate text-left hover:text-accent", st.state === "done" ? "text-muted line-through" : "text-ink-2")}>
                  {st.title}
                </button>
              ) : (
                <span className="min-w-0 flex-1 truncate text-faint">{st.title}</span>
              )}
              <span className={cx("label shrink-0", st.state === "done" && "text-good")}>
                {STEP_STATE[st.state] ?? st.state}
                {st.claimed_by && st.state !== "open" ? ` · @${st.claimed_by}` : ""}
              </span>
            </li>
          ))}
        </ol>
      )}
    </Block>
  );
}

function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <h2 className="label pb-1">{title}</h2>
      {children}
    </div>
  );
}

/** Copy the API's Markdown summary (untrusted text already escaped server-side). Silent success, inline error. */
export function CopySummaryButton({ markdown }: { markdown: string }) {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");
  return (
    <span className="flex items-center gap-2">
      <Button
        size="sm"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(markdown);
            setState("copied");
            setTimeout(() => setState("idle"), 2000);
          } catch {
            setState("error");
          }
        }}
      >
        {state === "copied" ? "Copied" : "Copy summary"}
      </Button>
      {state === "error" && (
        <span role="alert" className="text-xs text-critical">
          Couldn't copy
        </span>
      )}
    </span>
  );
}
