import { Link } from "react-router";
import { Fragment, useEffect, useMemo, useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, ApiError, refreshAll, useLiveQuery } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Input, Segmented, Tag, Time } from "../components/ui";
import {
  burn,
  burnTone,
  pct,
  stackDaily,
  tokens,
  usd,
  type AgentBudgetRow,
  type AgentCostReport,
  type ObservabilitySettings,
} from "../lib/agents";

const RANGES = [
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
] as const;

/** Eight categorical steps from the theme (accent, then good/warning/critical families, then neutrals) for stacked series. */
const SERIES = ["var(--color-accent)", "var(--color-good)", "var(--color-warning)", "var(--color-critical)", "var(--color-ink-2)", "var(--color-muted)", "var(--color-faint)", "var(--color-rule-strong)"];

function Tile({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="min-w-0 border-rule px-6 max-sm:px-4 py-4 [&:not(:first-child)]:border-l max-lg:[&:nth-child(3)]:border-l-0 max-lg:[&:nth-child(n+3)]:border-t">
      <p className="text-xs text-muted">{label}</p>
      <p className="tnum mt-1 text-[28px] font-semibold leading-none tracking-tight text-ink">{value}</p>
      <p className="mt-2 text-meta text-faint">{hint}</p>
    </div>
  );
}

/** Spend per day, stacked by agent. SVG, no chart library; a table follows for exact values (and screen readers). */
function DailyChart({ r }: { r: AgentCostReport }) {
  const { days, agents, values, max } = useMemo(() => stackDaily(r.daily), [r.daily]);
  if (days.length === 0) return <p className="text-ui text-muted">No spend recorded in this range.</p>;
  const shown = agents.slice(0, SERIES.length - 1);
  const color = (h: string) => SERIES[shown.indexOf(h)] ?? SERIES[SERIES.length - 1];
  const W = 640;
  const H = 160;
  const bw = Math.max(2, W / days.length - 2);
  return (
    <figure>
      <svg viewBox={`0 0 ${W} ${H + 18}`} className="h-auto w-full max-w-3xl" role="img" aria-label={`Spend per day by agent, ${days[0]} to ${days[days.length - 1]}, peak ${usd(max)}`}>
        <line x1={0} x2={W} y1={H} y2={H} stroke="var(--color-rule)" />
        {days.map((d, i) => {
          let y = H;
          return (
            <g key={d}>
              {agents.map((h) => {
                const v = values[d]?.[h] ?? 0;
                if (!v || max === 0) return null;
                const bh = (v / max) * (H - 4);
                y -= bh;
                return (
                  <rect key={h} x={i * (W / days.length) + 1} y={y} width={bw} height={Math.max(bh, 0.5)} fill={color(h)} rx={1}>
                    <title>{`${d} @${h}: ${usd(v)}`}</title>
                  </rect>
                );
              })}
            </g>
          );
        })}
        <text x={0} y={H + 14} className="fill-[var(--color-muted)] text-[10px]">
          {days[0]}
        </text>
        <text x={W} y={H + 14} textAnchor="end" className="fill-[var(--color-muted)] text-[10px]">
          {days[days.length - 1]}
        </text>
      </svg>
      <figcaption className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-ink-2">
        {shown.map((h) => (
          <span key={h} className="inline-flex items-center gap-1">
            <span aria-hidden className="inline-block size-2.5 rounded-[2px]" style={{ background: color(h) }} />@{h}
          </span>
        ))}
        {agents.length > shown.length && (
          <span className="inline-flex items-center gap-1">
            <span aria-hidden className="inline-block size-2.5 rounded-[2px]" style={{ background: SERIES[SERIES.length - 1] }} />
            {agents.length - shown.length} more
          </span>
        )}
      </figcaption>
    </figure>
  );
}

/** Budget burn bar: the tightest limit, top-ups included. Words beside the bar, never colour alone. */
function BurnBar({ b }: { b: AgentBudgetRow }) {
  const ratio = burn(b);
  if (ratio === null) return <span className="label">no budget</span>;
  const tone = burnTone(ratio, b.soft_pct);
  const fill = { good: "bg-good", warning: "bg-warning", critical: "bg-critical", neutral: "bg-accent" }[tone];
  const track = { good: "bg-good-soft", warning: "bg-warning-soft", critical: "bg-critical-soft", neutral: "bg-accent-soft" }[tone];
  const p = Math.min(100, Math.round(ratio * 100));
  return (
    <span className="grid grid-cols-[minmax(4rem,8rem)_3.5rem] items-center gap-2">
      <span className={cx("h-2 overflow-hidden rounded-full", track)} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={p} aria-label={`@${b.handle} budget used`}>
        <span className={cx("block h-full rounded-full", fill)} style={{ width: `${p}%` }} />
      </span>
      <span className="label tnum text-right">{Number.isFinite(ratio) ? `${Math.round(ratio * 100)}%` : "over"}</span>
    </span>
  );
}

function BudgetForm({ b, onDone }: { b: AgentBudgetRow; onDone: () => void }) {
  const [daily, setDaily] = useState(b.daily_usd?.toString() ?? "");
  const [monthly, setMonthly] = useState(b.monthly_usd?.toString() ?? "");
  const [dailyTok, setDailyTok] = useState(b.daily_tokens?.toString() ?? "");
  const [monthlyTok, setMonthlyTok] = useState(b.monthly_tokens?.toString() ?? "");
  const [soft, setSoft] = useState(String(b.soft_pct ?? 80));
  const [reason, setReason] = useState("");
  const [topUsd, setTopUsd] = useState("");
  const [topHours, setTopHours] = useState("24");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const num = (s: string) => (s.trim() === "" ? null : Number(s));
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      refreshAll();
      onDone();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
      setBusy(false);
    }
  };
  const path = `/manage/agents/${encodeURIComponent(b.handle)}`;
  return (
    <div className="space-y-2 py-2">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void run(() =>
            api(`${path}/budget`, {
              method: "PUT",
              body: JSON.stringify({ daily_usd: num(daily), monthly_usd: num(monthly), daily_tokens: num(dailyTok), monthly_tokens: num(monthlyTok), soft_pct: Number(soft) || 80, reason }),
            }),
          );
        }}
      >
        {[
          ["Daily USD", daily, setDaily],
          ["Monthly USD", monthly, setMonthly],
          ["Daily tokens", dailyTok, setDailyTok],
          ["Monthly tokens", monthlyTok, setMonthlyTok],
          ["Alert at %", soft, setSoft],
        ].map(([label, v, set]) => (
          <label key={label as string} className="grid gap-0.5 text-xs text-muted">
            {label as string}
            <Input inputMode="decimal" className="w-28" value={v as string} onChange={(e) => (set as (x: string) => void)(e.target.value)} placeholder="none" />
          </label>
        ))}
        <Input required minLength={5} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (audited)" className="min-w-48 flex-1" />
        <Button type="submit" variant="primary" size="sm" loading={busy}>
          Save budget
        </Button>
        {b.updated_at && (
          <Button type="button" variant="ghost" size="sm" disabled={busy || reason.trim().length < 5} onClick={() => void run(() => api(`${path}/budget?reason=${encodeURIComponent(reason)}`, { method: "DELETE" }))}>
            Remove budget
          </Button>
        )}
      </form>
      {b.updated_at && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => api(`${path}/topup`, { method: "POST", body: JSON.stringify({ usd: Number(topUsd) || 0, hours: Number(topHours) || 24, reason }) }));
          }}
        >
          <label className="grid gap-0.5 text-xs text-muted">
            Top-up USD
            <Input inputMode="decimal" className="w-28" value={topUsd} onChange={(e) => setTopUsd(e.target.value)} />
          </label>
          <label className="grid gap-0.5 text-xs text-muted">
            For hours
            <Input inputMode="numeric" className="w-20" value={topHours} onChange={(e) => setTopHours(e.target.value)} />
          </label>
          <Button type="submit" size="sm" loading={busy} disabled={reason.trim().length < 5}>
            Grant top-up
          </Button>
          <span className="text-xs text-muted">Uses the reason above. Lifts a block at once.</span>
        </form>
      )}
      {err && <ErrorLine>{err}</ErrorLine>}
    </div>
  );
}

function BudgetsSection() {
  const { data: rows, error } = useLiveQuery<AgentBudgetRow[]>("/manage/agents/budgets");
  const [open, setOpen] = useState<string | null>(null);
  return (
    <section aria-labelledby="budgets" className="overflow-x-auto border-b border-rule px-6 max-sm:px-4 py-5">
      <h2 id="budgets" className="text-sm font-semibold">
        Budgets
      </h2>
      <p className="mt-1 max-w-3xl text-xs text-muted">
        Hard caps. Over a limit, the board refuses the agent's MCP calls (except whoami, report_usage and releasing a claim), releases its claims and posts in #general. A daily block lifts at the next UTC day,
        a monthly one at the next month, or when you raise the budget or grant a top-up. Spend is reported LLM cost (priced by the board) plus metered tool cost.
      </p>
      {error && <ErrorLine>{error.message}</ErrorLine>}
      {rows && rows.length === 0 && <p className="mt-2 text-ui text-muted">No agents have signed in yet.</p>}
      {rows && rows.length > 0 && (
        <table className="mt-2 w-full min-w-[52rem] text-left text-ui">
          <thead className="label">
            <tr className="border-b border-rule">
              <th className="py-1.5 pr-4 font-normal">Agent</th>
              <th className="py-1.5 pr-4 text-right font-normal">Today</th>
              <th className="py-1.5 pr-4 text-right font-normal">This month</th>
              <th className="py-1.5 pr-4 font-normal">Limits</th>
              <th className="py-1.5 pr-4 font-normal">Burn</th>
              <th className="py-1.5 pr-4 font-normal">State</th>
              <th className="py-1.5 text-right font-normal" />
            </tr>
          </thead>
          <tbody className="tnum">
            {rows.map((b) => (
              <Fragment key={b.handle}>
                <tr className="border-b border-rule align-top">
                  <td className="py-2 pr-4">
                    <p className="text-ink">@{b.handle}</p>
                    {!b.enabled && <span className="label">disabled</span>}
                  </td>
                  <td className="py-2 pr-4 text-right">
                    {usd(b.day_usd)}
                    <p className="label">{tokens(b.day_tokens)} tok</p>
                  </td>
                  <td className="py-2 pr-4 text-right">
                    {usd(b.month_usd)}
                    <p className="label">{tokens(b.month_tokens)} tok</p>
                  </td>
                  <td className="py-2 pr-4 text-xs text-ink-2">
                    {b.updated_at ? (
                      <>
                        {[b.daily_usd !== null && `${usd(b.daily_usd)}/day`, b.monthly_usd !== null && `${usd(b.monthly_usd)}/mo`, b.daily_tokens !== null && `${tokens(b.daily_tokens)} tok/day`, b.monthly_tokens !== null && `${tokens(b.monthly_tokens)} tok/mo`]
                          .filter(Boolean)
                          .join(" · ") || "none"}
                        {b.topup_usd > 0 && <p className="text-good">+{usd(b.topup_usd)} top-up</p>}
                      </>
                    ) : (
                      <span className="label">none</span>
                    )}
                  </td>
                  <td className="py-2 pr-4">
                    <BurnBar b={b} />
                  </td>
                  <td className="py-2 pr-4">
                    <div className="flex flex-wrap gap-1">
                      {b.blocked && <Tag tone="critical">blocked</Tag>}
                      {b.calls_without_report7d > 0 && <Tag tone="warning" title="It calls tools but never reports LLM usage, so its spend is unknown">not reporting usage</Tag>}
                      {!b.blocked && b.calls_without_report7d === 0 && <Tag tone="good">ok</Tag>}
                    </div>
                    {b.blocked_reason && <p className="mt-0.5 max-w-64 text-xs text-critical">{b.blocked_reason}</p>}
                    {b.last_report_at && (
                      <p className="label mt-0.5">
                        last report <Time iso={b.last_report_at} />
                      </p>
                    )}
                  </td>
                  <td className="py-2 text-right">
                    <Button size="sm" aria-expanded={open === b.handle} onClick={() => setOpen(open === b.handle ? null : b.handle)}>
                      {open === b.handle ? "Close" : "Budget"}
                    </Button>
                  </td>
                </tr>
                {open === b.handle && (
                  <tr className="border-b border-rule">
                    <td colSpan={7}>
                      <BudgetForm b={b} onDone={() => setOpen(null)} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function SettingsSection() {
  const { data: s } = useLiveQuery<ObservabilitySettings>("/manage/agents/settings");
  const [retention, setRetention] = useState("");
  const [alert, setAlert] = useState("");
  const [quarantine, setQuarantine] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (!s) return;
    setRetention(String(s.trace_retention_days));
    setAlert(s.risk_alert_threshold?.toString() ?? "");
    setQuarantine(s.risk_quarantine_threshold?.toString() ?? "");
  }, [s]);
  if (!s) return null;
  const num = (x: string) => (x.trim() === "" ? null : Number(x));
  return (
    <section aria-labelledby="obs-settings" className="border-b border-rule px-6 max-sm:px-4 py-5">
      <h2 id="obs-settings" className="text-sm font-semibold">
        Trace retention and risk thresholds
      </h2>
      <p className="mt-1 max-w-3xl text-xs text-muted">
        Risk scores are on Access review. At the alert threshold the board posts once in #general and notifies approvers. At the quarantine threshold it disables the agent (claims released, webhooks off) — leave
        empty to keep that off.
      </p>
      <form
        className="mt-2 flex flex-wrap items-end gap-2"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setErr(null);
          setSaved(false);
          try {
            await api("/manage/agents/settings", {
              method: "PUT",
              body: JSON.stringify({ trace_retention_days: Number(retention), risk_alert_threshold: num(alert), risk_quarantine_threshold: num(quarantine), reason }),
            });
            setReason("");
            setSaved(true);
            refreshAll();
          } catch (x) {
            setErr(x instanceof ApiError ? x.message : String(x));
          } finally {
            setBusy(false);
          }
        }}
      >
        <label className="grid gap-0.5 text-xs text-muted">
          Keep traces (days)
          <Input inputMode="numeric" className="w-24" value={retention} onChange={(e) => setRetention(e.target.value)} />
        </label>
        <label className="grid gap-0.5 text-xs text-muted">
          Alert at risk
          <Input inputMode="numeric" className="w-24" value={alert} onChange={(e) => setAlert(e.target.value)} placeholder="off" />
        </label>
        <label className="grid gap-0.5 text-xs text-muted">
          Quarantine at risk
          <Input inputMode="numeric" className="w-28" value={quarantine} onChange={(e) => setQuarantine(e.target.value)} placeholder="off" />
        </label>
        <Input required minLength={5} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (audited)" className="min-w-48 flex-1" />
        <Button type="submit" size="sm" variant="primary" loading={busy}>
          Save
        </Button>
        {saved && <span className="text-xs text-good">Saved</span>}
      </form>
      {err && <ErrorLine>{err}</ErrorLine>}
    </section>
  );
}

/** /agents (Board.Admin): what agents cost, whether they're right, and their budgets. */
export default function AgentsPage() {
  const me = useMe();
  const isAdmin = me?.roles.includes("admin");
  const [days, setDays] = useState<(typeof RANGES)[number]["value"]>("30");
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => setNow(Date.now()), [days]);
  const query = now === null ? null : new URLSearchParams({ from: new Date(now - Number(days) * 86400_000).toISOString(), to: new Date(now).toISOString() }).toString();
  const { data: r, error } = useLiveQuery<AgentCostReport>(isAdmin && query ? `/manage/agents/report?${query}` : null);

  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Agents" />
        <Empty title="Agent costs are for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }
  return (
    <>
      <PageHeader title="Agents" sub="What agents cost, whether people agreed with them, and their hard budgets. LLM cost is reported by agents and priced by the board.">
        <Segmented label="Date range" value={days} onChange={setDays} options={RANGES.map((x) => ({ ...x }))} />
      </PageHeader>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't build the agent report">{error.message}</Empty>}
        {r && (
          <>
            <section aria-label="Totals" className="grid grid-cols-4 border-b border-rule max-lg:grid-cols-2">
              <Tile label="Spend in range" value={usd(r.total_usd)} hint={`${tokens(r.total_tokens)} tokens`} />
              <Tile label="Per closed incident" value={usd(r.usd_per_closed_incident)} hint="Resolved incidents agents worked on" />
              <Tile label="Per verdict" value={usd(r.usd_per_verdict)} hint="Agent verdict messages" />
              <Tile label="Month-end forecast" value={usd(r.forecast_month_usd)} hint={`${usd(r.month_to_date_usd)} so far this month`} />
            </section>

            <section aria-labelledby="daily" className="border-b border-rule px-6 max-sm:px-4 py-5">
              <h2 id="daily" className="mb-2 text-sm font-semibold">
                Spend per day
              </h2>
              <DailyChart r={r} />
            </section>

            <section aria-labelledby="per-agent" className="overflow-x-auto border-b border-rule px-6 max-sm:px-4 py-5">
              <h2 id="per-agent" className="text-sm font-semibold">
                Per agent
              </h2>
              {r.agents.length === 0 ? (
                <p className="mt-2 text-ui text-muted">No agent activity in this range.</p>
              ) : (
                <table className="mt-2 w-full min-w-[52rem] text-left text-ui">
                  <thead className="label">
                    <tr className="border-b border-rule">
                      <th className="py-1.5 pr-4 font-normal">Agent</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Spend</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Tokens</th>
                      <th className="py-1.5 pr-4 text-right font-normal">MCP calls</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Per verdict</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Per closed incident</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Month forecast</th>
                      <th className="py-1.5 font-normal">Reporting</th>
                    </tr>
                  </thead>
                  <tbody className="tnum">
                    {r.agents.map((a) => (
                      <tr key={a.handle} className="border-b border-rule last:border-0">
                        <td className="py-1.5 pr-4 text-ink">@{a.handle}</td>
                        <td className="py-1.5 pr-4 text-right">{usd(a.usd)}</td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">{tokens(a.tokens)}</td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">{a.calls}</td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">{usd(a.usd_per_verdict)}</td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">{usd(a.usd_per_closed_incident)}</td>
                        <td className={cx("py-1.5 pr-4 text-right", a.monthly_usd_limit !== null && a.forecast_month_usd > a.monthly_usd_limit ? "text-critical" : "text-ink-2")}>
                          {usd(a.forecast_month_usd)}
                          {a.monthly_usd_limit !== null && <span className="label"> / {usd(a.monthly_usd_limit)}</span>}
                        </td>
                        <td className="py-1.5">
                          {a.unreported ? (
                            <Tag tone="warning" title="Calls tools but sends no report_usage: its LLM spend is unknown">not reporting</Tag>
                          ) : a.unpriced_model ? (
                            <Tag tone="warning" title="The board has no price for this model: add it to AGENT_PRICE_TABLE">unpriced: {a.unpriced_model}</Tag>
                          ) : (
                            <Tag tone="good">{a.reports} reports</Tag>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>

            <section aria-labelledby="accuracy" className="overflow-x-auto border-b border-rule px-6 max-sm:px-4 py-5">
              <h2 id="accuracy" className="text-sm font-semibold">
                Accuracy
              </h2>
              <p className="mt-1 max-w-3xl text-xs text-muted">
                From people marking agent messages correct or incorrect, and incidents resolved in Defender / Sentinel or by update_incident with a different classification from the agent's latest verdict
                (an overturn). Precision counts judged verdicts only.
              </p>
              {r.accuracy.length === 0 ? (
                <p className="mt-2 text-ui text-muted">No agent verdicts, findings or IOCs in this range.</p>
              ) : (
                <table className="mt-2 w-full min-w-[46rem] text-left text-ui">
                  <thead className="label">
                    <tr className="border-b border-rule">
                      <th className="py-1.5 pr-4 font-normal">Agent</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Verdicts</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Feedback</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Correct / incorrect</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Overturn rate</th>
                      <th className="py-1.5 pr-4 text-right font-normal">TP precision</th>
                      <th className="py-1.5 text-right font-normal">FP precision</th>
                    </tr>
                  </thead>
                  <tbody className="tnum">
                    {r.accuracy.map((a) => (
                      <tr key={a.handle} className="border-b border-rule last:border-0">
                        <td className="py-1.5 pr-4 text-ink">@{a.handle}</td>
                        <td className="py-1.5 pr-4 text-right">{a.verdicts}</td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">{a.feedback_count}</td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">
                          {a.correct} / {a.incorrect}
                        </td>
                        <td className={cx("py-1.5 pr-4 text-right", (a.overturn_rate ?? 0) >= 0.25 ? "text-critical" : "text-ink-2")}>
                          {pct(a.overturn_rate)} <span className="label">({a.overturns}/{a.resolved_verdicts})</span>
                        </td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">
                          {pct(a.tp_precision)} <span className="label">n={a.tp_judged}</span>
                        </td>
                        <td className="py-1.5 text-right text-ink-2">
                          {pct(a.fp_precision)} <span className="label">n={a.fp_judged}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>

            <section aria-labelledby="by-incident" className="overflow-x-auto border-b border-rule px-6 max-sm:px-4 py-5">
              <h2 id="by-incident" className="text-sm font-semibold">
                Per incident
              </h2>
              {r.incidents.length === 0 ? (
                <p className="mt-2 text-ui text-muted">No spend linked to incidents in this range.</p>
              ) : (
                <table className="mt-2 w-full min-w-[40rem] text-left text-ui">
                  <thead className="label">
                    <tr className="border-b border-rule">
                      <th className="py-1.5 pr-4 font-normal">Incident</th>
                      <th className="py-1.5 pr-4 font-normal">Status</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Spend</th>
                      <th className="py-1.5 pr-4 text-right font-normal">Tokens</th>
                      <th className="py-1.5 text-right font-normal">Agent calls</th>
                    </tr>
                  </thead>
                  <tbody className="tnum">
                    {r.incidents.slice(0, 50).map((i) => (
                      <tr key={i.id} className="border-b border-rule last:border-0">
                        <td className="max-w-0 py-1.5 pr-4">
                          <Link to={`/incidents/${i.id}`} className="block truncate text-ink hover:text-accent">
                            <span className="label mr-2 text-ink-2">{i.graph_id}</span>
                            {i.display_name}
                          </Link>
                        </td>
                        <td className="py-1.5 pr-4 text-ink-2">{i.classification ? `${i.status} · ${i.classification}` : i.status}</td>
                        <td className="py-1.5 pr-4 text-right">{usd(i.usd)}</td>
                        <td className="py-1.5 pr-4 text-right text-ink-2">{tokens(i.tokens)}</td>
                        <td className="py-1.5 text-right text-ink-2">{i.calls}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          </>
        )}
        {isAdmin && <BudgetsSection />}
        {isAdmin && <SettingsSection />}
      </div>
    </>
  );
}
