/** Agent observability (WS3): types for the /agents dashboard, traces, feedback and risk, and the pure helpers they use. */

export type TraceCall = {
  id: number;
  handle: string;
  kind: string;
  tool: string;
  status: "ok" | "error" | "forbidden" | "rate_limited" | "budget_blocked" | "secret_blocked" | "invalid";
  args: Record<string, unknown> | null;
  kql: string | null;
  error: string | null;
  duration_ms: number;
  result_bytes: number;
  message_id: string | null;
  claim_message_id: string | null;
  incident_id: string | null;
  incident_inferred: boolean;
  at: string;
};

export type FeedbackItem = {
  message_id: string;
  message_type: string;
  incident_graph_id: string | null;
  source: "human" | "resolution";
  verdict: "correct" | "incorrect";
  reason: string | null;
  your_classification: string | null;
  corrected_classification: string | null;
  given_by: string | null;
  at: string;
};
export type MessageFeedback = { correct: number; incorrect: number; items: FeedbackItem[]; mine: "correct" | "incorrect" | null };

export type RiskFactor = { key: string; label: string; value: number; points: number; max_points: number };
export type AgentRiskScore = {
  principal_id: string;
  handle: string;
  score: number;
  factors: RiskFactor[];
  computed_at: string;
  alerted_at: string | null;
  quarantined_at: string | null;
};

export type AgentBudgetRow = {
  principal_id: string;
  handle: string;
  display_name: string;
  enabled: boolean;
  daily_usd: number | null;
  monthly_usd: number | null;
  daily_tokens: number | null;
  monthly_tokens: number | null;
  soft_pct: number;
  note: string | null;
  updated_by: string | null;
  updated_at: string | null;
  day_usd: number;
  day_tokens: number;
  month_usd: number;
  month_tokens: number;
  topup_usd: number;
  topup_tokens: number;
  blocked: boolean;
  blocked_reason: string | null;
  last_report_at: string | null;
  calls_without_report7d: number;
};

export type AgentAccuracy = {
  handle: string;
  display_name: string;
  verdicts: number;
  findings: number;
  iocs: number;
  feedback_count: number;
  correct: number;
  incorrect: number;
  overturns: number;
  resolved_verdicts: number;
  overturn_rate: number | null;
  tp_precision: number | null;
  fp_precision: number | null;
  tp_judged: number;
  fp_judged: number;
};

export type AgentSpendRow = {
  handle: string;
  display_name: string;
  usd: number;
  tokens: number;
  reports: number;
  calls: number;
  verdicts: number;
  closed_incidents: number;
  usd_per_verdict: number | null;
  usd_per_closed_incident: number | null;
  month_usd: number;
  forecast_month_usd: number;
  monthly_usd_limit: number | null;
  unreported: boolean;
  unpriced_model: string | null;
};
export type AgentDaySpend = { handle: string; day: string; llm_usd: number; metered_usd: number; tokens: number; calls: number };
export type IncidentSpend = { id: string; graph_id: string; display_name: string; status: string; classification: string | null; usd: number; tokens: number; calls: number };
export type AgentCostReport = {
  range: { from: string; to: string };
  total_usd: number;
  total_tokens: number;
  usd_per_closed_incident: number | null;
  usd_per_verdict: number | null;
  month_to_date_usd: number;
  forecast_month_usd: number;
  agents: AgentSpendRow[];
  daily: AgentDaySpend[];
  incidents: IncidentSpend[];
  accuracy: AgentAccuracy[];
};
export type ObservabilitySettings = { trace_retention_days: number; risk_alert_threshold: number | null; risk_quarantine_threshold: number | null };

/** Messages people can give feedback on, and that may carry an agent trace. */
export const FEEDBACK_TYPES = new Set(["verdict", "finding", "ioc"]);

export function usd(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n === 0) return "$0";
  if (Math.abs(n) < 0.01) return "<$0.01";
  return n >= 1000 ? `$${Math.round(n).toLocaleString()}` : `$${n.toFixed(2)}`;
}

export function tokens(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export function pct(n: number | null | undefined): string {
  return n === null || n === undefined ? "—" : `${Math.round(n * 100)}%`;
}

/**
 * Burn against the tightest limit with top-ups applied: 0-1+ (can exceed 1). Null when the agent has no limits.
 * Mirrors AgentBudgets.Burn on the server so the bar and the cap agree.
 */
export function burn(b: Pick<AgentBudgetRow, "day_usd" | "month_usd" | "day_tokens" | "month_tokens" | "daily_usd" | "monthly_usd" | "daily_tokens" | "monthly_tokens" | "topup_usd" | "topup_tokens">): number | null {
  const r = (spent: number, limit: number | null, extra: number) => (limit === null ? null : limit + extra > 0 ? spent / (limit + extra) : spent > 0 ? Infinity : 0);
  const xs = [r(b.day_usd, b.daily_usd, b.topup_usd), r(b.month_usd, b.monthly_usd, b.topup_usd), r(b.day_tokens, b.daily_tokens, b.topup_tokens), r(b.month_tokens, b.monthly_tokens, b.topup_tokens)].filter(
    (x): x is number => x !== null,
  );
  return xs.length ? Math.max(...xs) : null;
}

/** Tone for a burn ratio: within budget, past the soft alert, at or over the hard cap. */
export function burnTone(ratio: number | null, softPct: number): "good" | "warning" | "critical" | "neutral" {
  if (ratio === null) return "neutral";
  if (ratio >= 1) return "critical";
  if (ratio * 100 >= softPct) return "warning";
  return "good";
}

export function riskTone(score: number): "good" | "warning" | "critical" {
  return score >= 70 ? "critical" : score >= 40 ? "warning" : "good";
}

/** Daily spend per agent pivoted for a stacked bar chart: one entry per day, sorted; agents ordered by total spend. */
export function stackDaily(daily: AgentDaySpend[]): { days: string[]; agents: string[]; values: Record<string, Record<string, number>>; max: number } {
  const days = [...new Set(daily.map((d) => d.day))].sort();
  const totals = new Map<string, number>();
  const values: Record<string, Record<string, number>> = {};
  for (const d of daily) {
    const v = d.llm_usd + d.metered_usd;
    const row = (values[d.day] ??= {});
    row[d.handle] = (row[d.handle] ?? 0) + v;
    totals.set(d.handle, (totals.get(d.handle) ?? 0) + v);
  }
  const agents = [...totals.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([h]) => h);
  const max = Math.max(0, ...days.map((day) => Object.values(values[day] ?? {}).reduce((s, x) => s + x, 0)));
  return { days, agents, values, max };
}

/** Status words for a trace row. */
export const TRACE_STATUS: Record<TraceCall["status"], { label: string; tone: "good" | "warning" | "critical" | "neutral" }> = {
  ok: { label: "ok", tone: "good" },
  error: { label: "error", tone: "critical" },
  forbidden: { label: "forbidden", tone: "critical" },
  rate_limited: { label: "rate limited", tone: "warning" },
  budget_blocked: { label: "over budget", tone: "critical" },
  secret_blocked: { label: "secret blocked", tone: "critical" },
  invalid: { label: "invalid input", tone: "warning" },
};

/** A one-line summary of a call's redacted arguments for the trace list. */
export function argLine(args: Record<string, unknown> | null, max = 120): string {
  if (!args) return "";
  const parts = Object.entries(args)
    .filter(([k]) => k !== "_truncated" && k !== "query")
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`);
  const s = parts.join(" · ");
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/** Message payloads may carry a short `reasoning` field; returns it trimmed, or null. */
export function reasoningOf(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") return null;
  const r = (payload as { reasoning?: unknown }).reasoning;
  return typeof r === "string" && r.trim() ? r.trim().slice(0, 4000) : null;
}
