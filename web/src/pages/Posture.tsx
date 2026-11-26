import { PageHeader, useMe } from "../components/shell";
import { useLiveQuery } from "../lib/api";
import { cx, Empty, Tag, Time } from "../components/ui";

type Control = { id: string; area: string; title: string; state: "met" | "partial" | "not_met" | "external"; weight: number; detail: string; fix: string | null; owner: string | null; threat: string | null };
type Report = { checked_at: string; score: number; max_score: number; controls: Control[] };

const WORD = { met: "Met", partial: "Partial", not_met: "Not met", external: "Confirm in Entra" } as const;
const TONE = { met: "good", partial: "warning", not_met: "critical", external: "neutral" } as const;
const ORDER = { not_met: 0, partial: 1, external: 2, met: 3 } as const;

/** Points earned and available per area, for the area meters. */
export function areaScores(controls: Control[]) {
  const areas = new Map<string, { earned: number; max: number }>();
  for (const c of controls) {
    if (c.state === "external") continue;
    const a = areas.get(c.area) ?? { earned: 0, max: 0 };
    a.max += c.weight;
    a.earned += c.state === "met" ? c.weight : c.state === "partial" ? Math.floor(c.weight / 2) : 0;
    areas.set(c.area, a);
  }
  return [...areas.entries()].map(([area, v]) => ({ area, ...v }));
}

function Meter({ value, max, label }: { value: number; max: number; label: string }) {
  const pct = max === 0 ? 0 : Math.round((value / max) * 100);
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 text-xs">
        <span className="text-ink-2">{label}</span>
        <span className="tnum text-muted">
          {value} / {max}
        </span>
      </div>
      <div className="mt-1 h-1.5 rounded-full bg-paper-3" role="meter" aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} aria-label={`${label}: ${value} of ${max}`}>
        <div className="h-1.5 rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

/**
 * Admin → Posture (Board.Admin): the enterprise controls this deployment enforces, scored like Secure Score. Not met
 * first, each with the exact step that fixes it and the threat (docs/THREAT-MODEL.md) it addresses.
 */
export default function PosturePage() {
  const me = useMe();
  const isAdmin = me?.roles.includes("admin");
  const { data: r, error } = useLiveQuery<Report>(isAdmin ? "/manage/posture" : null);
  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Posture" />
        <Empty title="Posture is for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }
  const sorted = r ? [...r.controls].sort((a, b) => ORDER[a.state] - ORDER[b.state] || b.weight - a.weight) : [];
  return (
    <>
      <PageHeader
        title="Posture"
        sub={r ? <span>Control configuration reported by this deployment. Checked <Time iso={r.checked_at} />.</span> : "Control configuration reported by this deployment."}
      />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't load posture">{error.message}</Empty>}
        {r && (
          <>
            <section aria-label="Score" className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-8 gap-y-3 border-b border-rule px-5 py-4 max-md:grid-cols-1">
              <div>
                <p className="label">Posture score</p>
                <p className="tnum text-[28px] font-semibold leading-tight">
                  {r.score}
                  <span className="text-base font-normal text-muted"> / {r.max_score}</span>
                </p>
                <p className="text-xs text-muted">{r.max_score ? Math.round((r.score / r.max_score) * 100) : 0}% of scored controls</p>
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-2 max-sm:grid-cols-1">
                {areaScores(r.controls).map((a) => (
                  <Meter key={a.area} label={a.area} value={a.earned} max={a.max} />
                ))}
              </div>
            </section>
            <p className="border-b border-rule px-5 py-3 text-xs text-muted">Configuration score, not certification or a live Azure audit. Verify networking, WAF blocking and audit delivery in Azure. Confirm Conditional Access and PIM in Entra; external controls are not scored. Dry run does not reduce the score.</p>
            <ul aria-label="Controls">
              {sorted.map((c) => (
                <li key={c.id} className="grid grid-cols-[7.5rem_minmax(0,1fr)_auto] gap-x-4 border-b border-rule px-5 py-3 max-sm:grid-cols-1">
                  <span className="pt-0.5">
                    <Tag tone={TONE[c.state]}>{WORD[c.state]}</Tag>
                  </span>
                  <div className="min-w-0">
                    <h2 className="text-sm font-semibold">{c.title}</h2>
                    <p className="mt-0.5 text-[13px] text-ink-2 [overflow-wrap:anywhere]">{c.detail}</p>
                    {c.fix && c.state !== "met" && (
                      <p className="mt-1 text-xs text-ink-2">
                        <span className="font-medium text-ink">{c.state === "external" ? "Where:" : "How to fix:"}</span> <span className="font-mono">{c.fix}</span>
                      </p>
                    )}
                  </div>
                  <div className={cx("label whitespace-nowrap text-right max-sm:text-left")}>
                    <p>{c.area}</p>
                    <p>{c.state === "external" ? "not scored" : `${c.weight} pts`}</p>
                    {c.owner && <p>owner: {c.owner}</p>}
                    {c.threat && <p>{c.threat}</p>}
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </>
  );
}
