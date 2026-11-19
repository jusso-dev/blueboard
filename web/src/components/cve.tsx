import { useEffect, useState } from "react";
import { Link, useInRouterContext } from "react-router";
import { api } from "../lib/api";
import { Tag } from "./ui";

export type Badge = { cve: string; known_exploited: boolean; due_date: string | null; ransomware: boolean; epss: number | null; percentile: number | null };

/**
 * KEV and EPSS for CVE ids on screen. Requests are batched (one call per render pass) and answered from the board's
 * store only, so showing a message never fetches anything from outside.
 */
const cache = new Map<string, Badge | null>();
const waiting = new Map<string, Set<(b: Badge | null) => void>>();
let timer: ReturnType<typeof setTimeout> | undefined;

function flush() {
  timer = undefined;
  const ids = [...waiting.keys()].filter((id) => !cache.has(id)).slice(0, 100);
  if (ids.length === 0) return;
  const qs = ids.map((id) => `cve=${encodeURIComponent(id)}`).join("&");
  api<Badge[]>(`/intel/badges?${qs}`)
    .then((list) => {
      const byId = new Map(list.map((b) => [b.cve, b]));
      for (const id of ids) cache.set(id, byId.get(id) ?? null);
    })
    .catch(() => ids.forEach((id) => cache.set(id, null)))
    .finally(() => {
      for (const id of ids) {
        waiting.get(id)?.forEach((cb) => cb(cache.get(id) ?? null));
        waiting.delete(id);
      }
      if (waiting.size > 0) timer = setTimeout(flush, 50);
    });
}

export function useCveBadge(cve: string) {
  const [badge, setBadge] = useState<Badge | null>(cache.get(cve) ?? null);
  useEffect(() => {
    if (cache.has(cve)) return void setBadge(cache.get(cve) ?? null);
    const set = waiting.get(cve) ?? new Set();
    set.add(setBadge);
    waiting.set(cve, set);
    timer ??= setTimeout(flush, 50);
    return () => void waiting.get(cve)?.delete(setBadge);
  }, [cve]);
  return badge;
}

export const pct = (v: number) => (v >= 0.995 ? "99%+" : v < 0.01 && v > 0 ? "<1%" : `${Math.round(v * 100)}%`);

/** Words, not colour alone: "Known exploited", "ransomware", "EPSS 97% (p99)". */
export function BadgeTags({ b }: { b: Badge }) {
  return (
    <>
      {b.known_exploited && (
        <Tag tone="critical" title={`CISA KEV${b.due_date ? `, remediation due ${b.due_date}` : ""}. Source: CISA KEV`}>
          Known exploited{b.due_date ? ` · due ${b.due_date}` : ""}
        </Tag>
      )}
      {b.ransomware && <Tag tone="critical" title="Known use in ransomware campaigns. Source: CISA KEV">ransomware</Tag>}
      {b.epss !== null && (
        <Tag
          tone={b.epss >= 0.1 ? "warning" : "neutral"}
          title={`Likelihood of exploitation in the next 30 days: ${(b.epss * 100).toFixed(2)}%. Source: FIRST EPSS`}
        >
          EPSS {pct(b.epss)}
          {b.percentile !== null ? ` (p${Math.floor(b.percentile * 100)})` : ""}
        </Tag>
      )}
    </>
  );
}

export function CveBadge({ cve }: { cve: string }) {
  const b = useCveBadge(cve);
  if (!b) return null;
  return (
    <span className="ml-1 inline-flex gap-1 align-[1px]">
      <BadgeTags b={b} />
    </span>
  );
}

/** A CVE id in a message: links to /intel/<CVE>, with its KEV / EPSS badge when the board has one. */
export function CveRef({ id }: { id: string }) {
  const cve = id.toUpperCase();
  const inRouter = useInRouterContext();
  return (
    <span className="whitespace-nowrap">
      {inRouter ? <Link to={`/intel/${cve}`}>{id}</Link> : <a href={`/intel/${cve}`}>{id}</a>}
      {inRouter && <CveBadge cve={cve} />}
    </span>
  );
}
