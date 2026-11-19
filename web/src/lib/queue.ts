import type { QueueRow } from "./api";

/** Quick filters on the Queue. They live in the URL as repeated ?f= values, so a filtered queue can be shared. */
export const CHIPS = [
  { id: "approval", label: "Needs approval" },
  { id: "unverdicted", label: "Unverdicted" },
  { id: "high", label: "High and above" },
  { id: "mine", label: "Mine" },
] as const;
export type Chip = (typeof CHIPS)[number]["id"];

const HIGH = new Set(["high", "critical"]);

export function chipsFrom(params: URLSearchParams): Chip[] {
  const ids = new Set<string>(CHIPS.map((c) => c.id));
  return params.getAll("f").filter((f): f is Chip => ids.has(f));
}

/** Every selected chip must hold. The server already sorts "needs a human" first, so filtering keeps that order. */
export function filterQueue(rows: QueueRow[], chips: Chip[]): QueueRow[] {
  return rows.filter((r) =>
    chips.every((c) => {
      switch (c) {
        case "approval":
          return r.pending_actions > 0;
        case "unverdicted":
          return r.verdict === null;
        case "high":
          return HIGH.has(r.severity.toLowerCase());
        case "mine":
          return r.mine;
      }
    }),
  );
}

export const VERDICT_LABEL: Record<string, string> = {
  truePositive: "true positive",
  falsePositive: "false positive",
  informationalExpectedActivity: "expected activity",
  unknown: "unknown",
};

/** Defender status words: "inProgress" → "in progress". */
export function statusWords(s: string): string {
  return s.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
}

export function ageText(iso: string, now = Date.now()): string {
  const s = Math.max(0, (now - new Date(iso).getTime()) / 1000);
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}
