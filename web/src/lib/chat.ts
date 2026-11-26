/** Chat feed rules, kept free of React and the DOM so they can be unit-tested: day labels, grouping, thread roll-ups. */
import type { Author, Message } from "./api";

/** Consecutive messages from one author within this window share a header. */
export const GROUP_MS = 5 * 60 * 1000;

/** Local calendar day, as a sortable key. */
export function dayKey(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

const WEEKDAY = new Intl.DateTimeFormat("en-AU", { weekday: "long" });
const MONTH = new Intl.DateTimeFormat("en-AU", { month: "long" });

/** "Today", "Yesterday", "Tuesday, 25 November", and the year when it isn't this year (Australian order, no ordinal). */
export function dayLabel(iso: string, now: Date = new Date()): string {
  const d = new Date(iso);
  const k = dayKey(iso);
  if (k === dayKey(now.toISOString())) return "Today";
  const y = new Date(now);
  y.setDate(y.getDate() - 1);
  if (k === dayKey(y.toISOString())) return "Yesterday";
  const base = `${WEEKDAY.format(d)}, ${d.getDate()} ${MONTH.format(d)}`;
  return d.getFullYear() === now.getFullYear() ? base : `${base} ${d.getFullYear()}`;
}

/** Clock time in the reader's locale ("6:16 pm" or "18:16"). */
export function clockTime(iso: string, locale?: string): string {
  return new Date(iso).toLocaleTimeString(locale, { hour: "numeric", minute: "2-digit" });
}

/** Gutter time on grouped rows: the clock without am/pm ("6:16"; 24 h locales are unchanged). */
export function gutterTime(iso: string, locale?: string): string {
  const parts = new Intl.DateTimeFormat(locale, { hour: "numeric", minute: "2-digit" }).formatToParts(new Date(iso));
  return parts
    .filter((p) => p.type !== "dayPeriod")
    .map((p) => p.value)
    .join("")
    .trim();
}

/** "just now", "5 minutes ago", "2 hours ago", "yesterday", "3 days ago", then a date. */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const s = Math.max(0, (now - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} ${m === 1 ? "minute" : "minutes"} ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} ${h === 1 ? "hour" : "hours"} ago`;
  const d = Math.floor(h / 24);
  if (d === 1) return "yesterday";
  if (d < 30) return `${d} days ago`;
  return new Date(iso).toLocaleDateString("en-AU", { day: "numeric", month: "short", year: "numeric" });
}

/** Full date and time for tooltips. */
export function fullTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric", hour: "numeric", minute: "2-digit" });
}

/** True when `m` can sit under `prev` without its own avatar and name. */
export function groupsWith(prev: Message | undefined, m: Message): boolean {
  if (!prev) return false;
  if (prev.author.handle !== m.author.handle) return false;
  if (m.author.kind === "system" || prev.author.kind === "system") return false; // board events never group
  if (prev.type !== m.type) return false; // the type tag lives in the header
  if (prev.reply_count) return false; // a thread summary row ends the run
  if (dayKey(prev.created_at) !== dayKey(m.created_at)) return false;
  const gap = new Date(m.created_at).getTime() - new Date(prev.created_at).getTime();
  return gap >= 0 && gap <= GROUP_MS;
}

export type ReplySummary = { count: number; lastAt: string | null; authors: Author[] };

/**
 * A feed of roots plus (in incident feeds) their replies, as the channel should show it: roots only, each with a
 * reply roll-up derived from replies in the page, and any reply whose root isn't in the page kept as an "orphan".
 */
export function threadView(messages: readonly Message[]): { visible: Message[]; orphans: Set<string>; derived: Map<string, ReplySummary> } {
  const roots = new Set(messages.filter((m) => !m.parent_id).map((m) => m.id));
  const derived = new Map<string, ReplySummary>();
  const orphans = new Set<string>();
  const visible: Message[] = [];
  for (const m of messages) {
    if (!m.parent_id) {
      visible.push(m);
      continue;
    }
    if (!roots.has(m.parent_id)) {
      orphans.add(m.id);
      visible.push(m);
      continue;
    }
    const s = derived.get(m.parent_id) ?? { count: 0, lastAt: null, authors: [] };
    s.count++;
    if (!s.lastAt || m.created_at > s.lastAt) s.lastAt = m.created_at;
    if (!s.authors.some((a) => a.handle === m.author.handle)) s.authors.push(m.author);
    derived.set(m.parent_id, s);
  }
  return { visible, orphans, derived };
}

/** What the summary row under a root shows: the API's fields first, the page-derived roll-up as a fallback. */
export function replySummary(m: Message, derived?: ReplySummary): ReplySummary | null {
  const count = m.reply_count ?? derived?.count ?? 0;
  if (!count) return null;
  return {
    count,
    lastAt: m.last_reply_at ?? derived?.lastAt ?? null,
    authors: (m.reply_authors ?? derived?.authors ?? []).slice(0, 4),
  };
}

export type FeedRow = { m: Message; grouped: boolean; orphan: boolean; day: string; newDay: boolean };

/** Rows with grouping and day breaks worked out. Orphan replies always get a full header. */
export function feedRows(visible: readonly Message[], orphans: ReadonlySet<string> = new Set()): FeedRow[] {
  const rows: FeedRow[] = [];
  let prev: Message | undefined;
  let prevDay = "";
  for (const m of visible) {
    const day = dayKey(m.created_at);
    const orphan = orphans.has(m.id);
    const prevOrphan = prev ? orphans.has(prev.id) : false;
    rows.push({ m, orphan, day, newDay: day !== prevDay, grouped: !orphan && !prevOrphan && groupsWith(prev, m) });
    prev = m;
    prevDay = day;
  }
  return rows;
}

/** Avatar tint 1..6 from the handle: stable across sessions, calm, never meaningful on its own. */
export function avatarTint(handle: string): number {
  let h = 2166136261;
  for (let i = 0; i < handle.length; i++) {
    h ^= handle.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 6) + 1;
}

/** One or two initials: "SOC Analyst (dev)" → "SA", "enrichment-agent" → "EA". */
export function initials(name: string, handle = ""): string {
  const words = name
    .replace(/\([^)]*\)/g, " ")
    .split(/[\s\-_.]+/)
    .filter((w) => /[\p{L}\p{N}]/u.test(w));
  const src = words.length ? words : handle.split(/[-_.]+/).filter(Boolean);
  const chars = src.slice(0, 2).map((w) => [...w][0]!.toUpperCase());
  return chars.join("") || "?";
}
