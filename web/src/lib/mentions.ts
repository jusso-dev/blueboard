/** @mention autocomplete, as pure logic: trigger detection, ranking and insertion. The React side is components/mentions.tsx. */

export type Participant = {
  handle: string;
  display_name: string;
  kind: "agent" | "human" | "system";
  roles?: string[];
  description?: string | null;
  last_seen_at?: string | null;
  /** Present on admin views only; a disabled principal can't be mentioned usefully. */
  enabled?: boolean;
};

/** An open "@query" token ending at the caret. `start` is the index of the "@". */
export type Trigger = { start: number; query: string };

/** Handles are lowercase letters, digits and hyphens (the API's mention regex); a query may also hold "." and "_" while typing a name. */
const QUERY = /^[\w.-]{0,40}$/;
/** "@" opens only at the start, after whitespace or after an opening bracket: never inside a word or an email (a@b). */
const BEFORE = /[\s([{]/;

export const ACTIVE_MS = 5 * 60 * 1000;

export function detectTrigger(text: string, caret: number): Trigger | null {
  if (caret < 0 || caret > text.length) return null;
  const at = text.lastIndexOf("@", caret - 1);
  if (at < 0) return null;
  const query = text.slice(at + 1, caret);
  if (!QUERY.test(query)) return null;
  if (at > 0 && !BEFORE.test(text[at - 1]!)) return null;
  // Inside inline code (an odd number of backticks earlier on the line) a "@" is literal.
  const lineStart = text.lastIndexOf("\n", at - 1) + 1;
  const ticks = (text.slice(lineStart, at).match(/`/g) ?? []).length;
  if (ticks % 2 === 1) return null;
  // Inside a fenced code block too.
  const fences = (text.slice(0, lineStart).match(/^```/gm) ?? []).length;
  if (fences % 2 === 1) return null;
  return { start: at, query };
}

export function isActive(p: Pick<Participant, "last_seen_at">, now: number): boolean {
  if (!p.last_seen_at) return false;
  const t = Date.parse(p.last_seen_at);
  return Number.isFinite(t) && now - t <= ACTIVE_MS;
}

/** Lower is better: 0 handle prefix, 1 word prefix (name or handle part), 2 substring. null = no match. */
export function matchScore(p: Pick<Participant, "handle" | "display_name">, query: string): number | null {
  const q = query.toLowerCase();
  if (!q) return 0;
  const handle = p.handle.toLowerCase();
  const name = p.display_name.toLowerCase();
  if (handle.startsWith(q)) return 0;
  const words = [...name.split(/[\s()\-_.]+/), ...handle.split(/[-_.]/)].filter(Boolean);
  if (name.startsWith(q) || words.some((w) => w.startsWith(q))) return 1;
  if (handle.includes(q) || name.includes(q)) return 2;
  return null;
}

/**
 * Who can be mentioned for `query`, best first: match quality, then recently active, then name. Agents and people
 * interleave; the system principal and disabled principals are left out.
 */
export function rankParticipants(list: readonly Participant[], query: string, now = Date.now()): Participant[] {
  const scored: { p: Participant; s: number; seen: number }[] = [];
  for (const p of list) {
    if (p.kind === "system" || p.enabled === false) continue;
    const s = matchScore(p, query);
    if (s === null) continue;
    const seen = p.last_seen_at ? Date.parse(p.last_seen_at) : NaN;
    scored.push({ p, s, seen: Number.isFinite(seen) ? seen : -Infinity });
  }
  scored.sort((a, b) => {
    if (a.s !== b.s) return a.s - b.s;
    const aa = isActive(a.p, now);
    const ba = isActive(b.p, now);
    if (aa !== ba) return aa ? -1 : 1;
    if (a.seen !== b.seen) return b.seen - a.seen;
    return a.p.display_name.localeCompare(b.p.display_name);
  });
  return scored.map((x) => x.p);
}

/** Replace "@query" (from the trigger to the caret) with "@handle " and put the caret after the space. */
export function insertMention(text: string, trigger: Trigger, caret: number, handle: string): { text: string; caret: number } {
  const after = text.slice(caret);
  const token = `@${handle}`;
  const space = after.startsWith(" ") ? "" : " ";
  const next = text.slice(0, trigger.start) + token + space + after;
  return { text: next, caret: trigger.start + token.length + 1 };
}

/** Handles mentioned in a body, the same way the API parses them (not in an email, lowercase handle syntax). */
export function parseMentions(body: string): string[] {
  const out = new Set<string>();
  for (const m of body.matchAll(/(?:^|[^\w@.])@([a-z0-9][a-z0-9-]{0,40})/g)) out.add(m[1]!);
  return [...out];
}

/** Text to insert when the "@" toolbar button is pressed: a leading space if the caret sits right after a word. */
export function atInsertion(text: string, caret: number): string {
  return caret > 0 && !/[\s([{]/.test(text[caret - 1]!) ? " @" : "@";
}
