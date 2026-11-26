/**
 * Emoji as pure logic: the curated table, search, `:shortcode:` conversion (never inside code or URLs), the composer's
 * colon trigger, "frequently used", and reaction state. The React side is components/emoji.tsx.
 */
import { CATEGORY_DATA } from "./emoji-data";

export type Emoji = { char: string; name: string; aliases: string[]; keywords: string[]; category: string };
export type Category = { id: string; label: string; emoji: Emoji[] };

export const CATEGORIES: Category[] = CATEGORY_DATA.map((c) => ({
  id: c.id,
  label: c.label,
  emoji: c.lines
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [char, codes = "", ...keywords] = l.split(/\s+/);
      const [name, ...aliases] = codes.split(",");
      return { char: char!, name: name!, aliases, keywords, category: c.id };
    }),
}));

export const ALL_EMOJI: Emoji[] = CATEGORIES.flatMap((c) => c.emoji);

const BY_CODE = new Map<string, Emoji>();
const BY_CHAR = new Map<string, Emoji>();
for (const e of ALL_EMOJI) {
  for (const code of [e.name, ...e.aliases]) if (!BY_CODE.has(code)) BY_CODE.set(code, e);
  if (!BY_CHAR.has(e.char)) BY_CHAR.set(e.char, e);
}

/** "tada" → "🎉" (primary name or alias). */
export function emojiFor(code: string): string | undefined {
  return BY_CODE.get(code.toLowerCase())?.char;
}

/** "🎉" → its table entry (tolerates a missing or extra U+FE0F variation selector). */
export function emojiInfo(char: string): Emoji | undefined {
  return BY_CHAR.get(char) ?? BY_CHAR.get(char.replace(/\uFE0F/g, "")) ?? BY_CHAR.get(`${char}\uFE0F`);
}

/** ":tada:" for a known emoji; the emoji itself when it isn't in the table (an agent may react with anything). */
export function shortcodeOf(char: string): string {
  const e = emojiInfo(char);
  return e ? `:${e.name}:` : char;
}

// ── search ─────────────────────────────────────────────────────────────────────────────────────

/**
 * Best first: an exact shortcode, a primary shortcode prefix, alias prefix, keyword prefix, a word inside a shortcode ("check" finds
 * white_check_mark), then any substring. Ties go to the user's frequent emoji, then table order (common first).
 */
export function searchEmoji(query: string, limit = 50, frequent: readonly string[] = []): Emoji[] {
  const q = query.toLowerCase().replace(/^:|:$/g, "").trim();
  if (!q) return ALL_EMOJI.slice(0, limit);
  const rank = new Map(frequent.map((c, i) => [c, i]));
  const scored: { e: Emoji; s: number; i: number }[] = [];
  ALL_EMOJI.forEach((e, i) => {
    let s: number | null = null;
    if (e.name === q || e.aliases.includes(q)) s = -1;
    else if (e.name.startsWith(q)) s = 0;
    else if (e.aliases.some((a) => a.startsWith(q))) s = 1;
    else if (e.keywords.some((k) => k.startsWith(q))) s = 2;
    else if ([e.name, ...e.aliases].some((c) => c.split(/[_-]/).some((w) => w.startsWith(q)))) s = 3;
    else if (e.name.includes(q) || e.aliases.some((a) => a.includes(q))) s = 4;
    if (s !== null) scored.push({ e, s, i });
  });
  scored.sort((a, b) => a.s - b.s || (rank.get(a.e.char) ?? 1e9) - (rank.get(b.e.char) ?? 1e9) || a.i - b.i);
  return scored.slice(0, limit).map((x) => x.e);
}

// ── :shortcode: → emoji ────────────────────────────────────────────────────────────────────────

const SHORTCODE = /:([a-z0-9_+-]{1,40}):/gi;
const URL = /\bhttps?:\/\/\S+|\b[a-z][a-z0-9+.-]*:\/\/\S+/gi;

/** Replace :name: in prose that holds no code. Skips URLs and anything glued to a word, digit or colon (12:30:45, fe80::a:1). */
function replacePlain(text: string): string {
  const urls: [number, number][] = [];
  for (const m of text.matchAll(URL)) urls.push([m.index!, m.index! + m[0].length]);
  // A converted shortcode may be followed straight away by another (":eyes::fire:"); any other ":" before is not ours.
  let convertedEnd = -1;
  return text.replace(SHORTCODE, (whole, code: string, at: number) => {
    const before = text[at - 1];
    const after = text[at + whole.length];
    const chained = before === ":" && at === convertedEnd;
    if (before !== undefined && !chained && /[\p{L}\p{N}_:/]/u.test(before)) return whole;
    if (after !== undefined && /[\p{L}\p{N}_]/u.test(after)) return whole;
    if (urls.some(([s, e]) => at >= s && at < e)) return whole;
    const char = emojiFor(code);
    if (!char) return whole;
    convertedEnd = at + whole.length;
    return char;
  });
}

/** Split text into code (fenced blocks and `inline`) and prose. Code is returned untouched. */
function splitCode(text: string): { code: boolean; text: string }[] {
  const out: { code: boolean; text: string }[] = [];
  const re = /^```[^\n]*\n[\s\S]*?(?:^```[^\n]*$|(?![\s\S]))|`[^`\n]+`/gm;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index! > last) out.push({ code: false, text: text.slice(last, m.index) });
    out.push({ code: true, text: m[0] });
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push({ code: false, text: text.slice(last) });
  return out;
}

/** `:tada:` → 🎉 everywhere except inside inline code, code blocks and URLs. Unknown names stay as typed. */
export function replaceShortcodes(text: string): string {
  if (!text.includes(":")) return text;
  return splitCode(text)
    .map((p) => (p.code ? p.text : replacePlain(p.text)))
    .join("");
}

/** Same as replaceShortcodes for a fragment already known to hold no code (the markdown renderer's text runs). */
export const replaceShortcodesInProse = replacePlain;

const segmenter = typeof Intl !== "undefined" && "Segmenter" in Intl ? new Intl.Segmenter(undefined, { granularity: "grapheme" }) : null;
const EMOJI_GRAPHEME = /^(?:\p{Extended_Pictographic}|\p{Regional_Indicator}|[0-9#*]\uFE0F?\u20E3)/u;

/** 1 to 3 emoji and nothing else (whitespace aside): Slack's "jumbomoji". */
export function isJumbo(text: string): boolean {
  const t = replaceShortcodes(text).replace(/\s+/g, "");
  if (!t || t.length > 40 || !segmenter) return false;
  const parts = [...segmenter.segment(t)].map((s) => s.segment);
  return parts.length >= 1 && parts.length <= 3 && parts.every((g) => EMOJI_GRAPHEME.test(g));
}

// ── composer: ":" autocomplete ─────────────────────────────────────────────────────────────────

/** An open ":query" ending at the caret; `start` is the index of the ":". */
export type EmojiTrigger = { start: number; query: string };

/** Inside inline code or a fenced block at `at` (same rule as the @mention trigger). */
export function inCode(text: string, at: number): boolean {
  const lineStart = text.lastIndexOf("\n", at - 1) + 1;
  if ((text.slice(lineStart, at).match(/`/g) ?? []).length % 2 === 1) return true;
  return (text.slice(0, lineStart).match(/^```/gm) ?? []).length % 2 === 1;
}

/**
 * ":" followed by 2+ name characters opens the shortcode picker. The ":" must start the text or follow whitespace or an
 * opening bracket, so a URL scheme (https://), a time (12:30), "key:value" and inline code never trigger it.
 */
export function detectEmojiTrigger(text: string, caret: number): EmojiTrigger | null {
  if (caret < 0 || caret > text.length) return null;
  const at = text.lastIndexOf(":", caret - 1);
  if (at < 0) return null;
  const query = text.slice(at + 1, caret);
  if (!/^[a-z0-9_+-]{2,40}$/i.test(query)) return null;
  if (/^\d+$/.test(query)) return null; // ":30" is a time or a count, not an emoji
  if (at > 0 && !/[\s([{]/.test(text[at - 1]!)) return null;
  if (inCode(text, at)) return null;
  return { start: at, query };
}

/** Replace ":query" with the emoji plus a trailing space; caret after the space. */
export function insertEmoji(text: string, trigger: EmojiTrigger, caret: number, char: string): { text: string; caret: number } {
  const after = text.slice(caret);
  const space = after.startsWith(" ") ? "" : " ";
  return { text: text.slice(0, trigger.start) + char + space + after, caret: trigger.start + char.length + 1 };
}

/** Insert an emoji at the caret (or over the selection), from the picker. */
export function insertAtCaret(text: string, start: number, end: number, char: string): { text: string; caret: number } {
  return { text: text.slice(0, start) + char + text.slice(end), caret: start + char.length };
}

/**
 * Typing the closing ":" of a known shortcode converts it on the spot (as Slack does): "nice :tada:" → "nice 🎉".
 * Returns null when nothing changes.
 */
export function completeShortcode(text: string, caret: number): { text: string; caret: number } | null {
  if (text[caret - 1] !== ":") return null;
  const m = /(^|[\s([{]):([a-z0-9_+-]{1,40}):$/i.exec(text.slice(0, caret));
  if (!m) return null;
  const start = caret - m[2]!.length - 2;
  if (inCode(text, start)) return null;
  const char = emojiFor(m[2]!);
  if (!char) return null;
  return { text: text.slice(0, start) + char + text.slice(caret), caret: start + char.length };
}

// ── frequently used ────────────────────────────────────────────────────────────────────────────

export const FREQUENT_KEY = "bb_emoji_freq";
export const DEFAULT_FREQUENT = ["👍", "✅", "👀", "🎉", "🙏", "🔥"];
export const DEFAULT_QUICK = ["✅", "👀", "👍"];

type Store = Pick<Storage, "getItem" | "setItem">;
const store = (): Store | null => {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
};

/** Parsed once per stored value: every message row asks for its quick reactions on each render. */
let parsed: { raw: string | null; counts: Record<string, number> } | null = null;
function counts(s: Store | null): Record<string, number> {
  const raw = s?.getItem(FREQUENT_KEY) ?? null;
  if (parsed && parsed.raw === raw) return { ...parsed.counts };
  let c: Record<string, number> = {};
  try {
    const v = JSON.parse(raw ?? "{}");
    if (v && typeof v === "object" && !Array.isArray(v)) c = v as Record<string, number>;
  } catch {
    /* junk in storage: start again */
  }
  parsed = { raw, counts: c };
  return { ...c };
}

/** Most used first; padded with the defaults so the row is never short. */
export function frequentEmoji(n = 12, s: Store | null = store()): string[] {
  const used = Object.entries(counts(s))
    .filter(([, c]) => typeof c === "number" && c > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([e]) => e);
  const out = [...used];
  for (const d of DEFAULT_FREQUENT) if (!out.includes(d)) out.push(d);
  return out.slice(0, n);
}

/** The hover toolbar's three quick reactions: the user's three most used, else ✅ 👀 👍. */
export function quickReactions(s: Store | null = store()): string[] {
  const used = Object.entries(counts(s))
    .filter(([, c]) => c > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([e]) => e);
  const out = used.slice(0, 3);
  for (const d of DEFAULT_QUICK) if (out.length < 3 && !out.includes(d)) out.push(d);
  return out;
}

export function recordEmojiUse(char: string, s: Store | null = store()) {
  if (!s) return;
  const c = counts(s);
  c[char] = (c[char] ?? 0) + 1;
  try {
    s.setItem(FREQUENT_KEY, JSON.stringify(c));
  } catch {
    /* quota or private mode: memory only */
  }
}

// ── reactions ──────────────────────────────────────────────────────────────────────────────────

export type Reaction = { emoji: string; count: number; handles: string[] };

export function reactedBy(r: Reaction, handle: string | undefined): boolean {
  return !!handle && r.handles.includes(handle);
}

/** The op a click sends, and the optimistic state: remove mine if I reacted, otherwise add it (new pills go last). */
export function toggleReaction(list: readonly Reaction[], emoji: string, me: string): { op: "add" | "remove"; next: Reaction[] } {
  const hit = list.find((r) => r.emoji === emoji);
  if (hit && hit.handles.includes(me)) {
    const next = list
      .map((r) => (r === hit ? { ...r, count: r.count - 1, handles: r.handles.filter((h) => h !== me) } : r))
      .filter((r) => r.count > 0);
    return { op: "remove", next };
  }
  if (hit) return { op: "add", next: list.map((r) => (r === hit ? { ...r, count: r.count + 1, handles: [...r.handles, me] } : r)) };
  return { op: "add", next: [...list, { emoji, count: 1, handles: [me] }] };
}

/** "Ana and Enrichment Agent reacted with :eyes:" / "A, B and 3 others reacted with :tada:" (handles hold up to 20). */
export function reactionLabel(r: Reaction, nameOf: (handle: string) => string): string {
  const names = r.handles.map(nameOf);
  const others = Math.max(0, r.count - r.handles.length);
  const parts = others > 0 ? [...names, `${others} ${others === 1 ? "other" : "others"}`] : names;
  const who = parts.length <= 1 ? (parts[0] ?? "Someone") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
  return `${who} reacted with ${shortcodeOf(r.emoji)}`;
}

// ── typing ─────────────────────────────────────────────────────────────────────────────────────

export type Typist = { handle: string; display_name: string; kind: string };

/** "Enrichment Agent is typing…", "A and B are typing…", "Several people are typing…" (3 or more), or "". */
export function typingText(list: readonly Typist[]): string {
  const names = [...new Set(list.map((t) => t.display_name || t.handle))];
  if (names.length === 0) return "";
  if (names.length === 1) return `${names[0]} is typing…`;
  if (names.length === 2) return `${names[0]} and ${names[1]} are typing…`;
  return "Several people are typing…";
}

/** Query string for /typing in one scope: a thread (root id), else an incident, else a channel. */
export function typingScope(s: { channel?: string; incident?: string | null; thread?: string | null }): Record<string, string> {
  if (s.thread) return { thread: s.thread };
  if (s.incident) return { incident: s.incident };
  return s.channel ? { channel: s.channel } : {};
}

/** At most one "I'm typing" ping per interval, and never for an empty draft. */
export function createTypingThrottle(intervalMs = 3000, now: () => number = () => Date.now()) {
  let last = -Infinity;
  return {
    shouldSend(draft: string): boolean {
      if (!draft.trim()) return false;
      const t = now();
      if (t - last < intervalMs) return false;
      last = t;
      return true;
    },
    reset() {
      last = -Infinity;
    },
  };
}
