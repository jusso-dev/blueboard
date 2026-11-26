/**
 * Slack-like GIF support helpers and strict URL safety checks.
 *
 * Security model: browsers only ever load animated GIFs from the exact trusted CDN host allowlist
 * (matching api/Blueboard.Api/Board/Gifs.cs and web/host/SecurityHeaders.cs). Arbitrary remote
 * image URLs are never rendered as <img>, preventing tracking pixels and SSRF/leakage.
 */

export const ALLOWED_GIF_HOSTS = new Set([
  "media.giphy.com",
  "media0.giphy.com",
  "media1.giphy.com",
  "media2.giphy.com",
  "media3.giphy.com",
  "media4.giphy.com",
  "i.giphy.com",
  "media.tenor.com",
  "c.tenor.com",
]);

export type GifPayload = {
  url: string;
  preview_url?: string;
  title?: string;
  width?: number;
  height?: number;
  provider?: "giphy" | "tenor";
};

export type GifItem = {
  id: string;
  title: string;
  url: string;
  preview_url: string;
  width?: number | null;
  height?: number | null;
  provider: string;
  tags?: string[];
};

export type GifSearchResponse = {
  enabled: boolean;
  provider: string;
  items: GifItem[];
};

/** Returns true only for clean https:// URLs on the exact allowlisted GIF CDN hosts. */
export function isAllowedGifUrl(raw: string | null | undefined): raw is string {
  if (!raw || raw.length > 2048) return false;
  if (/[\s()<>]/.test(raw)) return false;
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return false;
    if (u.username || u.password || u.port || u.hash) return false;
    const host = u.hostname.replace(/\.$/, "").toLowerCase();
    return ALLOWED_GIF_HOSTS.has(host);
  } catch {
    return false;
  }
}

/** Validates an external navigation href: only http(s) URLs are allowed (blocks javascript:, data:, etc.). */
export function safeHref(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 4096) return null;
  try {
    const u = new URL(trimmed);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    return u.toString();
  } catch {
    return null;
  }
}

/** Detects Slack-style `/giphy <query>` or `/gif <query>` commands in the composer. */
export function parseGifCommand(text: string): { command: "giphy" | "gif"; query: string } | null {
  const m = text.trim().match(/^\/(giphy|gif)(?:\s+([\s\S]*))?$/i);
  if (!m) return null;
  return {
    command: m[1]!.toLowerCase() as "giphy" | "gif",
    query: (m[2] ?? "").trim(),
  };
}

export function gifProviderOf(url: string): "giphy" | "tenor" {
  try {
    return new URL(url).hostname.toLowerCase().endsWith("tenor.com") ? "tenor" : "giphy";
  } catch {
    return "giphy";
  }
}

/** Extracts and validates `payload.gif` from a board message payload. */
export function extractGif(payload: unknown): GifPayload | null {
  if (!payload || typeof payload !== "object") return null;
  const gif = (payload as { gif?: unknown }).gif;
  if (!gif || typeof gif !== "object") return null;
  const g = gif as Record<string, unknown>;
  const url = typeof g.url === "string" ? g.url : null;
  if (!isAllowedGifUrl(url)) return null;
  const preview = typeof g.preview_url === "string" && isAllowedGifUrl(g.preview_url) ? g.preview_url : undefined;
  const title = typeof g.title === "string" ? g.title.trim().slice(0, 200) : undefined;
  const width = typeof g.width === "number" && g.width > 0 && g.width <= 4096 ? g.width : undefined;
  const height = typeof g.height === "number" && g.height > 0 && g.height <= 4096 ? g.height : undefined;
  const provider = g.provider === "tenor" || g.provider === "giphy" ? g.provider : gifProviderOf(url);
  return { url, preview_url: preview, title, width, height, provider };
}

export function toGifPayload(item: GifItem): GifPayload {
  return {
    url: item.url,
    preview_url: isAllowedGifUrl(item.preview_url) ? item.preview_url : undefined,
    title: item.title.trim().slice(0, 200) || undefined,
    width: item.width ?? undefined,
    height: item.height ?? undefined,
    provider: item.provider === "tenor" ? "tenor" : gifProviderOf(item.url),
  };
}

function giphy(id: string, title: string, tags: string[]): GifItem {
  return {
    id,
    title,
    url: `https://media.giphy.com/media/${id}/giphy.gif`,
    preview_url: `https://media.giphy.com/media/${id}/200w.gif`,
    width: 480,
    height: 270,
    provider: "giphy",
    tags,
  };
}

/** Local fallback matching the backend curated library so GIF search responds immediately even offline. */
export const CURATED_GIFS: GifItem[] = [
  giphy("3o7abKhOpu0NwenH3O", "Thumbs up — looks good", ["thumbs", "up", "lgtm", "approve", "approved", "yes", "ok", "good", "nice"]),
  giphy("QMHoU66sBXqqLqYvGO", "This is fine", ["fine", "fire", "incident", "sev1", "alert", "chaos", "monday", "oncall", "panic"]),
  giphy("l0MYt5jPR6QX5pnqM", "Party celebration", ["party", "celebrate", "win", "resolved", "closed", "done", "yay", "woohoo", "friday"]),
  giphy("3ohzdIuqJoo8QdKlnW", "Yes! Let's go", ["yes", "letsgo", "celebrate", "win", "awesome", "ship", "done"]),
  giphy("xT0xeJpnrWC4XWblEk", "Mind blown", ["mind", "blown", "wow", "whoa", "discovery", "finding", "cve", "zero", "day"]),
  giphy("13HgwGsXF0aiGY", "Typing furiously", ["hack", "hacker", "hackerman", "typing", "coding", "kql", "hunt", "hunting", "investigating"]),
  giphy("3o6Zt481isNVuQI1l6", "Cat typing on keyboard", ["cat", "typing", "work", "triage", "investigating", "busy", "keyboard"]),
  giphy("uWzS6ZLs0AaVOJlgRd", "Grabbing popcorn", ["popcorn", "watching", "waiting", "drama", "logs", "audit"]),
  giphy("3o7TKTDn976rzVgky4", "Suspicious squinting", ["suspicious", "sus", "hmm", "doubt", "ioc", "phishing", "threat", "investigate"]),
  giphy("TJawtKM6OCKkvwCIqX", "Facepalm", ["facepalm", "oops", "fail", "false", "positive", "sigh", "bruh", "misconfig"]),
  giphy("l41lFw057lAJQMwg0", "Coffee time", ["coffee", "morning", "oncall", "shift", "handover", "tired", "caffeine"]),
  giphy("3oriO0OEd9QIDdllqo", "Hello wave", ["hello", "hi", "wave", "hey", "welcome", "morning", "handover", "general"]),
  giphy("26u4lOMA8JKSnL9Uk", "Mission accomplished", ["done", "complete", "contained", "eradicated", "mission", "accomplished", "ship", "clean"]),
  giphy("xT5LMHxhOfscxPfIfm", "Ship it!", ["ship", "deploy", "release", "merge", "go", "rocket", "launch"]),
  giphy("5VKbvrjxpVJCM", "Excited reaction", ["wow", "nice", "excited", "awesome", "cool", "amazing", "great"]),
  giphy("3oEjI6SIIHBdRxXI40", "Waiting / loading", ["waiting", "loading", "pending", "approval", "soon", "patience"]),
  giphy("d3mlE7uhX8KFgEmY", "Smart move", ["smart", "big", "brain", "idea", "clever", "genius", "playbook"]),
  giphy("l2JehQ2GitHGdVG9y", "Alert / alarm", ["alert", "alarm", "siren", "critical", "high", "incident", "breach", "paged"]),
  giphy("111ebonMs90YLu", "Approved nod", ["approve", "approved", "nod", "nice", "good", "lgtm", "agree", "cheers"]),
  giphy("Ju7l5y9osyymQ", "Never gonna give you up", ["rick", "rickroll", "music", "dance", "fun", "troll"]),
];

export function searchLocalGifs(query: string, limit = 16): GifItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return CURATED_GIFS.slice(0, limit);
  const tokens = q.split(/\s+/).filter(Boolean);
  const scored = CURATED_GIFS.map((item) => {
    const tags = item.tags ?? [];
    const title = item.title.toLowerCase();
    let score = 0;
    for (const t of tokens) {
      if (tags.includes(t)) score += 10;
      else if (tags.some((tag) => tag.startsWith(t))) score += 6;
      else if (title.includes(t)) score += 4;
      else if (tags.some((tag) => tag.includes(t))) score += 2;
    }
    return { item, score };
  })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((x) => x.item)
    .slice(0, limit);
  return scored.length > 0 ? scored : CURATED_GIFS.slice(0, Math.min(limit, 6));
}
