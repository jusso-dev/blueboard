import { describe, expect, it } from "vitest";
import type { Message } from "../lib/api";
import { avatarTint, dayLabel, feedRows, groupsWith, initials, relativeTime, replySummary, threadView } from "../lib/chat";

let seq = 0;
function msg(p: Partial<Message> & { at: string; who?: string }): Message {
  seq++;
  const who = p.who ?? "analyst";
  return {
    id: p.id ?? `m${seq}`,
    seq: String(seq),
    channel: "triage",
    author: p.author ?? { handle: who, display_name: who, kind: "human" },
    parent_id: p.parent_id ?? null,
    incident_id: null,
    incident_graph_id: null,
    type: p.type ?? "chat",
    body: "x",
    payload: null,
    mentions: [],
    claim_state: "open",
    claimed_by: null,
    created_at: p.at,
    reply_count: p.reply_count,
    last_reply_at: p.last_reply_at,
    reply_authors: p.reply_authors,
  };
}

describe("dayLabel", () => {
  const now = new Date(2026, 10, 26, 15, 0);
  it("says Today and Yesterday", () => {
    expect(dayLabel(new Date(2026, 10, 26, 1, 0).toISOString(), now)).toBe("Today");
    expect(dayLabel(new Date(2026, 10, 25, 23, 0).toISOString(), now)).toBe("Yesterday");
  });
  it("uses weekday, day, month without an ordinal, and adds the year only for other years", () => {
    expect(dayLabel(new Date(2026, 10, 24, 9, 0).toISOString(), now)).toBe("Tuesday, 24 November");
    expect(dayLabel(new Date(2025, 11, 31, 9, 0).toISOString(), now)).toBe("Wednesday, 31 December 2025");
  });
});

describe("grouping", () => {
  const t = (min: number) => new Date(2026, 10, 26, 10, min).toISOString();
  it("groups the same author and type within five minutes", () => {
    expect(groupsWith(msg({ at: t(0) }), msg({ at: t(4) }))).toBe(true);
    expect(groupsWith(msg({ at: t(0) }), msg({ at: t(6) }))).toBe(false);
  });
  it("breaks on author, type, system posts and thread roots", () => {
    expect(groupsWith(msg({ at: t(0) }), msg({ at: t(1), who: "other" }))).toBe(false);
    expect(groupsWith(msg({ at: t(0) }), msg({ at: t(1), type: "finding" }))).toBe(false);
    const sys = { handle: "board", display_name: "Blueboard", kind: "system" as const };
    expect(groupsWith(msg({ at: t(0), author: sys }), msg({ at: t(1), author: sys }))).toBe(false);
    expect(groupsWith(msg({ at: t(0), reply_count: 2 }), msg({ at: t(1) }))).toBe(false);
  });
  it("breaks across days", () => {
    const late = new Date(2026, 10, 25, 23, 58).toISOString();
    const early = new Date(2026, 10, 26, 0, 1).toISOString();
    const rows = feedRows([msg({ at: late }), msg({ at: early })]);
    expect(rows[1]!.grouped).toBe(false);
    expect(rows[1]!.newDay).toBe(true);
  });
});

describe("threadView", () => {
  const t = (min: number) => new Date(2026, 10, 26, 10, min).toISOString();
  it("hides replies under their root and rolls them up", () => {
    const root = msg({ id: "r", at: t(0) });
    const a = msg({ parent_id: "r", at: t(1), who: "a" });
    const b = msg({ parent_id: "r", at: t(2), who: "b" });
    const a2 = msg({ parent_id: "r", at: t(3), who: "a" });
    const v = threadView([root, a, b, a2]);
    expect(v.visible.map((m) => m.id)).toEqual(["r"]);
    const s = v.derived.get("r")!;
    expect(s.count).toBe(3);
    expect(s.lastAt).toBe(t(3));
    expect(s.authors.map((x) => x.handle)).toEqual(["a", "b"]);
  });
  it("keeps a reply whose root isn't on the page, marked as an orphan", () => {
    const lone = msg({ id: "x", parent_id: "elsewhere", at: t(0) });
    const v = threadView([lone]);
    expect(v.visible).toHaveLength(1);
    expect(v.orphans.has("x")).toBe(true);
  });
  it("prefers the API's roll-up fields and degrades to just a count", () => {
    const withApi = msg({ at: t(0), reply_count: 5, last_reply_at: t(9), reply_authors: [{ handle: "z", display_name: "Z", kind: "agent" }] });
    expect(replySummary(withApi)).toEqual({ count: 5, lastAt: t(9), authors: [{ handle: "z", display_name: "Z", kind: "agent" }] });
    expect(replySummary(msg({ at: t(0), reply_count: 2 }))).toEqual({ count: 2, lastAt: null, authors: [] });
    expect(replySummary(msg({ at: t(0), reply_count: 0 }))).toBeNull();
  });
});

describe("avatars and times", () => {
  it("initials skip bracketed suffixes and fall back to the handle", () => {
    expect(initials("SOC Analyst (dev)")).toBe("SA");
    expect(initials("Enrichment Agent")).toBe("EA");
    expect(initials("", "observer-bot")).toBe("OB");
  });
  it("avatar tint is stable and in 1..6", () => {
    expect(avatarTint("analyst")).toBe(avatarTint("analyst"));
    for (const h of ["a", "b", "enrichment-agent", "analyst2"]) expect(avatarTint(h)).toBeGreaterThanOrEqual(1), expect(avatarTint(h)).toBeLessThanOrEqual(6);
  });
  it("relative time reads naturally", () => {
    const now = Date.parse("2026-11-26T10:00:00Z");
    expect(relativeTime("2026-11-26T09:59:30Z", now)).toBe("just now");
    expect(relativeTime("2026-11-26T09:55:00Z", now)).toBe("5 minutes ago");
    expect(relativeTime("2026-11-26T08:00:00Z", now)).toBe("2 hours ago");
    expect(relativeTime("2026-11-25T08:00:00Z", now)).toBe("yesterday");
  });
});
