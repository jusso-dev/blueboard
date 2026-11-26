import { describe, expect, it } from "vitest";
import { atInsertion, detectTrigger, insertMention, isActive, matchScore, parseMentions, rankParticipants, type Participant } from "../lib/mentions";

const NOW = Date.parse("2026-11-26T10:00:00Z");
const ago = (min: number) => new Date(NOW - min * 60_000).toISOString();

const people: Participant[] = [
  { handle: "enrichment-agent", display_name: "Enrichment Agent", kind: "agent", description: "Enriches incidents", last_seen_at: ago(2) },
  { handle: "my-agent", display_name: "My Agent (template)", kind: "agent", last_seen_at: null },
  { handle: "observer-bot", display_name: "Observer Bot", kind: "agent", last_seen_at: ago(60) },
  { handle: "analyst", display_name: "SOC Analyst (dev)", kind: "human", last_seen_at: ago(1) },
  { handle: "analyst2", display_name: "Second Analyst (dev)", kind: "human", last_seen_at: null },
  { handle: "board", display_name: "Blueboard", kind: "system", last_seen_at: null },
  { handle: "gone", display_name: "Gone Agent", kind: "agent", enabled: false },
];

describe("detectTrigger", () => {
  it("opens at the start, after whitespace and after an opening bracket", () => {
    expect(detectTrigger("@", 1)).toEqual({ start: 0, query: "" });
    expect(detectTrigger("ask @en", 7)).toEqual({ start: 4, query: "en" });
    expect(detectTrigger("line\n@an", 8)).toEqual({ start: 5, query: "an" });
    expect(detectTrigger("(cc @an", 7)).toEqual({ start: 4, query: "an" });
    expect(detectTrigger("(@an", 4)).toEqual({ start: 1, query: "an" });
  });
  it("never opens inside a word or an email address", () => {
    expect(detectTrigger("j.doe@contoso", 13)).toBeNull();
    expect(detectTrigger("a@b", 3)).toBeNull();
  });
  it("closes once the token holds a space or the caret leaves it", () => {
    expect(detectTrigger("@analyst ", 9)).toBeNull();
    expect(detectTrigger("@ana lyst", 9)).toBeNull();
    expect(detectTrigger("hi @an there", 2)).toBeNull();
  });
  it("only looks at text before the caret", () => {
    expect(detectTrigger("@analyst and more", 3)).toEqual({ start: 0, query: "an" });
  });
  it("ignores @ inside inline code and fenced code", () => {
    expect(detectTrigger("run `whoami @lo", 15)).toBeNull();
    expect(detectTrigger("`x` then @lo", 12)).toEqual({ start: 9, query: "lo" });
    expect(detectTrigger("```\nssh @host", 13)).toBeNull();
    expect(detectTrigger("```\nx\n```\n@an", 13)).toEqual({ start: 10, query: "an" });
  });
});

describe("matchScore", () => {
  it("ranks handle prefix, then word prefix, then substring", () => {
    expect(matchScore(people[3]!, "ana")).toBe(0);
    expect(matchScore(people[0]!, "agent")).toBe(1); // second word of the name / handle part
    expect(matchScore(people[3]!, "soc")).toBe(1);
    expect(matchScore(people[0]!, "rich")).toBe(2);
    expect(matchScore(people[0]!, "zzz")).toBeNull();
  });
  it("is case-insensitive", () => {
    expect(matchScore(people[0]!, "ENR")).toBe(0);
  });
});

describe("rankParticipants", () => {
  it("leaves out the system principal and disabled principals", () => {
    const handles = rankParticipants(people, "", NOW).map((p) => p.handle);
    expect(handles).not.toContain("board");
    expect(handles).not.toContain("gone");
    expect(handles).toHaveLength(5);
  });
  it("puts recently active first when match quality ties, agents and people interleaved", () => {
    const handles = rankParticipants(people, "", NOW).map((p) => p.handle);
    expect(handles.slice(0, 2).sort()).toEqual(["analyst", "enrichment-agent"]);
    expect(handles[0]).toBe("analyst"); // seen 1 min ago beats 2 min ago
  });
  it("prefers a prefix match over a substring match", () => {
    const handles = rankParticipants(people, "an", NOW).map((p) => p.handle);
    expect(handles[0]).toBe("analyst");
    expect(handles[1]).toBe("analyst2");
    // "SOC Analyst", "Second Analyst" also match by word; Enrichment Agent only as a substring ("enrichment" has no "an"...)
    expect(handles).not.toContain("observer-bot");
  });
  it("finds agents by a word of their name", () => {
    expect(rankParticipants(people, "en", NOW)[0]!.handle).toBe("enrichment-agent");
    expect(rankParticipants(people, "agent", NOW).map((p) => p.handle)).toEqual(expect.arrayContaining(["enrichment-agent", "my-agent"]));
  });
  it("returns nothing when no one matches", () => {
    expect(rankParticipants(people, "xyz", NOW)).toEqual([]);
  });
});

describe("insertMention", () => {
  it("replaces the token with @handle and a space, caret after it", () => {
    const t = "ask @en please";
    const r = insertMention(t, { start: 4, query: "en" }, 7, "enrichment-agent");
    expect(r.text).toBe("ask @enrichment-agent please");
    expect(r.caret).toBe("ask @enrichment-agent ".length);
  });
  it("adds the trailing space at the end of the text", () => {
    const r = insertMention("@a", { start: 0, query: "a" }, 2, "analyst");
    expect(r.text).toBe("@analyst ");
    expect(r.caret).toBe(9);
  });
});

describe("helpers", () => {
  it("isActive means seen within five minutes", () => {
    expect(isActive({ last_seen_at: ago(4) }, NOW)).toBe(true);
    expect(isActive({ last_seen_at: ago(6) }, NOW)).toBe(false);
    expect(isActive({ last_seen_at: null }, NOW)).toBe(false);
  });
  it("parseMentions matches the API's rules", () => {
    expect(parseMentions("hi @analyst and j.doe@contoso.com, cc @enrichment-agent")).toEqual(["analyst", "enrichment-agent"]);
  });
  it("the @ button adds a space after a word", () => {
    expect(atInsertion("", 0)).toBe("@");
    expect(atInsertion("hi ", 3)).toBe("@");
    expect(atInsertion("hi", 2)).toBe(" @");
  });
});
