import { describe, expect, it } from "vitest";
import {
  ALL_EMOJI,
  CATEGORIES,
  completeShortcode,
  createTypingThrottle,
  detectEmojiTrigger,
  emojiFor,
  frequentEmoji,
  insertEmoji,
  isJumbo,
  quickReactions,
  reactionLabel,
  recordEmojiUse,
  replaceShortcodes,
  searchEmoji,
  shortcodeOf,
  toggleReaction,
  typingScope,
  typingText,
  type Reaction,
} from "../lib/emoji";

function memStore(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init));
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
}

describe("emoji table", () => {
  it("has a curated set in Slack's categories with unique primary names", () => {
    expect(ALL_EMOJI.length).toBeGreaterThanOrEqual(400);
    expect(ALL_EMOJI.length).toBeLessThanOrEqual(600);
    expect(CATEGORIES.map((c) => c.label)).toEqual(["Smileys & People", "Nature", "Food & Drink", "Activity", "Travel & Places", "Objects", "Symbols", "Flags"]);
    expect(CATEGORIES.find((c) => c.id === "flags")!.emoji.length).toBeLessThanOrEqual(40);
    const names = ALL_EMOJI.map((e) => e.name);
    expect(new Set(names).size).toBe(names.length);
    for (const e of ALL_EMOJI) expect(e.name).toMatch(/^[a-z0-9_+-]+$/);
  });
  it("knows the shortcodes a SOC board uses", () => {
    expect(emojiFor("thumbsup")).toBe("👍");
    expect(emojiFor("+1")).toBe("👍");
    expect(emojiFor("white_check_mark")).toBe("✅");
    expect(emojiFor("eyes")).toBe("👀");
    expect(emojiFor("tada")).toBe("🎉");
    expect(emojiFor("fire")).toBe("🔥");
    expect(emojiFor("rotating_light")).toBe("🚨");
    expect(emojiFor("shield")).toBe("🛡️");
    expect(emojiFor("bug")).toBe("🐛");
    expect(emojiFor("lock")).toBe("🔒");
    expect(emojiFor("nope_not_real")).toBeUndefined();
  });
  it("maps an emoji back to its primary shortcode, tolerating the variation selector", () => {
    expect(shortcodeOf("👀")).toBe(":eyes:");
    expect(shortcodeOf("🛡")).toBe(":shield:");
    expect(shortcodeOf("🫠")).toBe("🫠");
  });
});

describe("searchEmoji", () => {
  it("ranks a shortcode prefix first, then aliases, then keywords", () => {
    expect(searchEmoji("eye")[0]!.char).toBe("👀");
    expect(searchEmoji("thumbs")[0]!.char).toBe("👍");
    expect(searchEmoji("+1")[0]!.char).toBe("👍");
    // "approve" is a keyword only
    expect(searchEmoji("approve").map((e) => e.char)).toContain("✅");
    // "check" finds white_check_mark through a word inside the shortcode, after names starting with "check"
    const check = searchEmoji("check").map((e) => e.name);
    expect(check[0]).toBe("checkered_flag");
    expect(check).toContain("white_check_mark");
  });
  it("accepts a leading colon and is case-insensitive", () => {
    expect(searchEmoji(":TaDa")[0]!.char).toBe("🎉");
  });
  it("breaks ties with frequently used emoji", () => {
    expect(searchEmoji("heart")[0]!.char).toBe("❤️"); // an exact name wins
    const plain = searchEmoji("love").map((e) => e.char);
    const withFreq = searchEmoji("love", 50, ["💜"]).map((e) => e.char);
    expect(plain[0]).not.toBe("💜");
    expect(withFreq[0]).toBe("💜");
  });
  it("returns nothing for nonsense", () => {
    expect(searchEmoji("qqqzzz")).toEqual([]);
  });
});

describe("replaceShortcodes", () => {
  it("converts known :names: in prose", () => {
    expect(replaceShortcodes("nice :tada: work :+1:")).toBe("nice 🎉 work 👍");
    expect(replaceShortcodes(":eyes:")).toBe("👀");
    expect(replaceShortcodes("(:fire:)")).toBe("(🔥)");
    expect(replaceShortcodes(":eyes::fire:")).toBe("👀🔥");
  });
  it("leaves unknown names as typed", () => {
    expect(replaceShortcodes("see :notanemoji: here")).toBe("see :notanemoji: here");
  });
  it("never converts inside inline code or code blocks", () => {
    expect(replaceShortcodes("run `echo :tada:` then :tada:")).toBe("run `echo :tada:` then 🎉");
    expect(replaceShortcodes("```\nkey :fire: here\n```\n:fire:")).toBe("```\nkey :fire: here\n```\n🔥");
    expect(replaceShortcodes("```sh\nunterminated :fire:")).toBe("```sh\nunterminated :fire:");
  });
  it("never converts inside URLs, times, IPv6 or key:value", () => {
    expect(replaceShortcodes("https://example.com/a:fire:b")).toBe("https://example.com/a:fire:b");
    expect(replaceShortcodes("see https://x.test/:fire:/y ok")).toBe("see https://x.test/:fire:/y ok");
    expect(replaceShortcodes("at 12:30:45 today")).toBe("at 12:30:45 today");
    expect(replaceShortcodes("fe80::1:ok:")).toBe("fe80::1:ok:");
    expect(replaceShortcodes("level:fire:x")).toBe("level:fire:x");
  });
});

describe("isJumbo", () => {
  it("is true for 1 to 3 emoji and nothing else", () => {
    expect(isJumbo("🎉")).toBe(true);
    expect(isJumbo("👍 🎉 🔥")).toBe(true);
    expect(isJumbo(":tada::fire:")).toBe(true);
    expect(isJumbo(":tada: :fire:")).toBe(true);
    expect(isJumbo("🇦🇺")).toBe(true);
    expect(isJumbo("🧑‍💻")).toBe(true);
  });
  it("is false with text, digits or 4+ emoji", () => {
    expect(isJumbo("ok 🎉")).toBe(false);
    expect(isJumbo("🎉🎉🎉🎉")).toBe(false);
    expect(isJumbo("1")).toBe(false);
    expect(isJumbo("")).toBe(false);
  });
});

describe("detectEmojiTrigger", () => {
  it("opens after ':' plus two or more name characters at a word start", () => {
    expect(detectEmojiTrigger(":ta", 3)).toEqual({ start: 0, query: "ta" });
    expect(detectEmojiTrigger("nice :tad", 9)).toEqual({ start: 5, query: "tad" });
    expect(detectEmojiTrigger("(:+1", 4)).toEqual({ start: 1, query: "+1" });
    expect(detectEmojiTrigger("line\n:fi", 8)).toEqual({ start: 5, query: "fi" });
  });
  it("waits for two characters", () => {
    expect(detectEmojiTrigger(":", 1)).toBeNull();
    expect(detectEmojiTrigger(":t", 2)).toBeNull();
  });
  it("never fires in a URL, a time, key:value or inline code", () => {
    expect(detectEmojiTrigger("https://example", 15)).toBeNull();
    expect(detectEmojiTrigger("see https://ex", 14)).toBeNull();
    expect(detectEmojiTrigger("at 12:30", 8)).toBeNull();
    expect(detectEmojiTrigger("meet at :30", 11)).toBeNull();
    expect(detectEmojiTrigger("status:open", 11)).toBeNull();
    expect(detectEmojiTrigger("run `a :fi", 10)).toBeNull();
    expect(detectEmojiTrigger("```\n:fi", 7)).toBeNull();
    expect(detectEmojiTrigger("`x` :fi", 7)).toEqual({ start: 4, query: "fi" });
  });
  it("closes once the token holds a space", () => {
    expect(detectEmojiTrigger(":tada ", 6)).toBeNull();
  });
  it("inserts the emoji with a trailing space", () => {
    const t = detectEmojiTrigger("great :ta", 9)!;
    expect(insertEmoji("great :ta", t, 9, "🎉")).toEqual({ text: "great 🎉 ", caret: 6 + "🎉".length + 1 });
    expect(insertEmoji(":ta more", { start: 0, query: "ta" }, 3, "🎉").text).toBe("🎉 more");
  });
  it("converts a complete :shortcode: when its closing colon is typed", () => {
    expect(completeShortcode("nice :tada:", 11)).toEqual({ text: "nice 🎉", caret: 5 + "🎉".length });
    expect(completeShortcode("nice :nope:", 11)).toBeNull();
    expect(completeShortcode("`:tada:", 7)).toBeNull();
    expect(completeShortcode("12:30:", 6)).toBeNull();
  });
});

describe("frequently used", () => {
  it("falls back to the defaults and puts used emoji first", () => {
    const s = memStore();
    expect(frequentEmoji(6, s)).toEqual(["👍", "✅", "👀", "🎉", "🙏", "🔥"]);
    expect(quickReactions(s)).toEqual(["✅", "👀", "👍"]);
    recordEmojiUse("🚨", s);
    recordEmojiUse("🚨", s);
    recordEmojiUse("🐛", s);
    expect(frequentEmoji(4, s)).toEqual(["🚨", "🐛", "👍", "✅"]);
    expect(quickReactions(s)).toEqual(["🚨", "🐛", "✅"]);
  });
  it("survives junk in storage", () => {
    expect(frequentEmoji(3, memStore({ bb_emoji_freq: "{oops" }))).toEqual(["👍", "✅", "👀"]);
  });
});

describe("reactions", () => {
  const list: Reaction[] = [
    { emoji: "👀", count: 1, handles: ["enrichment-agent"] },
    { emoji: "✅", count: 2, handles: ["analyst", "analyst2"] },
  ];
  it("adds me to an existing reaction", () => {
    const r = toggleReaction(list, "👀", "analyst");
    expect(r.op).toBe("add");
    expect(r.next[0]).toEqual({ emoji: "👀", count: 2, handles: ["enrichment-agent", "analyst"] });
  });
  it("removes my reaction, dropping the pill at zero", () => {
    const r = toggleReaction(list, "✅", "analyst");
    expect(r.op).toBe("remove");
    expect(r.next[1]).toEqual({ emoji: "✅", count: 1, handles: ["analyst2"] });
    const gone = toggleReaction([{ emoji: "🎉", count: 1, handles: ["analyst"] }], "🎉", "analyst");
    expect(gone).toEqual({ op: "remove", next: [] });
  });
  it("appends a new reaction last (order of first reaction)", () => {
    const r = toggleReaction(list, "🎉", "analyst");
    expect(r.next.map((x) => x.emoji)).toEqual(["👀", "✅", "🎉"]);
    expect(list).toHaveLength(2); // input untouched
  });
  it("labels who reacted by display name, with overflow counted", () => {
    const names: Record<string, string> = { analyst: "SOC Analyst", analyst2: "Second Analyst", "enrichment-agent": "Enrichment Agent" };
    const nameOf = (h: string) => names[h] ?? h;
    expect(reactionLabel(list[0]!, nameOf)).toBe("Enrichment Agent reacted with :eyes:");
    expect(reactionLabel(list[1]!, nameOf)).toBe("SOC Analyst and Second Analyst reacted with :white_check_mark:");
    expect(reactionLabel({ emoji: "🫠", count: 1, handles: ["x"] }, nameOf)).toBe("x reacted with 🫠");
    expect(reactionLabel({ emoji: "🎉", count: 23, handles: ["analyst", "analyst2"] }, nameOf)).toBe("SOC Analyst, Second Analyst and 21 others reacted with :tada:");
  });
});

describe("typing", () => {
  const a = { handle: "enrichment-agent", display_name: "Enrichment Agent", kind: "agent" };
  const b = { handle: "analyst2", display_name: "Second Analyst", kind: "human" };
  const c = { handle: "observer-bot", display_name: "Observer Bot", kind: "agent" };
  it("reads like Slack", () => {
    expect(typingText([])).toBe("");
    expect(typingText([a])).toBe("Enrichment Agent is typing…");
    expect(typingText([a, b])).toBe("Enrichment Agent and Second Analyst are typing…");
    expect(typingText([a, b, c])).toBe("Several people are typing…");
    expect(typingText([a, a])).toBe("Enrichment Agent is typing…");
  });
  it("picks one scope: thread, then incident, then channel", () => {
    expect(typingScope({ channel: "triage", thread: "t1", incident: "i1" })).toEqual({ thread: "t1" });
    expect(typingScope({ channel: "incidents", incident: "i1" })).toEqual({ incident: "i1" });
    expect(typingScope({ channel: "triage" })).toEqual({ channel: "triage" });
  });
  it("throttles pings to one per 3 s and never sends an empty draft", () => {
    let t = 0;
    const th = createTypingThrottle(3000, () => t);
    expect(th.shouldSend("   ")).toBe(false);
    expect(th.shouldSend("h")).toBe(true);
    t = 1000;
    expect(th.shouldSend("he")).toBe(false);
    t = 2999;
    expect(th.shouldSend("hel")).toBe(false);
    t = 3000;
    expect(th.shouldSend("hell")).toBe(true);
    th.reset();
    expect(th.shouldSend("hello")).toBe(true);
  });
});
