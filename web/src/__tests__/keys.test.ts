import { describe, expect, it } from "vitest";
import { createKeyReader, isTyping, matches, SEQUENCE_MS, SHORTCUTS, type KeyInput } from "../lib/keys";

const el = (tagName: string, extra: Record<string, unknown> = {}) => ({ tagName, getAttribute: (n: string) => (extra[n] as string) ?? null, ...extra });
const body = el("BODY");
const key = (k: string, more: Partial<KeyInput> = {}): KeyInput => ({ key: k, target: body, ...more });

describe("key reader", () => {
  it("maps single keys and g sequences", () => {
    let t = 0;
    const read = createKeyReader(() => t);
    expect(read(key("j"))).toEqual({ type: "next" });
    expect(read(key("ArrowUp"))).toEqual({ type: "prev" });
    expect(read(key("Enter"))).toEqual({ type: "open" });
    expect(read(key("r"))).toEqual({ type: "reply" });
    expect(read(key("?"))).toEqual({ type: "help" });
    expect(read(key("/"))).toEqual({ type: "search" });
    expect(read(key("Escape"))).toEqual({ type: "escape" });
    for (const [k, to] of [["q", "/"], ["a", "/approvals"], ["s", "/search"], ["r", "/reports"]] as const) {
      expect(read(key("g"))).toBeNull();
      t += 100;
      expect(read(key(k))).toEqual({ type: "go", to });
    }
  });

  it("forgets a g after the sequence window", () => {
    let t = 0;
    const read = createKeyReader(() => t);
    read(key("g"));
    t += SEQUENCE_MS + 1;
    expect(read(key("a"))).toBeNull(); // plain "a" does nothing
    expect(read(key("r"))).toEqual({ type: "reply" });
  });

  it("opens the palette with Cmd+K or Ctrl+K, even with single keys off", () => {
    const read = createKeyReader();
    expect(read(key("k", { metaKey: true }))).toEqual({ type: "palette" });
    expect(read(key("K", { ctrlKey: true }), false)).toEqual({ type: "palette" });
    expect(read(key("j"), false)).toBeNull();
    expect(read(key("j", { ctrlKey: true }))).toBeNull();
  });

  it("does nothing while typing", () => {
    const read = createKeyReader();
    for (const target of [el("INPUT", { type: "text" }), el("TEXTAREA"), el("SELECT"), el("DIV", { isContentEditable: true }), el("DIV", { role: "combobox" })]) {
      expect(isTyping(target)).toBe(true);
      for (const k of ["j", "k", "r", "?", "/", "g", "Enter", "Escape"]) expect(read(key(k, { target }))).toBeNull();
      expect(read(key("k", { target, metaKey: true }))).toBeNull();
    }
    expect(isTyping(el("INPUT", { type: "checkbox" }))).toBe(false);
  });

  it("leaves Enter to links and buttons, and ignores composed or handled keys", () => {
    const read = createKeyReader();
    expect(read(key("Enter", { target: el("BUTTON") }))).toBeNull();
    expect(read(key("Enter", { target: el("A") }))).toBeNull();
    expect(read(key("j", { isComposing: true }))).toBeNull();
    expect(read(key("j", { defaultPrevented: true }))).toBeNull();
  });

  it("has no approve or deny shortcut", () => {
    const read = createKeyReader();
    const intents = "abcdefhilmnopqstuvwxyz".split("").map((k) => read(key(k)));
    expect(intents.every((i) => i === null)).toBe(true); // only g, j, k, r and symbols do anything
    expect(SHORTCUTS.some((s) => /approve|deny/i.test(s.label) && !/no shortcut/i.test(s.label))).toBe(false);
  });
});

describe("palette matching", () => {
  it("matches every word, any order, ignoring case", () => {
    expect(matches("INC 90210 · Suspicious PowerShell", "powershell 902")).toBe(true);
    expect(matches("#triage", "TRI")).toBe(true);
    expect(matches("#triage", "intel")).toBe(false);
  });
});
