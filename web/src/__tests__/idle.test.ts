import { describe, expect, it } from "vitest";
import { idleState, lastActivity, recordActivity, WARN_MS } from "../lib/idle";

describe("idleState", () => {
  const t0 = 1_000_000;
  it("is always active when the limit is off", () => {
    expect(idleState(t0 + 10 * 3600_000, t0, 0).phase).toBe("active");
  });
  it("warns in the final minute and expires at the limit", () => {
    expect(idleState(t0 + 13 * 60_000, t0, 15).phase).toBe("active");
    expect(idleState(t0 + 15 * 60_000 - WARN_MS + 1, t0, 15).phase).toBe("warning");
    expect(idleState(t0 + 15 * 60_000, t0, 15)).toEqual({ phase: "expired", remainingMs: 0 });
  });
});

describe("lastActivity", () => {
  it("uses another tab's newer activity", () => {
    expect(lastActivity({ getItem: () => "2000" }, 1000)).toBe(2000);
  });
  it("ignores older or garbage values", () => {
    expect(lastActivity({ getItem: () => "500" }, 1000)).toBe(1000);
    expect(lastActivity({ getItem: () => "nope" }, 1000)).toBe(1000);
    expect(lastActivity(null, 1000)).toBe(1000);
  });
  it("keeps local expiry working when storage rejects access", () => {
    const denied = () => { throw new Error("storage denied"); };
    expect(lastActivity({ getItem: denied }, 1000)).toBe(1000);
    expect(() => recordActivity({ setItem: denied }, 1000)).not.toThrow();
    expect(idleState(901_000, lastActivity({ getItem: denied }, 1000), 15).phase).toBe("expired");
  });
});
