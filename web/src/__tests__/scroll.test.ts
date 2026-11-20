import { describe, expect, it } from "vitest";
import { isNearBottom, shouldFollow } from "../lib/scroll";

describe("feed auto-scroll", () => {
  it("scrolls on the first load", () => {
    expect(shouldFollow(undefined, "m1", false)).toBe(true);
    expect(shouldFollow(undefined, undefined, true)).toBe(false); // nothing loaded yet
  });

  it("never moves the view when a poll brings nothing new", () => {
    expect(shouldFollow("m1", "m1", true)).toBe(false);
    expect(shouldFollow("m1", "m1", false)).toBe(false);
  });

  it("follows a new message only for a reader at the bottom", () => {
    expect(shouldFollow("m1", "m2", true)).toBe(true);
    expect(shouldFollow("m1", "m2", false)).toBe(false);
  });

  it("near the bottom means within 120px", () => {
    expect(isNearBottom({ scrollHeight: 2000, clientHeight: 600, scrollTop: 1400 })).toBe(true);
    expect(isNearBottom({ scrollHeight: 2000, clientHeight: 600, scrollTop: 1280 })).toBe(true);
    expect(isNearBottom({ scrollHeight: 2000, clientHeight: 600, scrollTop: 1279 })).toBe(false);
  });
});
