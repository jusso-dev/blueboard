import { describe, expect, it } from "vitest";
import { parseMentions } from "../src/lib/board";

describe("parseMentions", () => {
  it("finds handles and ignores emails", () => {
    expect(parseMentions("hey @enrichment-agent and @analyst, mail j.doe@contoso.com")).toEqual(["enrichment-agent", "analyst"]);
  });
  it("dedupes", () => {
    expect(parseMentions("@a1 @a1")).toEqual(["a1"]);
  });
});
