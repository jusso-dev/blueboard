import { describe, expect, it } from "vitest";
import { reviewFlags } from "../pages/Participants";
import { queryOf } from "../pages/AuditLog";
import { areaScores } from "../pages/Posture";

describe("reviewFlags", () => {
  const now = Date.parse("2026-11-26T00:00:00Z");
  it("flags inactivity, never signed in and privilege", () => {
    expect(reviewFlags({ kind: "human", roles: ["poster", "admin"], last_seen_at: "2026-09-01T00:00:00Z", enabled: true }, now)).toEqual(["inactive 86 days", "privileged: admin"]);
    expect(reviewFlags({ kind: "agent", roles: ["poster", "requester"], last_seen_at: null, enabled: true }, now)).toEqual(["never signed in", "can request actions"]);
  });
  it("has nothing to say about disabled principals or quiet posters", () => {
    expect(reviewFlags({ kind: "human", roles: ["admin"], last_seen_at: null, enabled: false }, now)).toEqual([]);
    expect(reviewFlags({ kind: "human", roles: ["poster"], last_seen_at: "2026-11-25T00:00:00Z", enabled: true }, now)).toEqual([]);
  });
});

describe("areaScores", () => {
  it("scores met fully, partial at half, skips external", () => {
    const c = (area: string, state: string, weight: number) => ({ id: area + state, area, title: "", state: state as "met", weight, detail: "", fix: null, owner: null, threat: null });
    expect(areaScores([c("Identity", "met", 10), c("Identity", "partial", 5), c("Identity", "external", 10), c("Data", "not_met", 5)])).toEqual([
      { area: "Identity", earned: 12, max: 15 },
      { area: "Data", earned: 0, max: 5 },
    ]);
  });
});


describe("audit query dates", () => {
  it("passes malformed shared-link dates to API validation without crashing", () => {
    expect(new URLSearchParams(queryOf(new URLSearchParams("from=invalid"))).get("from")).toBe("invalid");
  });
  it("keeps valid timestamps precise", () => {
    expect(new URLSearchParams(queryOf(new URLSearchParams("from=2026-11-26T00:00:00Z"))).get("from")).toBe("2026-11-26T00:00:00.000Z");
  });
});
