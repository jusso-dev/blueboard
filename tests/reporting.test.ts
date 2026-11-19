import { describe, expect, it } from "vitest";
import { percentile, reportCsv, type Report } from "../src/lib/reporting";

describe("percentile", () => {
  it("matches percentile_cont (linear interpolation)", () => {
    expect(percentile([], 0.5)).toBeNull();
    expect(percentile([7], 0.9)).toBe(7);
    expect(percentile([1, 2, 3, 4], 0.5)).toBe(2.5);
    expect(percentile([10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 0.9)).toBeCloseTo(91);
    expect(percentile([3, 1, 2], 0.5)).toBe(2); // unsorted input
  });
});

describe("reportCsv", () => {
  const base: Report = {
    range: { from: "2026-11-01T00:00:00.000Z", to: "2026-11-19T00:00:00.000Z" },
    incidents: { total: 1, enriched: 1, with_verdict: 0, contained: 0 },
    enrichment: { median: 60, p90: 60, n: 1 },
    verdict: { median: null, p90: null, n: 0 },
    containment: { median: null, p90: null, n: 0 },
    approval: { median: null, p90: null, n: 0 },
    actions: [],
    rows: [
      {
        id: "x",
        graph_id: "42",
        display_name: '=HYPERLINK("http://evil","click"), "quoted"',
        severity: "high",
        status: "active",
        first_seen_at: "2026-11-18T10:00:00.000Z",
        enrichment_s: 61.4,
        verdict_s: null,
        containment_s: null,
        messages: 3,
        actions: 0,
      },
    ],
  };

  it("neutralises formula injection and escapes quotes", () => {
    const [head, row] = reportCsv(base).trim().split("\n");
    expect(head).toBe("incident,name,severity,status,first_seen_at,enrichment_s,verdict_s,containment_s,messages,actions");
    expect(row).toContain(`"'=HYPERLINK(""http://evil"",""click""), ""quoted"""`);
    expect(row).toContain(",61,,,3,0");
  });
});
