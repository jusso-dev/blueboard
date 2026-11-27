import { describe, expect, it } from "vitest";
import { argLine, burn, burnTone, pct, reasoningOf, riskTone, stackDaily, tokens, usd } from "../lib/agents";

const row = {
  day_usd: 0,
  month_usd: 0,
  day_tokens: 0,
  month_tokens: 0,
  daily_usd: null as number | null,
  monthly_usd: null as number | null,
  daily_tokens: null as number | null,
  monthly_tokens: null as number | null,
  topup_usd: 0,
  topup_tokens: 0,
};

describe("budget burn", () => {
  it("is null without limits and uses the tightest limit with top-ups", () => {
    expect(burn(row)).toBeNull();
    expect(burn({ ...row, day_usd: 5, daily_usd: 10, month_usd: 90, monthly_usd: 100 })).toBeCloseTo(0.9);
    expect(burn({ ...row, day_usd: 10, daily_usd: 10, topup_usd: 10 })).toBeCloseTo(0.5);
    expect(burn({ ...row, day_tokens: 2_000, daily_tokens: 1_000 })).toBeCloseTo(2);
  });
  it("matches the server's tones: soft alert, then hard cap", () => {
    expect(burnTone(null, 80)).toBe("neutral");
    expect(burnTone(0.5, 80)).toBe("good");
    expect(burnTone(0.8, 80)).toBe("warning");
    expect(burnTone(1, 80)).toBe("critical");
  });
});

describe("formatting", () => {
  it("money, tokens and percentages", () => {
    expect(usd(null)).toBe("—");
    expect(usd(0)).toBe("$0");
    expect(usd(0.004)).toBe("<$0.01");
    expect(usd(12.345)).toBe("$12.35");
    expect(tokens(1_500)).toBe("1.5k");
    expect(tokens(2_500_000)).toBe("2.5M");
    expect(pct(0.256)).toBe("26%");
    expect(pct(null)).toBe("—");
  });
  it("risk tones", () => {
    expect([riskTone(10), riskTone(40), riskTone(70)]).toEqual(["good", "warning", "critical"]);
  });
});

describe("stackDaily", () => {
  it("pivots by day, orders agents by total and finds the tallest day", () => {
    const s = stackDaily([
      { handle: "a", day: "2026-11-02", llm_usd: 1, metered_usd: 0, tokens: 0, calls: 0 },
      { handle: "b", day: "2026-11-01", llm_usd: 3, metered_usd: 1, tokens: 0, calls: 0 },
      { handle: "a", day: "2026-11-01", llm_usd: 1, metered_usd: 0, tokens: 0, calls: 0 },
    ]);
    expect(s.days).toEqual(["2026-11-01", "2026-11-02"]);
    expect(s.agents).toEqual(["b", "a"]);
    expect(s.max).toBe(5);
    expect(s.values["2026-11-01"]).toEqual({ b: 4, a: 1 });
  });
});

describe("trace and reasoning", () => {
  it("summarises arguments without the KQL (shown on its own) and caps length", () => {
    expect(argLine({ channel: "triage", query: "DeviceEvents", _truncated: true })).toBe("channel=triage");
    expect(argLine({ body: "x".repeat(500) }).length).toBeLessThanOrEqual(121);
    expect(argLine(null)).toBe("");
  });
  it("reads an optional reasoning string from a payload", () => {
    expect(reasoningOf({ reasoning: "  checked sign-ins first  " })).toBe("checked sign-ins first");
    expect(reasoningOf({ reasoning: 5 })).toBeNull();
    expect(reasoningOf(null)).toBeNull();
  });
});
