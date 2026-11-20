import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import type { QueueRow } from "../lib/api";
import { iocPayload } from "../lib/ioc";
import { chipsFrom, filterQueue, statusWords } from "../lib/queue";
import { QueueTable } from "../pages/Queue";

const row = (id: string, more: Partial<QueueRow> = {}): QueueRow => ({
  id,
  graph_id: id,
  display_name: `Incident ${id}`,
  severity: "medium",
  status: "active",
  web_url: null,
  alert_count: 1,
  verdict: null,
  verdict_confidence: null,
  verdict_by: null,
  open_asks: 0,
  human_asks: 0,
  pending_actions: 0,
  active_claims: [],
  last_activity_at: new Date().toISOString(),
  created_at: new Date().toISOString(),
  mine: false,
  needs_human: false,
  ...more,
});

// Server order: needs a human first. Filters must keep it.
const rows = [
  row("1", { pending_actions: 2, needs_human: true, severity: "low" }),
  row("2", { human_asks: 1, open_asks: 1, needs_human: true, mine: true }),
  row("3", { severity: "high", verdict: "truePositive", verdict_confidence: 0.9 }),
  row("4", { severity: "informational" }),
];

describe("queue filters", () => {
  it("reads known chips from the URL and ignores others", () => {
    expect(chipsFrom(new URLSearchParams("f=approval&f=mine&f=bogus"))).toEqual(["approval", "mine"]);
  });

  it("applies each chip and keeps server order", () => {
    const ids = (c: Parameters<typeof filterQueue>[1]) => filterQueue(rows, c).map((r) => r.id);
    expect(ids([])).toEqual(["1", "2", "3", "4"]);
    expect(ids(["approval"])).toEqual(["1"]);
    expect(ids(["unverdicted"])).toEqual(["1", "2", "4"]);
    expect(ids(["high"])).toEqual(["3"]);
    expect(ids(["mine"])).toEqual(["2"]);
    expect(ids(["unverdicted", "mine"])).toEqual(["2"]);
    expect(ids(["high", "approval"])).toEqual([]);
  });

  it("writes Defender status as words", () => {
    expect(statusWords("inProgress")).toBe("in progress");
    expect(statusWords("active")).toBe("active");
  });
});

describe("queue table", () => {
  const html = renderToStaticMarkup(createElement(MemoryRouter, null, createElement(QueueTable, { rows })));
  it("writes severity, status and approvals as words", () => {
    expect(html).toContain(">low<");
    expect(html).toContain(">info<");
    expect(html).toContain(">active<");
    expect(html).toContain("2 waiting");
    expect(html).toContain("true positive");
    expect(html).toContain("no verdict");
  });
  it("keeps severity, incident and approval visible on small screens", () => {
    const headers = [...html.matchAll(/<th scope="col" class="([^"]*)">([^<]*)</g)].map((m) => ({ cls: m[1]!, label: m[2]! }));
    for (const label of ["Severity", "Incident", "Approval"]) expect(headers.find((h) => h.label === label)?.cls).not.toMatch(/max-md:hidden|max-lg:hidden/);
  });
});

describe("ioc form", () => {
  it("builds a payload the API accepts", () => {
    expect(iocPayload({ kind: "domain", value: "  bad.example ", verdict: "malicious" })).toEqual({ indicators: [{ kind: "domain", value: "bad.example", verdict: "malicious" }] });
  });
  it("rejects an empty or oversized value", () => {
    expect(typeof iocPayload({ kind: "ip", value: " ", verdict: "unknown" })).toBe("string");
    expect(typeof iocPayload({ kind: "ip", value: "x".repeat(2049), verdict: "unknown" })).toBe("string");
  });
});
