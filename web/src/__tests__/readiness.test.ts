import { describe, expect, it } from "vitest";
import { stageStates, type SetupCheck } from "../lib/readiness";

const ok = (id: string): SetupCheck => ({ id, name: id, status: "ok" });
const warn = (id: string): SetupCheck => ({ id, name: id, status: "warning" });

describe("stageStates", () => {
  it("a fresh read-only deploy is at Connected", () => {
    const s = stageStates([ok("database"), ok("auth"), ok("reads"), warn("ingest"), warn("agents"), warn("broker")]);
    expect(s.map((x) => x.state)).toEqual(["done", "current", "todo", "todo"]);
    expect(s[1]?.blocking.map((c) => c.id)).toEqual(["ingest", "agents"]);
  });

  it("skips checks the report doesn't run (audit export outside production)", () => {
    const s = stageStates(["database", "auth", "reads", "ingest", "agents", "policy", "access", "notify"].map(ok).concat(warn("broker"), ok("writes")));
    expect(s.map((x) => x.state)).toEqual(["done", "done", "done", "current"]);
    expect(s[3]?.blocking.map((c) => c.id)).toEqual(["broker"]);
  });

  it("later stages stay to do after the first blocked one, even when their checks pass", () => {
    const s = stageStates([warn("database"), ok("auth"), ok("reads"), ok("ingest"), ok("agents")]);
    expect(s.map((x) => x.state)).toEqual(["current", "todo", "todo", "todo"]);
  });

  it("everything OK is all done", () => {
    const all = ["database", "auth", "reads", "ingest", "agents", "policy", "access", "notify", "audit_export", "writes", "broker"].map(ok);
    expect(stageStates(all).every((x) => x.state === "done")).toBe(true);
  });
});
