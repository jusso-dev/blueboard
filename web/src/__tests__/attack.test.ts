import { describe, expect, it } from "vitest";
import { targetsFromEntities } from "../lib/actions";
import { filterTimeline, layoutGraph, refLink, targetsForNode, type GraphNode, type TimelineEvent } from "../lib/attack";

const ev = (over: Partial<TimelineEvent>): TimelineEvent => ({
  id: Math.random().toString(36).slice(2), ts: "2026-11-20T09:00:00Z", kind: "alert", lane: "attack", action: "x", entities: [], source: "Defender",
  refs: [], reported_by: [], reported: false, in_evidence: null, thread_id: null, ...over,
});

const node = (over: Partial<GraphNode>): GraphNode => ({
  id: "n", kind: "device", label: "n", keys: [], alert_ids: [], in_evidence: true, verdict: null, compromised: false, protected: false,
  protected_as: null, pending_actions: [], executed_actions: [], ...over,
});

describe("filterTimeline", () => {
  const events = [
    ev({ kind: "alert", entities: ["ws-0142.contoso.com", "7c3f"], action: "Activity began" }),
    ev({ kind: "action", entities: ["7c3f"], action: "Isolate" }),
    ev({ kind: "ioc", entities: ["203.0.113.77"], action: "reported", source: "board" }),
  ];
  it("filters to a graph node by any of its keys", () => {
    expect(filterTimeline(events, { keys: ["7C3F", "ws-0142"] }).map((e) => e.kind)).toEqual(["alert", "action"]);
  });
  it("filters by source kind and free text", () => {
    expect(filterTimeline(events, { kinds: new Set(["ioc"]) })).toHaveLength(1);
    expect(filterTimeline(events, { text: "isolate" }).map((e) => e.kind)).toEqual(["action"]);
    expect(filterTimeline(events, { text: "203.0.113" })).toHaveLength(1);
  });
});

describe("refLink", () => {
  it("opens message threads in place and actions in Approvals", () => {
    expect(refLink({ type: "message", id: "m1", label: null }, "root")).toEqual({ thread: "root", label: "message" });
    expect(refLink({ type: "action", id: "a1", label: "Isolate" }, null)).toEqual({ to: "/approvals#action-a1", label: "Isolate" });
    expect(refLink({ type: "ref", id: "x", label: null }, null)).toBeNull();
  });
});

describe("targetsForNode", () => {
  const targets = targetsFromEntities(
    { devices: [{ mde_device_id: "7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e", name: "ws-0142.contoso.com" }], users: [{ upn: "sam@contoso.com", aad_user_id: null, name: null }], ips: ["203.0.113.77"], urls: [], domains: [], files: [], emails: [], mitre: [] },
    "1002",
  );
  it("reuses the incident's pre-filled targets for a node", () => {
    const t = targetsForNode(node({ kind: "device", keys: ["7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e", "ws-0142.contoso.com"] }), targets);
    expect(t).toHaveLength(1);
    expect(t[0]!.params).toEqual({ machine_id: "7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e" });
  });
  it("builds an indicator target for an IOC-only node and none for a process", () => {
    expect(targetsForNode(node({ kind: "domain", keys: ["evil.example"] }), targets)[0]!.type).toBe("indicator");
    expect(targetsForNode(node({ kind: "file", keys: ["a".repeat(64)] }), targets)[0]!.params).toMatchObject({ indicator_type: "sha256" });
    expect(targetsForNode(node({ kind: "process", keys: ["proc:x"] }), targets)).toEqual([]);
  });
});

describe("layoutGraph", () => {
  it("is deterministic, places kinds in columns and keeps every node", () => {
    const nodes = [node({ id: "u", kind: "user", label: "u" }), node({ id: "d", kind: "device", label: "d" }), node({ id: "i", kind: "ip", label: "i" }), node({ id: "i2", kind: "ip", label: "i2" })];
    const edges = [{ from: "u", to: "d", relation: "logged on to", alert_ids: [], inferred: false }, { from: "d", to: "i2", relation: "connected to", alert_ids: [], inferred: true }];
    const a = layoutGraph({ nodes, edges });
    const b = layoutGraph({ nodes: [...nodes].reverse(), edges });
    const xy = (l: typeof a) => Object.fromEntries(l.nodes.map((n) => [n.id, [n.x, n.y]]));
    expect(xy(a)).toEqual(xy(b));
    expect(a.nodes).toHaveLength(4);
    const x = Object.fromEntries(a.nodes.map((n) => [n.id, n.x]));
    expect(x.u! < x.d! && x.d! < x.i!).toBe(true);
    expect(x.i).toBe(x.i2);
  });
});
