import { describe, expect, it } from "vitest";
import { ACTIONS } from "../src/lib/actions/catalog";
import { evaluate, PolicySchema } from "../src/lib/actions/policy";
import { extractEntities } from "../src/lib/graph/entities";

const DEVICE = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";
const incident = {
  graph_id: "42",
  data: {
    alerts: [
      {
        mitreTechniques: ["T1003.001"],
        evidence: [
          { "@odata.type": "#microsoft.graph.security.deviceEvidence", mdeDeviceId: DEVICE, deviceDnsName: "fin-lt-1.contoso.local" },
          { "@odata.type": "#microsoft.graph.security.userEvidence", userAccount: { userPrincipalName: "J.Doe@contoso.com", azureAdUserId: "u-1" } },
          { "@odata.type": "#microsoft.graph.security.ipEvidence", ipAddress: "203.0.113.45" },
          { "@odata.type": "#microsoft.graph.security.urlEvidence", url: "https://evil.example.net/a.ps1" },
        ],
      },
    ],
  },
};
const policy = (p = {}) => PolicySchema.parse(p);

describe("entity extraction", () => {
  it("normalises evidence and derives domains", () => {
    const e = extractEntities(incident.data as never);
    expect(e.devices[0]?.mdeDeviceId).toBe(DEVICE);
    expect(e.users[0]?.upn).toBe("J.Doe@contoso.com");
    expect(e.domains).toEqual(["evil.example.net"]);
    expect(e.mitre).toEqual(["T1003.001"]);
  });
});

describe("action policy", () => {
  it("destructive actions always need approval", () => {
    const d = evaluate(ACTIONS.isolate_device as never, { machine_id: DEVICE, isolation_type: "Full" }, incident, policy());
    expect(d.outcome).toBe("needs_approval");
    expect(d.notes).toEqual([]);
  });

  it("auto-approves listed non-destructive actions when targets are in scope", () => {
    const d = evaluate(ACTIONS.run_av_scan as never, { machine_id: DEVICE, scan_type: "Quick" }, incident, policy());
    expect(d.outcome).toBe("auto");
  });

  it("does not auto-approve when the target is outside the incident", () => {
    const other = "0".repeat(40);
    const d = evaluate(ACTIONS.run_av_scan as never, { machine_id: other, scan_type: "Quick" }, incident, policy());
    expect(d.outcome).toBe("needs_approval");
    expect(d.notes[0]).toMatch(/not in incident 42 evidence/);
  });

  it("does not auto-approve when there is no linked incident", () => {
    const d = evaluate(ACTIONS.run_av_scan as never, { machine_id: DEVICE, scan_type: "Quick" }, null, policy());
    expect(d.outcome).toBe("needs_approval");
  });

  it("rejects protected users case-insensitively", () => {
    const d = evaluate(ACTIONS.disable_user as never, { user: "j.doe@contoso.com" }, incident, policy({ protected_users: ["J.DOE@contoso.com"] }));
    expect(d.outcome).toBe("reject");
  });

  it("rejects protected devices", () => {
    const d = evaluate(ACTIONS.isolate_device as never, { machine_id: DEVICE, isolation_type: "Full" }, incident, policy({ protected_devices: [DEVICE] }));
    expect(d.outcome).toBe("reject");
  });

  it("rejects blocking protected domains and their subdomains", () => {
    const p = policy({ protected_indicators: ["contoso.com"] });
    const block = (value: string, indicator_type = "domain") =>
      evaluate(ACTIONS.block_indicator as never, { indicator_type, value, title: "t", severity: "High", expires_in_days: 30 }, incident, p).outcome;
    expect(block("contoso.com")).toBe("reject");
    expect(block("login.contoso.com")).toBe("reject");
    expect(block("https://contoso.com/x", "url")).toBe("reject");
    expect(block("evil.example.net")).toBe("needs_approval");
  });

  it("rejects disabled kinds", () => {
    const d = evaluate(ACTIONS.reset_password as never, { user: "u-1" }, incident, policy({ disabled: ["reset_password"] }));
    expect(d.outcome).toBe("reject");
  });

  it("rejects incident updates aimed at a different incident", () => {
    const d = evaluate(ACTIONS.update_incident as never, { incident_id: "999", status: "resolved" }, incident, policy());
    expect(d.outcome).toBe("reject");
  });
});

describe("action schemas", () => {
  it("validate MDE machine ids", () => {
    expect(ACTIONS.isolate_device.schema.safeParse({ machine_id: "not-an-id" }).success).toBe(false);
    expect(ACTIONS.isolate_device.schema.safeParse({ machine_id: DEVICE }).success).toBe(true);
  });
  it("update_incident requires a change", () => {
    expect(ACTIONS.update_incident.schema.safeParse({ incident_id: "1" }).success).toBe(false);
  });
});
