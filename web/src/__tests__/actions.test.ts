import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { actionsFor, initialParams, targetFromIoc, targetsFromEntities, type IncidentEntities } from "../lib/actions";
import { ActionStatusTag, SchemaFields } from "../components/request-action";
import type { CatalogEntry } from "../lib/api";

const DEVICE = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";

// The shape GET /api/incidents/{id} returns for the sample incident (Entities.Extract, snake_case).
const entities: IncidentEntities = {
  devices: [
    { mde_device_id: DEVICE, name: "ws-042.contoso.com" },
    { mde_device_id: null, name: "printer-7" },
  ],
  users: [{ upn: "ana@contoso.com", aad_user_id: "11111111-1111-1111-1111-111111111111", name: "ana" }],
  ips: ["203.0.113.50"],
  urls: ["https://bad.example/payload.ps1"],
  domains: ["bad.example"],
  files: [{ sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", sha1: null, name: "update.exe" }],
  emails: [{ network_message_id: "abcdefgh12", recipient: "ana@contoso.com", sender: "x@evil.example", subject: "Invoice" }],
  mitre: ["T1059.001"],
};

const schema = (props: Record<string, object>, required: string[]) => ({ type: "object", properties: props, required });
const catalog: CatalogEntry[] = [
  { kind: "isolate_device", title: "Isolate device", stage: "contain", destructive: true, target: "device", mode: "approval",
    params: schema({ machine_id: { type: "string" }, isolation_type: { type: "string", enum: ["Full", "Selective"], default: "Full" } }, ["machine_id"]) },
  { kind: "run_av_scan", title: "Run AV scan", stage: "eradicate", destructive: false, target: "device", mode: "auto", params: schema({ machine_id: { type: "string" } }, ["machine_id"]) },
  { kind: "release_device", title: "Release", stage: "recover", destructive: true, target: "device", mode: "disabled", params: schema({ machine_id: { type: "string" } }, ["machine_id"]) },
  { kind: "disable_user", title: "Disable user", stage: "contain", destructive: true, target: "user", mode: "two_approvers", params: schema({ user: { type: "string" } }, ["user"]) },
  { kind: "block_indicator", title: "Block indicator", stage: "contain", destructive: true, target: "indicator", mode: "approval",
    params: schema({ indicator_type: { type: "string", enum: ["ip", "domain"] }, value: { type: "string" }, title: { type: "string" }, expires_in_days: { type: "integer", default: 30 } }, ["indicator_type", "value", "title"]) },
];

describe("targetsFromEntities", () => {
  const targets = targetsFromEntities(entities, "90210");

  it("pre-fills device actions with the MDE id from the evidence", () => {
    const devices = targets.filter((t) => t.type === "device");
    expect(devices).toEqual([{ type: "device", label: "ws-042.contoso.com", params: { machine_id: DEVICE } }]);
  });

  it("uses the UPN for users", () => {
    expect(targets.find((t) => t.type === "user")).toEqual({ type: "user", label: "ana@contoso.com", params: { user: "ana@contoso.com" } });
  });

  it("offers IPs, domains, URLs and file hashes as indicators with the right type", () => {
    const ind = targets.filter((t) => t.type === "indicator").map((t) => [t.params.indicator_type, t.params.value]);
    expect(ind).toEqual([
      ["ip", "203.0.113.50"],
      ["domain", "bad.example"],
      ["url", "https://bad.example/payload.ps1"],
      ["sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
    ]);
  });

  it("groups emails into one purge target and ends with the incident itself", () => {
    expect(targets.find((t) => t.type === "email")?.params).toEqual({ messages: [{ network_message_id: "abcdefgh12", recipient: "ana@contoso.com" }] });
    expect(targets.at(-1)).toEqual({ type: "incident", label: "INC 90210", params: { incident_id: "90210" } });
  });
});

describe("targetFromIoc", () => {
  it("maps IOC kinds to action targets", () => {
    expect(targetFromIoc("sha256", "abc")?.params).toMatchObject({ indicator_type: "sha256", value: "abc" });
    expect(targetFromIoc("user", "ana@contoso.com")?.type).toBe("user");
    expect(targetFromIoc("device", DEVICE)?.params).toEqual({ machine_id: DEVICE });
    expect(targetFromIoc("device", "ws-042")).toBeNull();
  });
});

describe("action picker", () => {
  it("lists only kinds for the target type that policy hasn't disabled", () => {
    expect(actionsFor(catalog, "device").map((a) => a.kind)).toEqual(["isolate_device", "run_av_scan"]);
    expect(actionsFor(catalog, "user").map((a) => a.kind)).toEqual(["disable_user"]);
    expect(actionsFor(catalog, "email")).toEqual([]);
  });

  it("merges schema defaults with the evidence and drops unknown keys", () => {
    expect(initialParams(catalog[0]!.params, { machine_id: DEVICE, junk: 1 })).toEqual({ machine_id: DEVICE, isolation_type: "Full" });
    expect(initialParams(catalog[4]!.params, { indicator_type: "ip", value: "203.0.113.50", title: "t" })).toEqual({
      indicator_type: "ip", value: "203.0.113.50", title: "t", expires_in_days: 30,
    });
  });
});

describe("generated form", () => {
  const html = renderToStaticMarkup(
    createElement(SchemaFields, { schema: catalog[4]!.params, values: { indicator_type: "ip", value: "203.0.113.50" }, onChange: () => {}, idPrefix: "f" }),
  );

  it("labels every field and marks required ones", () => {
    for (const name of ["indicator_type", "value", "title", "expires_in_days"]) expect(html).toContain(`for="f-p-${name}"`);
    expect(html).toContain("expires in days (optional)");
    expect(html).toMatch(/id="f-p-value"[^>]*required/);
  });

  it("renders enums as selects and integers as number inputs", () => {
    expect(html).toMatch(/<select[^>]*id="f-p-indicator_type"/);
    expect(html).toMatch(/type="number"[^>]*id="f-p-expires_in_days"|id="f-p-expires_in_days"[^>]*type="number"/);
  });
});

describe("status tag", () => {
  it("writes 1 of 2 out in words", () => {
    expect(renderToStaticMarkup(createElement(ActionStatusTag, { status: "approved_once" }))).toContain("1 of 2 approved");
    expect(renderToStaticMarkup(createElement(ActionStatusTag, { status: "expired" }))).toContain("expired");
  });
});
