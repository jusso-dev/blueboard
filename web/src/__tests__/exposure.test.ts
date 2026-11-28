import { describe, expect, it } from "vitest";
import { remediationTargets, scoreBand, type ExposureItem } from "../lib/exposure";
import { actionsFor } from "../lib/actions";
import type { CatalogEntry } from "../lib/api";

const MDE = "7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e";
const item: ExposureItem = {
  id: "CVE-2024-3400", title: "CVE-2024-3400 in globalprotect", cve_id: "CVE-2024-3400", severity: "Critical", cvss: 10, exploit_available: true,
  known_exploited: true, devices: 3, internet_facing_devices: 1, critical_devices: 2, in_open_incidents: 1, score: 91.5, reasons: ["CVSS 10.0"],
  remediation: "Update GlobalProtect",
  top_devices: [
    { mde_device_id: MDE, name: "ws-0142.contoso.com", aad_device_id: null, internet_facing: false, asset_value: "High", in_open_incident: true },
    { mde_device_id: null, name: "unmanaged-printer", aad_device_id: null, internet_facing: false, asset_value: null, in_open_incident: false },
    { mde_device_id: "not-an-mde-id", name: "odd", aad_device_id: null, internet_facing: false, asset_value: null, in_open_incident: false },
  ],
};

describe("exposure remediation", () => {
  it("targets only devices with an MDE id, by name", () => {
    expect(remediationTargets(item)).toEqual([{ type: "device", label: "ws-0142.contoso.com", params: { machine_id: MDE } }]);
  });

  it("offers the Intune kinds for those device targets and hides disabled ones", () => {
    const entry = (kind: string, mode: CatalogEntry["mode"]): CatalogEntry =>
      ({ kind, title: kind, stage: "eradicate", destructive: false, target: "device", mode, params: { type: "object", properties: {} } });
    const catalog = [entry("intune_expedite_quality_update", "approval"), entry("intune_sync_device", "auto"), entry("intune_update_defender_signatures", "disabled"),
      { ...entry("create_detection_rule", "approval"), target: "detection" as const }];
    expect(actionsFor(catalog, "device").map((c) => c.kind)).toEqual(["intune_expedite_quality_update", "intune_sync_device"]);
  });

  it("bands scores in words", () => {
    expect([scoreBand(91), scoreBand(55), scoreBand(30), scoreBand(5)]).toEqual(["critical", "high", "medium", "low"]);
  });
});
