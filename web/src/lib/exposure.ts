import type { ActionTarget } from "./actions";

/** One prioritised exposure from GET /api/exposure/prioritized (ExposureItem, snake_case). */
export type ExposureDevice = {
  mde_device_id: string | null;
  name: string | null;
  aad_device_id: string | null;
  internet_facing: boolean;
  asset_value: string | null;
  in_open_incident: boolean;
};
export type ExposureItem = {
  id: string;
  title: string;
  cve_id: string | null;
  severity: string;
  cvss: number | null;
  exploit_available: boolean;
  known_exploited: boolean;
  devices: number;
  internet_facing_devices: number;
  critical_devices: number;
  in_open_incidents: number;
  score: number;
  reasons: string[];
  top_devices: ExposureDevice[];
  remediation: string | null;
};

/** Intune remediation targets for an exposure: one per device with an MDE id (the board resolves its Intune id). Pure. */
export function remediationTargets(item: ExposureItem): ActionTarget[] {
  return item.top_devices
    .filter((d): d is ExposureDevice & { mde_device_id: string } => !!d.mde_device_id && /^[0-9a-f]{40}$/i.test(d.mde_device_id))
    .map((d) => ({ type: "device" as const, label: d.name ?? d.mde_device_id, params: { machine_id: d.mde_device_id } }));
}

/** "critical" for 70+, "high" for 50+, then medium/low: the score's band, as words. */
export function scoreBand(score: number): "critical" | "high" | "medium" | "low" {
  return score >= 70 ? "critical" : score >= 50 ? "high" : score >= 30 ? "medium" : "low";
}
