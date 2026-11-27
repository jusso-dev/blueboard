import type { CatalogEntry, JsonSchema, TargetType } from "./api";

/** Entities as the incident API returns them (`Entities.Extract`, snake_case). */
export type IncidentEntities = {
  devices: { mde_device_id: string | null; name: string | null }[];
  users: { upn: string | null; aad_user_id: string | null; name: string | null }[];
  ips: string[];
  urls: string[];
  domains: string[];
  files: { sha256: string | null; sha1: string | null; name: string | null }[];
  emails: { network_message_id: string | null; recipient: string | null; sender: string | null; subject: string | null }[];
  mitre: string[];
  cloud_apps?: { app_id: string | null; object_id: string | null; display_name: string | null; kind?: string | null }[];
  data_assets?: { kind: string; name: string | null; url_or_path: string | null; sensitivity_label?: string | null }[];
  purview_signals?: { source: string; title: string | null; severity: string | null; policy_or_label?: string | null }[];
};

/** Something on the incident an action can be aimed at. `params` pre-fills the action form. */
export type ActionTarget = {
  type: TargetType;
  label: string;
  params: Record<string, unknown>;
};

/** Every target the evidence offers, in the order an analyst would scan them. Pure: unit-tested. */
export function targetsFromEntities(e: IncidentEntities, incidentGraphId: string): ActionTarget[] {
  const out: ActionTarget[] = [];
  for (const d of e.devices) {
    // Device actions need the MDE id; a device with only a name can't be targeted.
    if (d.mde_device_id) out.push({ type: "device", label: d.name ?? d.mde_device_id, params: { machine_id: d.mde_device_id } });
  }
  for (const u of e.users) {
    const user = u.upn ?? u.aad_user_id;
    if (user) {
      const params: Record<string, unknown> = { user };
      if (u.aad_user_id) params.user_id = u.aad_user_id;
      out.push({ type: "user", label: u.upn ?? u.name ?? user, params });
    }
  }
  for (const app of e.cloud_apps ?? []) {
    if (app.object_id) {
      out.push({ type: "app", label: app.display_name ?? app.object_id, params: { service_principal_id: app.object_id } });
    }
  }
  const indicator = (indicator_type: string, value: string) =>
    out.push({ type: "indicator", label: value, params: { indicator_type, value, title: `blueboard: ${value}`.slice(0, 200) } });
  e.ips.forEach((ip) => indicator("ip", ip));
  e.domains.forEach((d) => indicator("domain", d));
  e.urls.forEach((u) => indicator("url", u));
  for (const f of e.files) {
    if (f.sha256) indicator("sha256", f.sha256);
    else if (f.sha1) indicator("sha1", f.sha1);
  }
  const mails = e.emails.filter((m) => m.network_message_id && m.recipient);
  const [first] = mails;
  if (first) {
    out.push({
      type: "email",
      label: mails.length === 1 ? `${first.subject ?? "message"} to ${first.recipient}` : `${mails.length} messages`,
      params: { messages: mails.map((m) => ({ network_message_id: m.network_message_id, recipient: m.recipient })) },
    });
  }
  out.push({ type: "incident", label: `INC ${incidentGraphId}`, params: { incident_id: incidentGraphId } });
  return out;
}

/** The target for an IOC row or entity value posted on the board (kind from the ioc payload). */
export function targetFromIoc(kind: string, value: string): ActionTarget | null {
  switch (kind) {
    case "device":
      return /^[0-9a-f]{40}$/i.test(value) ? { type: "device", label: value, params: { machine_id: value } } : null;
    case "user":
    case "email":
      return { type: "user", label: value, params: { user: value } };
    case "ip":
    case "domain":
    case "url":
    case "sha1":
    case "sha256":
    case "md5":
      return { type: "indicator", label: value, params: { indicator_type: kind, value, title: `blueboard: ${value}`.slice(0, 200) } };
    default:
      return null;
  }
}

/** Kinds the picker offers for a target: matching target type, and not switched off by policy. */
export function actionsFor(catalog: CatalogEntry[], type: TargetType): CatalogEntry[] {
  return catalog.filter((a) => a.target === type && a.mode !== "disabled");
}

/** Form defaults for a kind: schema defaults, then the target's pre-filled values. Only keys the schema knows. */
export function initialParams(schema: JsonSchema, prefill: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, p] of Object.entries(schema.properties ?? {})) {
    if (k in prefill) out[k] = prefill[k];
    else if (p.default !== undefined) out[k] = p.default;
  }
  return out;
}

export const MIN_JUSTIFICATION = 20;

/** Plain-words label for a policy mode, as on the /policy page. */
export const MODE_WORDS: Record<string, string> = {
  auto: "Runs on its own",
  approval: "Needs approval",
  on_instruction: "Runs when an approver asks",
  two_approvers: "Needs two approvers",
  disabled: "Off",
  conditional: "Runs on its own when its rule holds",
};

export function actionTitle(kind: string) {
  return kind.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
}
