/** Okta, ServiceNow and Jira as the API returns them (GET /api/manage/connectors, GET /api/incidents/{id}/connectors). */
export type ConnectorView = {
  connector: "okta" | "servicenow" | "jira";
  configured: boolean;
  host: string | null;
  auth: string | null;
  inbound_enabled: boolean | null;
  last_ok_at: string | null;
  last_error_at: string | null;
  last_error: string | null;
  last_sync_at: string | null;
  links: number;
  health: "off" | "ok" | "failing" | "unknown";
};
export type ConnectorsView = {
  connectors: ConnectorView[];
  tickets: { min_severity: string; on_playbook: boolean; on_action_approved: boolean; sync_events: string[] };
  reverse_kinds: Record<string, string>;
};
export type OktaChip = {
  upn: string;
  okta_user_id: string;
  status: string | null;
  last_login: string | null;
  factors: number;
  groups: number;
  admin_roles: string[] | null;
  refreshed_at: string;
};
export type TicketChip = { system: "servicenow" | "jira"; key: string; url: string | null; reason: string; created_at: string; last_synced_at: string | null; last_error: string | null };
export type IncidentConnectors = { okta_enabled: boolean; ticket_systems: string[]; okta: OktaChip[]; tickets: TicketChip[] };

export const CONNECTOR_NAME: Record<string, string> = { okta: "Okta", servicenow: "ServiceNow", jira: "Jira" };

export type Tone = "good" | "warning" | "critical" | "neutral";

/** Health in words and tone; never colour alone. */
export function healthTag(c: Pick<ConnectorView, "health" | "configured">): { word: string; tone: Tone } {
  if (!c.configured || c.health === "off") return { word: "Off", tone: "neutral" };
  if (c.health === "failing") return { word: "Failing", tone: "critical" };
  if (c.health === "unknown") return { word: "Not used yet", tone: "warning" };
  return { word: "Healthy", tone: "good" };
}

/** Admin centre tile: one summary across the three connectors. */
export function connectorsSummary(cs: ConnectorView[] | undefined): { status: string; tone: Tone } | undefined {
  if (!cs) return undefined;
  const on = cs.filter((c) => c.configured);
  if (on.length === 0) return { status: "None configured", tone: "neutral" };
  const failing = on.filter((c) => c.health === "failing").length;
  if (failing) return { status: `${failing} failing`, tone: "critical" };
  return { status: `${on.length} configured`, tone: "good" };
}

/** Okta statuses that mean the account can't sign in (or is part-way through being blocked), shown as a warning. */
export function oktaStatusTone(status: string | null): Tone {
  switch ((status ?? "").toUpperCase()) {
    case "ACTIVE":
      return "good";
    case "SUSPENDED":
    case "LOCKED_OUT":
    case "DEPROVISIONED":
      return "critical";
    case "":
      return "neutral";
    default:
      return "warning";
  }
}
