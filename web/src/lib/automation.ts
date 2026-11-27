/** Types and pure helpers for conditional automation (GET /policy/automation). Unit-tested. */

export type AutoRule = {
  min_confidence: number;
  severities: string[] | null;
  sources: string[] | null;
  max_per_hour: number;
  max_per_incident: number;
  requesters: string[] | null;
  revert_after_minutes: number | null;
  require_human_verdict: boolean;
};

export type KindSetting = { mode: string; confirm_target: boolean; rule: AutoRule | null };

export type KindView = {
  kind: string;
  title: string;
  destructive: boolean;
  reversible: boolean;
  reverse_kind: string | null;
  ceiling_allows_rule: boolean;
  file: KindSetting;
  override: KindSetting | null;
  override_version: number | null;
  effective: KindSetting;
  rule_id: string | null;
  mode: string;
};

export type TriggerMatch = { severities: string[]; sources: string[]; titles: string[]; categories: string[]; techniques: string[] };
export type PlaybookTrigger = { id: string; source: "file" | "custom"; playbook_id: string; priority: number; match: TriggerMatch; enabled: boolean; version: number | null; edited: boolean };

export type PolicyChange = {
  id: string;
  target: string;
  before: unknown;
  after: unknown;
  loosening: boolean;
  reason: string;
  status: "pending" | "applied" | "denied" | "expired" | "superseded";
  requested_by: string;
  requested_at: string;
  expires_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
};

export type Ceiling = {
  conditional_auto_allowed: string[];
  irreversible_auto_allowed: string[];
  min_confidence_floor: number;
  max_per_hour: number;
  max_per_incident: number;
  max_revert_after_minutes: number;
  change_expiry_hours: number;
};

export type AutomationPause = { paused: boolean; by: string | null; at: string | null; reason: string | null };

export type AutomationView = {
  ceiling: Ceiling;
  pause: AutomationPause;
  kinds: KindView[];
  triggers: PlaybookTrigger[];
  pending: PolicyChange[];
  history: PolicyChange[];
  can_edit: boolean;
};

/** Modes from loosest to strictest, as the server orders them. */
export const MODE_ORDER = ["auto", "on_instruction", "approval", "two_approvers", "disabled"] as const;
export const SEVERITIES = ["informational", "low", "medium", "high"] as const;

/** Modes an admin may pick for a kind: never looser than the file, never auto for destructive kinds. */
export function allowedModes(k: KindView): string[] {
  const floor = MODE_ORDER.indexOf(k.file.mode as (typeof MODE_ORDER)[number]);
  return MODE_ORDER.filter((m, i) => i >= floor && !(m === "auto" && k.destructive));
}

/** A rule with the ceiling's safe defaults, for the conditions form. */
export function defaultRule(k: KindView, c: Ceiling): AutoRule {
  return {
    min_confidence: Math.max(0.9, c.min_confidence_floor),
    severities: ["high"],
    sources: null,
    max_per_hour: Math.min(3, c.max_per_hour),
    max_per_incident: 1,
    requesters: null,
    revert_after_minutes: k.reversible ? Math.min(60, c.max_revert_after_minutes) : null,
    require_human_verdict: false,
  };
}

/** Client-side mirror of the ceiling check, so the form can say what's wrong before the server does. */
export function ruleProblems(k: KindView, r: AutoRule, c: Ceiling): string[] {
  const out: string[] = [];
  if (!k.ceiling_allows_rule) out.push(`policy.json does not allow a rule for ${k.kind}`);
  if (r.min_confidence < c.min_confidence_floor || r.min_confidence > 1) out.push(`confidence must be ${c.min_confidence_floor}–1`);
  if (!r.severities?.length) out.push("pick at least one severity");
  if (r.max_per_hour < 1 || r.max_per_hour > c.max_per_hour) out.push(`max per hour must be 1–${c.max_per_hour}`);
  if (r.max_per_incident < 1 || r.max_per_incident > c.max_per_incident) out.push(`max per incident must be 1–${c.max_per_incident}`);
  if (k.reversible && (r.revert_after_minutes == null || r.revert_after_minutes < 5 || r.revert_after_minutes > c.max_revert_after_minutes))
    out.push(`revert after must be 5–${c.max_revert_after_minutes} minutes`);
  if (!k.reversible && r.revert_after_minutes != null) out.push(`${k.kind} can't be reverted automatically`);
  return out;
}

/** "a, b , c" → ["a","b","c"]; empty → null. */
export function splitList(s: string): string[] | null {
  const xs = s.split(",").map((x) => x.trim()).filter(Boolean);
  return xs.length ? xs : null;
}

/** Short words for a change target ("kind:isolate_device" → "isolate_device"). */
export function targetLabel(target: string): string {
  const [type, key] = [target.slice(0, target.indexOf(":")), target.slice(target.indexOf(":") + 1)];
  return type === "kind" ? key : type === "trigger" ? `trigger ${key}` : "resume automation";
}

/** Human-readable label for an action's revert state. */
export function revertWords(state: string | null | undefined, at: string | null | undefined): string | null {
  switch (state) {
    case "scheduled":
      return at ? `auto-revert at ${new Date(at).toLocaleString()}` : "auto-revert scheduled";
    case "kept":
      return "kept (no automatic revert)";
    case "reverting":
      return "reverting";
    case "reverted":
      return "reverted";
    case "failed":
      return "revert failed: still in place";
    default:
      return null;
  }
}
