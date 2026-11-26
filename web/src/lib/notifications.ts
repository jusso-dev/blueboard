/**
 * Notification settings: board defaults, one person's overrides ("mine", a deep partial), and the effective result.
 * Pure helpers so the page and the tests share one idea of "inherited", "overridden" and "what to PUT".
 */

export type Severity = "informational" | "low" | "medium" | "high";
export type EventKey = "approvals" | "mention" | "question" | "reply" | "verdict" | "finding" | "incident" | "action_result";
export type SinkKey = "webhook" | "teams" | "mail" | "ntfy";
/** Delivery list order on the settings page. */
export const SINK_KEYS: SinkKey[] = ["webhook", "teams", "mail", "ntfy"];

export type NotificationSettings = {
  enabled: boolean;
  events: Record<EventKey, boolean>;
  verdict_classifications: string[];
  min_incident_severity: Severity;
  mentions_from_people: boolean;
  include_summary: boolean;
  quiet_hours: { enabled: boolean; start: string; end: string; time_zone: string; except_high_severity: boolean };
  sinks: Record<SinkKey, boolean>;
};

export type DeepPartial<T> = { [K in keyof T]?: T[K] extends unknown[] ? T[K] : T[K] extends object ? DeepPartial<T[K]> : T[K] };
/** A PUT body: like DeepPartial, but any key may be null ("reset to the board default"). */
export type Patch = { [key: string]: Patch | unknown[] | string | number | boolean | null };

export type SinkStatus = { sink: SinkKey; configured: boolean; ready: boolean; problem: string | null };
export type SettingsResponse = {
  defaults: NotificationSettings;
  mine: DeepPartial<NotificationSettings> | null;
  effective: NotificationSettings;
  sinks: SinkStatus[];
  can_edit_defaults: boolean;
};
export type TestResult = { sink: string; ok: boolean; detail: string };
export type Delivery = {
  event: string;
  sink: string;
  status: "sending" | "sent" | "failed";
  error: string | null;
  recipient: string | null;
  created_at: string;
  message_id: string | null;
  action_id: string | null;
};

/** Mirrors Payloads.Classifications in api/Blueboard.Api/Board/Payloads.cs (the verdict payload's allowed values). */
export const CLASSIFICATIONS: { value: string; label: string }[] = [
  { value: "truePositive", label: "True positive" },
  { value: "falsePositive", label: "False positive" },
  { value: "informationalExpectedActivity", label: "Expected activity" },
  { value: "unknown", label: "Undetermined" },
];

export const SEVERITIES: { value: Severity; label: string }[] = [
  { value: "informational", label: "Informational" },
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
];

export const EVENT_LABELS: Record<EventKey, string> = {
  approvals: "Approvals waiting for me",
  mention: "Someone mentions me",
  question: "An agent asks a question",
  reply: "Replies in threads I'm in",
  verdict: "An agent's verdict",
  finding: "Findings on incidents",
  incident: "New incidents",
  action_result: "Results of actions I asked for",
};

export const SINK_LABELS: Record<SinkKey, string> = { webhook: "Webhook", teams: "Microsoft Teams", mail: "Email", ntfy: "ntfy (phone push)" };

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** A dotted path such as "quiet_hours.start". */
export type Path = string;

export function getAt(obj: unknown, path: Path): unknown {
  let cur: unknown = obj;
  for (const k of path.split(".")) {
    if (!isObj(cur)) return undefined;
    cur = cur[k];
  }
  return cur;
}

/** True when the person has their own value for this field (null and absent both mean "use the board default"). */
export function isOverridden(mine: unknown, path: Path): boolean {
  const v = getAt(mine, path);
  return v !== undefined && v !== null;
}

/** Drop nulls and empty objects: the server may echo resets as nulls. */
export function normalizeMine<T>(mine: DeepPartial<T> | null | undefined): DeepPartial<T> {
  const walk = (o: Record<string, unknown>): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(o)) {
      if (v === null || v === undefined) continue;
      if (isObj(v)) {
        const inner = walk(v);
        if (Object.keys(inner).length) out[k] = inner;
      } else out[k] = v;
    }
    return out;
  };
  return (isObj(mine) ? walk(mine) : {}) as DeepPartial<T>;
}

/** Defaults with the person's overrides laid over them. Arrays are values, not merged element by element. */
export function mergeSettings<T>(defaults: T, mine: DeepPartial<T> | null | undefined): T {
  const merge = (base: unknown, over: unknown): unknown => {
    if (over === undefined || over === null) return base;
    if (isObj(base) && isObj(over)) {
      const out: Record<string, unknown> = { ...base };
      for (const [k, v] of Object.entries(over)) out[k] = merge(base[k], v);
      return out;
    }
    return over;
  };
  return merge(defaults, mine) as T;
}

/** Return a copy of `mine` with `path` set to `value` (creating parents). */
export function setOverride<T>(mine: DeepPartial<T> | null | undefined, path: Path, value: unknown): DeepPartial<T> {
  const keys = path.split(".");
  const set = (o: Record<string, unknown>, i: number): Record<string, unknown> => {
    const k = keys[i]!;
    if (i === keys.length - 1) return { ...o, [k]: value };
    return { ...o, [k]: set(isObj(o[k]) ? o[k] : {}, i + 1) };
  };
  return set(normalizeMine(mine) as Record<string, unknown>, 0) as DeepPartial<T>;
}

/** Return a copy of `mine` without `path`, pruning parents that become empty. */
export function clearOverride<T>(mine: DeepPartial<T> | null | undefined, path: Path): DeepPartial<T> {
  const keys = path.split(".");
  const drop = (o: Record<string, unknown>, i: number): Record<string, unknown> => {
    const k = keys[i]!;
    if (!(k in o)) return o;
    const { [k]: child, ...rest } = o;
    if (i === keys.length - 1) return rest;
    if (!isObj(child)) return o;
    const inner = drop(child, i + 1);
    return Object.keys(inner).length ? { ...rest, [k]: inner } : rest;
  };
  return drop(normalizeMine(mine) as Record<string, unknown>, 0) as DeepPartial<T>;
}

/**
 * The smallest PUT body that turns `base` into `next` under merge-patch rules: changed leaves carry their new value,
 * leaves present in `base` but gone from `next` become null (reset to the board default), unchanged leaves are left out.
 * Arrays are leaves. Empty result = nothing to send.
 */
export function diffPatch(base: unknown, next: unknown): Patch {
  const b = isObj(base) ? base : {};
  const n = isObj(next) ? next : {};
  const out: Patch = {};
  for (const k of new Set([...Object.keys(b), ...Object.keys(n)])) {
    const bv = b[k] ?? undefined;
    const nv = n[k] ?? undefined;
    if (isObj(bv) || isObj(nv)) {
      if (isObj(nv) && !isObj(bv) && bv !== undefined) {
        out[k] = nv as Patch; // a leaf became an object: send it whole
        continue;
      }
      const inner = diffPatch(bv, nv);
      if (Object.keys(inner).length) out[k] = inner;
    } else if (nv === undefined) {
      if (bv !== undefined) out[k] = null;
    } else if (!same(bv, nv)) out[k] = nv as Patch[string];
  }
  return out;
}

export const isEmptyPatch = (p: Patch) => Object.keys(p).length === 0;

export type FieldState = { value: unknown; overridden: boolean; defaultValue: unknown };

/** What a control shows: the value in force, whether it's the person's own, and the board default for the hint. */
export function fieldState<T>(defaults: T, mine: DeepPartial<T> | null | undefined, path: Path): FieldState {
  const overridden = isOverridden(mine, path);
  const defaultValue = getAt(defaults, path);
  return { value: overridden ? getAt(mine, path) : defaultValue, overridden, defaultValue };
}

/** Board default in words for the inherited hint ("On", "Medium", "22:00", "True positive, Undetermined"). */
export function describeValue(path: Path, v: unknown): string {
  if (typeof v === "boolean") return v ? "On" : "Off";
  if (Array.isArray(v)) {
    if (path === "verdict_classifications") {
      if (v.length === 0) return "none";
      return v.map((c) => CLASSIFICATIONS.find((x) => x.value === c)?.label ?? String(c)).join(", ");
    }
    return v.join(", ");
  }
  if (path === "min_incident_severity") return SEVERITIES.find((s) => s.value === v)?.label ?? String(v);
  if (v === "" || v === undefined || v === null) return "not set";
  return String(v);
}

/** Every IANA zone the browser knows, plus the current value if the list lacks it (Chrome omits "UTC"). */
export function timeZones(current?: string): string[] {
  let zones: string[] = [];
  try {
    zones = Intl.supportedValuesOf("timeZone");
  } catch {
    /* older engines */
  }
  const extra = ["UTC", browserTimeZone(), current].filter((z): z is string => !!z && !zones.includes(z));
  return [...new Set([...extra, ...zones])];
}

export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}
