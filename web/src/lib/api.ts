import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { authHeaders, current } from "./auth";
import { LiveCache, type Snapshot } from "./live";
import type { Reaction } from "./emoji";

export type Author = { handle: string; display_name: string; kind: "agent" | "human" | "system" };
export type Message = {
  id: string;
  seq: string;
  channel: string;
  author: Author;
  parent_id: string | null;
  incident_id: string | null;
  incident_graph_id: string | null;
  type: string;
  body: string;
  payload: any;
  mentions: string[];
  claim_state: "open" | "claimed" | "done";
  claimed_by: string | null;
  created_at: string;
  reply_count?: number;
  /** Newest reply's time (roots only). Optional: older APIs don't send it. */
  last_reply_at?: string | null;
  /** Distinct repliers, newest first (roots only). Optional: older APIs don't send it. */
  reply_authors?: Author[];
  snippet?: string | null;
  /** In order of first reaction; `handles` are the reactors (up to 20, so `count` can be larger). */
  reactions?: Reaction[];
};
export type { Reaction } from "./emoji";
/** GET /participants: who can be mentioned. */
export type { Participant } from "./mentions";
export type Channel = { name: string; topic: string; last_seq: string | null };
export type Incident = {
  id: string;
  graph_id: string;
  display_name: string;
  severity: string;
  status: string;
  alert_count: number;
  message_count: number;
  web_url: string | null;
};
/** One row of GET /incidents?view=queue. */
export type QueueRow = {
  id: string;
  graph_id: string;
  display_name: string;
  severity: string;
  status: string;
  web_url: string | null;
  alert_count: number;
  verdict: string | null;
  verdict_confidence: number | null;
  verdict_by: string | null;
  open_asks: number;
  human_asks: number;
  pending_actions: number;
  active_claims: string[];
  last_activity_at: string;
  created_at: string;
  mine: boolean;
  needs_human: boolean;
};

export type SummaryEntity = { kind: "user" | "device" | "app"; id: string; label: string };
export type SummaryVerdict = {
  message_id: string;
  thread_id: string;
  classification: string;
  confidence: number;
  determination: string | null;
  author: string;
  author_name: string;
  author_kind: string;
  at: string;
  not_in_evidence: string[];
};
export type SummaryIoc = {
  kind: string;
  value: string;
  verdict: string;
  first_seen: string;
  reporters: string[];
  message_ids: string[];
  thread_id: string;
  in_evidence: boolean;
  not_in_evidence: boolean;
};
export type SummaryStep = { id: string; title: string; stage: string; state: "open" | "claimed" | "done" | "hidden"; message_id: string | null; thread_id: string | null; claimed_by: string | null; suggested_action: string | null };
/** GET /incidents/{id} → summary: a deterministic roll-up of the incident's stored messages. */
export type IncidentSummary = {
  verdict: SummaryVerdict | null;
  verdicts_disagree: boolean;
  verdicts: SummaryVerdict[];
  iocs: SummaryIoc[];
  actions: { id: string; kind: string; title: string; status: string; status_text: string; requested_by: string; request_message_id: string | null; created_at: string }[];
  open_asks: { message_id: string; thread_id: string; excerpt: string; author: string; created_at: string; age_seconds: number }[];
  entities: SummaryEntity[];
  playbook: { id: string; title: string; done: number; total: number; steps: SummaryStep[] } | null;
  markdown: string;
};

export type Action = {
  id: string;
  kind: string;
  params: Record<string, unknown>;
  incident_graph_id: string | null;
  requested_by: string;
  justification: string;
  status: string;
  policy_notes: string[];
  decided_by: string | null;
  decision_note: string | null;
  created_at: string;
  request_message_id?: string | null;
  expires_at?: string | null;
  approvals_required?: number;
  approvals?: string[];
  /** Set for kinds in the policy's confirm_target list: the approver types this name back to approve. */
  confirm_prompt?: string | null;
  held_at?: string | null;
  /** Ran without a person under this automation rule (e.g. "isolate_device@v3"). */
  auto_rule?: string | null;
  revert_after_minutes?: number | null;
  revert_at?: string | null;
  revert_state?: "scheduled" | "kept" | "reverting" | "reverted" | "failed" | null;
  revert_action_id?: string | null;
  revert_of?: string | null;
};
/** Shell banner state: broker mode, pause, whether a policy file is loaded. Cheap, polled with everything else. */
export type BoardStatus = {
  broker: "live" | "dry_run" | "paused";
  paused_by: string | null;
  paused_at: string | null;
  policy: "loaded" | "default" | "missing";
  held: number;
  /** Sign out after this many minutes without input (SESSION_IDLE_MINUTES); 0 is off. */
  session_idle_minutes?: number;
  /** Automation kill switch: every automatic decision waits for a person. */
  automation_paused?: boolean;
  automation_paused_by?: string | null;
  /** Policy loosening changes waiting for a second admin. */
  pending_policy_changes?: number;
};
export type Me = { handle: string; display_name: string; kind: string; roles: string[] };

/** One action kind from GET /actions?catalog=true. */
export type CatalogEntry = {
  kind: string;
  title: string;
  stage: string;
  destructive: boolean;
  target: TargetType;
  params: JsonSchema;
  mode: PolicyMode | null;
};
export type TargetType = "device" | "user" | "app" | "indicator" | "email" | "incident" | "detection";
export type PolicyMode = "auto" | "approval" | "on_instruction" | "two_approvers" | "disabled" | "conditional";
export type JsonSchema = {
  type?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  enum?: string[];
  default?: unknown;
  description?: string;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  items?: JsonSchema;
  minItems?: number;
  maxItems?: number;
};

/** What policy would do with a request: POST /actions/preview and /policy/simulate. */
export type Assessment = {
  kind: string;
  title: string;
  destructive: boolean;
  outcome: "reject" | "needs_approval" | "auto";
  status: string;
  approvals_required: number;
  confirm_target: boolean;
  expires_in_hours: number;
  notes: string[];
  summary: string;
  describe: string;
  /** Set when a destructive kind would run on its own under an automation rule. */
  auto_rule?: string | null;
  revert_after_minutes?: number | null;
};

/** Open = still waiting on a person: no approval yet, or 1 of 2. */
export const OPEN_STATUSES = ["pending_approval", "approved_once"];

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public retryAfter: string | null = null,
  ) {
    super(message);
  }
}

async function authedFetch(path: string, init?: RequestInit, defaultHeaders?: Record<string, string>): Promise<Response> {
  const headers = await authHeaders();
  if (headers === null) throw new ApiError("sign in required", 401);
  const send = (auth: Record<string, string>) =>
    fetch(`${current().apiBase}${path}`, {
      ...init,
      credentials: "omit",
      headers: { ...defaultHeaders, ...auth, ...init?.headers },
    });
  const res = await send(headers);
  // A cached Entra access token can expire right at a clock-skew boundary: refresh silently once before signing out.
  if (res.status === 401 && current().mode === "entra") {
    const fresh = await authHeaders(true);
    if (fresh === null) throw new ApiError("sign in required", 401);
    return send(fresh);
  }
  return res;
}

/**
 * JSON call to the board API with an Entra access token (or the dev principal locally).
 * A 401 means "signed out": the shell then offers Microsoft sign-in.
 */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await authedFetch(path, init, { "content-type": "application/json" });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(body.error ?? res.statusText, res.status, res.headers.get("retry-after"));
  return body as T;
}

/** Fetch a file from the API with auth and save it (CSV export). Links can't carry a bearer token. */
export async function download(path: string, filename: string) {
  const res = await authedFetch(path);
  if (!res.ok) throw new ApiError(res.statusText, res.status);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Live updates by polling: the Function App doesn't hold long-lived connections, and the board changes
 * slowly. One shared ticker; it pauses while the tab is hidden and fires immediately when it returns.
 */
const POLL_MS = 4000;
let timer: ReturnType<typeof setInterval> | undefined;
let lastOk = true;
const statusListeners = new Set<(ok: boolean) => void>();

/**
 * One shared cache keyed by path: the shell, the rail and a page all asking for /actions?status=pending_approval
 * share one request per tick instead of one each.
 */
const cache = new LiveCache(async (path) => {
  try {
    const data = await api<unknown>(path);
    setLive(true);
    return data;
  } catch (e) {
    const err = e instanceof ApiError ? e : new ApiError(String(e), 0);
    if (err.status === 0 || err.status >= 500) setLive(false);
    throw err;
  }
});

function ensureTicker() {
  if (timer || typeof window === "undefined") return;
  const tick = () => {
    if (document.visibilityState === "visible") void cache.refreshAll();
  };
  timer = setInterval(tick, POLL_MS);
  document.addEventListener("visibilitychange", tick);
}

export function setLive(ok: boolean) {
  if (ok === lastOk) return;
  lastOk = ok;
  statusListeners.forEach((l) => l(ok));
}

/** Call after a write so every open view refreshes now, not on the next tick. */
export function refreshAll() {
  void cache.refreshAll();
}

export function useLive() {
  const [ok, setOk] = useState(lastOk);
  useEffect(() => {
    statusListeners.add(setOk);
    return () => void statusListeners.delete(setOk);
  }, []);
  return ok;
}

const idle: Snapshot<never> = Object.freeze({ data: undefined, error: null, loading: false });
const noop = () => () => {};

/** Fetch JSON and keep it fresh with the shared poll. Pass null to skip. Same path, same request. */
export function useLiveQuery<T>(path: string | null) {
  const subscribe = useCallback((onChange: () => void) => {
    if (!path) return noop();
    ensureTicker();
    return cache.subscribe(path, onChange);
  }, [path]);
  const snap = useSyncExternalStore(subscribe, () => (path ? cache.get<T>(path) : idle), () => idle);
  const reload = useCallback(() => (path ? cache.load(path) : Promise.resolve()), [path]);
  return { data: snap.data as T | undefined, error: (snap.error as ApiError | null) ?? null, loading: snap.loading, reload };
}
