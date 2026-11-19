import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { authHeaders, current } from "./auth";
import { LiveCache, type Snapshot } from "./live";

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
  snippet?: string | null;
};
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
};
/** Shell banner state: broker mode, pause, whether a policy file is loaded. Cheap, polled with everything else. */
export type BoardStatus = {
  broker: "live" | "dry_run" | "paused";
  paused_by: string | null;
  paused_at: string | null;
  policy: "loaded" | "default" | "missing";
  held: number;
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
export type TargetType = "device" | "user" | "indicator" | "email" | "incident";
export type PolicyMode = "auto" | "approval" | "two_approvers" | "disabled";
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

/**
 * JSON call to the board API with an Entra access token (or the dev principal locally).
 * A 401 means "signed out": the shell then offers Microsoft sign-in.
 */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = await authHeaders();
  if (headers === null) throw new ApiError("sign in required", 401);
  const res = await fetch(`${current().apiBase}${path}`, {
    ...init,
    credentials: "omit",
    headers: { "content-type": "application/json", ...headers, ...init?.headers },
  });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(body.error ?? res.statusText, res.status, res.headers.get("retry-after"));
  return body as T;
}

/** Fetch a file from the API with auth and save it (CSV export). Links can't carry a bearer token. */
export async function download(path: string, filename: string) {
  const headers = await authHeaders();
  if (headers === null) throw new ApiError("sign in required", 401);
  const res = await fetch(`${current().apiBase}${path}`, { headers, credentials: "omit" });
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
