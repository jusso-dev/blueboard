import { useCallback, useEffect, useRef, useState } from "react";
import { authHeaders, current } from "./auth";

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

export type SummaryEntity = { kind: "user" | "device"; id: string; label: string };
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
};
export type Me = { handle: string; display_name: string; kind: string; roles: string[] };

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
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | undefined;
let lastOk = true;
const statusListeners = new Set<(ok: boolean) => void>();

function ensureTicker() {
  if (timer || typeof window === "undefined") return;
  const tick = () => {
    if (document.visibilityState === "visible") listeners.forEach((l) => l());
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
  listeners.forEach((l) => l());
}

export function useLive() {
  const [ok, setOk] = useState(lastOk);
  useEffect(() => {
    statusListeners.add(setOk);
    return () => void statusListeners.delete(setOk);
  }, []);
  return ok;
}

/** Fetch JSON and keep it fresh with the shared poll. Pass null to skip. */
export function useLiveQuery<T>(path: string | null) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(false);
  const inflight = useRef(false);
  const load = useCallback(async () => {
    if (!path || inflight.current) return;
    inflight.current = true;
    setLoading(true);
    try {
      setData(await api<T>(path));
      setError(null);
      setLive(true);
    } catch (e) {
      const err = e instanceof ApiError ? e : new ApiError(String(e), 0);
      setError(err);
      if (err.status === 0 || err.status >= 500) setLive(false);
    } finally {
      inflight.current = false;
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    setData(undefined);
    void load();
  }, [load]);
  useEffect(() => {
    ensureTicker();
    listeners.add(load);
    return () => void listeners.delete(load);
  }, [load]);
  return { data, error, loading, reload: load };
}
