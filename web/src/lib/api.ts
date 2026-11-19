import { useCallback, useEffect, useRef, useState } from "react";

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
};
export type Me = { handle: string; display_name: string; kind: string; roles: string[] };

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

/** Same-origin JSON fetch. In Azure the Static Web App auth cookie rides along; /api goes to the linked Function App. */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const dev = import.meta.env.DEV ? sessionStorage.getItem("bb_dev_principal") : null;
  const res = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...(dev ? { "x-dev-principal": dev } : {}), ...init?.headers },
  });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(body.error ?? res.statusText, res.status);
  return body as T;
}

/**
 * Live updates by polling: Azure Functions don't hold long-lived connections, and the board changes
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
