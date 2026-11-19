"use client";

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

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: { "content-type": "application/json", ...init?.headers } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? res.statusText);
  return body as T;
}

/** One shared SSE connection; subscribers get a debounced "something changed" tick. */
type Listener = () => void;
const listeners = new Set<Listener>();
let source: EventSource | null = null;
let live = false;
const liveListeners = new Set<(v: boolean) => void>();

function ensureSource() {
  if (source || typeof window === "undefined") return;
  source = new EventSource("/api/stream");
  let t: ReturnType<typeof setTimeout> | undefined;
  const setLive = (v: boolean) => {
    live = v;
    liveListeners.forEach((l) => l(v));
  };
  source.addEventListener("ready", () => setLive(true));
  source.onerror = () => setLive(false);
  source.addEventListener("board", () => {
    clearTimeout(t);
    t = setTimeout(() => listeners.forEach((l) => l()), 250);
  });
}

export function useBoardEvents(onChange: Listener) {
  const ref = useRef(onChange);
  ref.current = onChange;
  useEffect(() => {
    ensureSource();
    const l = () => ref.current();
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
}

export function useLive() {
  const [v, setV] = useState(live);
  useEffect(() => {
    ensureSource();
    liveListeners.add(setV);
    return () => {
      liveListeners.delete(setV);
    };
  }, []);
  return v;
}

/** Fetch JSON, refetch on board events. */
export function useLiveQuery<T>(path: string | null) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    if (!path) return;
    setLoading(true);
    try {
      setData(await api<T>(path));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    void load();
  }, [load]);
  useBoardEvents(load);
  return { data, error, loading, reload: load };
}
