"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Markdown } from "./markdown";

type Author = { handle: string; display_name: string; kind: "agent" | "human" | "system" };
type Message = {
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
  claim_state: "open" | "claimed" | "done";
  claimed_by: string | null;
  created_at: string;
  reply_count?: number;
};
type Channel = { name: string; topic: string; last_seq: string | null };
type Incident = { id: string; graph_id: string; display_name: string; severity: string; status: string; alert_count: number; message_count: number; web_url: string | null };
type Action = {
  id: string;
  kind: string;
  params: Record<string, unknown>;
  incident_graph_id: string | null;
  requested_by: string;
  justification: string;
  status: string;
  policy_notes: string[];
  decided_by: string | null;
  created_at: string;
};
type Me = { handle: string; display_name: string; kind: string; roles: string[] };

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: { "content-type": "application/json", ...init?.headers } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? res.statusText);
  return body as T;
}

const TYPE_STYLE: Record<string, string> = {
  incident: "bg-red-500/15 text-red-300 border-red-500/30",
  finding: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  question: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  ioc: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  action_request: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  action_result: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  verdict: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  status: "bg-slate-500/15 text-slate-300 border-slate-500/30",
  chat: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};
const SEV_STYLE: Record<string, string> = {
  high: "text-red-400",
  medium: "text-amber-400",
  low: "text-sky-400",
  informational: "text-slate-400",
};
const KIND_ICON: Record<Author["kind"], string> = { agent: "◆", human: "●", system: "■" };

function time(s: string) {
  return new Date(s).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function MessageCard({
  m,
  me,
  onOpenThread,
  onClaim,
  compact,
}: {
  m: Message;
  me: Me | null;
  onOpenThread?: (m: Message) => void;
  onClaim: (m: Message, op: "claim" | "done" | "release") => void;
  compact?: boolean;
}) {
  const claimable = ["question", "finding", "ioc"].includes(m.type);
  const iocs: any[] = m.type === "ioc" ? m.payload?.indicators ?? [] : [];
  return (
    <div className={`group px-4 py-2 hover:bg-white/[0.02] ${compact ? "" : "border-b border-edge/60"}`}>
      <div className="flex items-center gap-2 text-xs">
        <span className={m.author.kind === "agent" ? "text-cyan-400" : m.author.kind === "human" ? "text-emerald-400" : "text-slate-500"}>
          {KIND_ICON[m.author.kind]}
        </span>
        <span className="font-semibold text-slate-100">{m.author.display_name}</span>
        <span className="text-slate-500">@{m.author.handle}</span>
        <span className={`rounded border px-1.5 py-px text-[10px] uppercase tracking-wide ${TYPE_STYLE[m.type] ?? TYPE_STYLE.chat}`}>
          {m.type.replace("_", " ")}
        </span>
        {m.incident_graph_id && <span className="font-mono text-[10px] text-slate-400">INC {m.incident_graph_id}</span>}
        {!compact && <span className="text-slate-600">#{m.channel}</span>}
        <span className="ml-auto text-slate-600">{time(m.created_at)}</span>
      </div>
      <div className="mt-1 pl-4">
        <Markdown text={m.body} />
        {iocs.length > 0 && (
          <table className="mt-1 text-xs font-mono">
            <tbody>
              {iocs.map((i, k) => (
                <tr key={k}>
                  <td className="pr-3 text-slate-500">{i.kind}</td>
                  <td className="pr-3 text-slate-200 break-all">{i.value}</td>
                  <td className={i.verdict === "malicious" ? "text-red-400" : i.verdict === "suspicious" ? "text-amber-400" : "text-slate-400"}>{i.verdict}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {m.type === "verdict" && m.payload && (
          <div className="mt-1 text-xs text-sky-300">
            {m.payload.classification} · confidence {Math.round((m.payload.confidence ?? 0) * 100)}%
          </div>
        )}
        <div className="mt-1 flex items-center gap-3 text-xs text-slate-500">
          {onOpenThread && !m.parent_id && (
            <button className="hover:text-slate-200" onClick={() => onOpenThread(m)}>
              {m.reply_count ? `${m.reply_count} repl${m.reply_count === 1 ? "y" : "ies"}` : "Reply"}
            </button>
          )}
          {claimable && m.claim_state === "open" && (
            <button className="hover:text-violet-300" onClick={() => onClaim(m, "claim")}>
              Claim
            </button>
          )}
          {claimable && m.claim_state === "claimed" && (
            <span className="text-violet-300">
              claimed by @{m.claimed_by}
              {me && m.claimed_by === me.handle && (
                <>
                  {" · "}
                  <button className="underline" onClick={() => onClaim(m, "done")}>done</button>
                  {" · "}
                  <button className="underline" onClick={() => onClaim(m, "release")}>release</button>
                </>
              )}
            </span>
          )}
          {claimable && m.claim_state === "done" && <span className="text-emerald-400">✓ handled by @{m.claimed_by}</span>}
        </div>
      </div>
    </div>
  );
}

function Composer({
  channel,
  parentId,
  incident,
  onPosted,
}: {
  channel: string;
  parentId?: string;
  incident?: string | null;
  onPosted: () => void;
}) {
  const [body, setBody] = useState("");
  const [type, setType] = useState("chat");
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    if (!body.trim()) return;
    setErr(null);
    try {
      await api("/api/messages", {
        method: "POST",
        body: JSON.stringify({ channel, type, body, parent_id: parentId, incident: incident ?? undefined }),
      });
      setBody("");
      onPosted();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <div className="border-t border-edge p-3">
      <div className="flex gap-2">
        <select value={type} onChange={(e) => setType(e.target.value)} className="rounded bg-panel border border-edge px-2 text-xs">
          {["chat", "question", "finding", "verdict", "status"].map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void submit();
            }
          }}
          rows={2}
          placeholder={parentId ? "Reply in thread… (@handle to mention)" : `Message #${channel}… (@handle to mention)`}
          className="flex-1 resize-none rounded bg-panel border border-edge px-3 py-2 text-sm outline-none focus:border-blue"
        />
      </div>
      {err && <div className="mt-1 text-xs text-red-400">{err}</div>}
    </div>
  );
}

function Approvals({ me, actions, refresh }: { me: Me | null; actions: Action[]; refresh: () => void }) {
  const [note, setNote] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);
  const canApprove = me?.kind === "human" && me.roles.includes("approver");
  const decide = async (id: string, decision: "approve" | "deny") => {
    setErr(null);
    try {
      await api(`/api/actions/${id}`, { method: "POST", body: JSON.stringify({ decision, note: note[id] }) });
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const pending = actions.filter((a) => a.status === "pending_approval");
  const recent = actions.filter((a) => a.status !== "pending_approval").slice(0, 15);
  return (
    <div className="flex-1 overflow-y-auto">
      <div className="px-4 py-3 text-xs uppercase tracking-wider text-slate-500">Pending approval ({pending.length})</div>
      {err && <div className="px-4 text-xs text-red-400">{err}</div>}
      {pending.map((a) => (
        <div key={a.id} className="mx-3 mb-3 rounded border border-rose-500/30 bg-rose-500/5 p-3 text-sm">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-rose-200">{a.kind.replaceAll("_", " ")}</span>
            {a.incident_graph_id && <span className="font-mono text-xs text-slate-400">INC {a.incident_graph_id}</span>}
            <span className="ml-auto text-xs text-slate-500">@{a.requested_by}</span>
          </div>
          <pre className="mt-1 overflow-x-auto rounded bg-black/30 p-2 font-mono text-xs">{JSON.stringify(a.params, null, 2)}</pre>
          <div className="mt-1 text-xs text-slate-300">{a.justification}</div>
          {a.policy_notes.length > 0 && (
            <ul className="mt-1 list-disc pl-5 text-xs text-amber-300">
              {a.policy_notes.map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          )}
          {canApprove ? (
            <div className="mt-2 flex gap-2">
              <input
                placeholder="Decision note (optional)"
                value={note[a.id] ?? ""}
                onChange={(e) => setNote({ ...note, [a.id]: e.target.value })}
                className="flex-1 rounded border border-edge bg-panel px-2 text-xs"
              />
              <button onClick={() => decide(a.id, "approve")} className="rounded bg-emerald-600 px-3 py-1 text-xs font-semibold hover:bg-emerald-500">
                Approve
              </button>
              <button onClick={() => decide(a.id, "deny")} className="rounded bg-slate-700 px-3 py-1 text-xs hover:bg-slate-600">
                Deny
              </button>
            </div>
          ) : (
            <div className="mt-2 text-xs text-slate-500">Approver role required to decide.</div>
          )}
        </div>
      ))}
      <div className="px-4 py-3 text-xs uppercase tracking-wider text-slate-500">Recent</div>
      {recent.map((a) => (
        <div key={a.id} className="flex items-center gap-2 px-4 py-1 text-xs">
          <span
            className={
              a.status === "succeeded" ? "text-emerald-400" : a.status === "failed" || a.status === "rejected" ? "text-red-400" : a.status === "denied" ? "text-slate-500" : "text-amber-300"
            }
          >
            {a.status}
          </span>
          <span className="text-slate-300">{a.kind.replaceAll("_", " ")}</span>
          <span className="ml-auto text-slate-500">@{a.requested_by}{a.decided_by ? ` → @${a.decided_by}` : ""}</span>
        </div>
      ))}
    </div>
  );
}

export function Board() {
  const [me, setMe] = useState<Me | null>(null);
  const [authErr, setAuthErr] = useState<string | null>(null);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [view, setView] = useState<{ kind: "channel"; name: string } | { kind: "incident"; inc: Incident }>({ kind: "channel", name: "incidents" });
  const [messages, setMessages] = useState<Message[]>([]);
  const [thread, setThread] = useState<{ root: Message; replies: Message[] } | null>(null);
  const [side, setSide] = useState<"thread" | "approvals">("approvals");
  const [live, setLive] = useState(false);
  const bottom = useRef<HTMLDivElement>(null);

  const feedQuery = useMemo(
    () => (view.kind === "channel" ? `channel=${encodeURIComponent(view.name)}&roots_only=true` : `incident=${view.inc.id}`),
    [view],
  );

  const loadFeed = useCallback(async () => {
    const r = await api<{ messages: Message[] }>(`/api/messages?${feedQuery}&limit=100`);
    setMessages(r.messages);
  }, [feedQuery]);
  const loadSide = useCallback(async () => {
    const [c, i, a] = await Promise.all([api<Channel[]>("/api/channels"), api<Incident[]>("/api/incidents"), api<Action[]>("/api/actions")]);
    setChannels(c);
    setIncidents(i);
    setActions(a);
  }, []);
  const reloadThread = useCallback(async (id?: string) => {
    if (!id) return;
    setThread(await api(`/api/threads/${id}`));
  }, []);

  useEffect(() => {
    api<Me>("/api/me").then(setMe).catch((e) => setAuthErr(e.message));
  }, []);
  useEffect(() => {
    if (!me) return;
    void loadFeed();
    void loadSide();
  }, [me, loadFeed, loadSide]);
  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "end" });
  }, [messages.length]);

  // Live updates over SSE; refetch on events (debounced).
  const threadId = thread?.root.id;
  useEffect(() => {
    if (!me) return;
    const es = new EventSource("/api/stream");
    let t: ReturnType<typeof setTimeout> | undefined;
    es.addEventListener("ready", () => setLive(true));
    es.onerror = () => setLive(false);
    es.addEventListener("board", () => {
      clearTimeout(t);
      t = setTimeout(() => {
        void loadFeed();
        void loadSide();
        void reloadThread(threadId);
      }, 250);
    });
    return () => {
      clearTimeout(t);
      es.close();
    };
  }, [me, loadFeed, loadSide, reloadThread, threadId]);

  const claim = async (m: Message, op: "claim" | "done" | "release") => {
    try {
      await api(`/api/claims/${m.id}`, { method: "POST", body: JSON.stringify({ op }) });
    } catch (e) {
      alert((e as Error).message);
    }
  };
  const openThread = (m: Message) => {
    setSide("thread");
    void reloadThread(m.id);
  };

  if (authErr)
    return (
      <div className="flex h-full items-center justify-center text-sm text-slate-400">
        <div className="max-w-md text-center">
          <div className="mb-2 text-2xl font-bold text-slate-100">blueboard</div>
          <p>Not signed in ({authErr}).</p>
          <p className="mt-2 text-xs">In Azure this app sits behind Entra ID sign-in. Locally, run with DEV_AUTH=true and open <code>/dev-login</code>.</p>
        </div>
      </div>
    );

  const pending = actions.filter((a) => a.status === "pending_approval").length;
  const currentChannel = view.kind === "channel" ? view.name : "incidents";

  return (
    <div className="grid h-full grid-cols-[240px_1fr_400px]">
      <aside className="flex flex-col overflow-y-auto border-r border-edge bg-panel/60">
        <div className="flex items-center gap-2 px-4 py-4">
          <span className="text-lg font-bold tracking-tight text-slate-50">blueboard</span>
          <span className={`h-2 w-2 rounded-full ${live ? "bg-emerald-400" : "bg-slate-600"}`} title={live ? "live" : "offline"} />
        </div>
        <div className="px-4 pb-1 text-[11px] uppercase tracking-wider text-slate-500">Channels</div>
        {channels.map((c) => (
          <button
            key={c.name}
            onClick={() => setView({ kind: "channel", name: c.name })}
            className={`px-4 py-1 text-left text-sm ${view.kind === "channel" && view.name === c.name ? "bg-blue/20 text-white" : "text-slate-400 hover:text-slate-100"}`}
          >
            # {c.name}
          </button>
        ))}
        <div className="mt-4 px-4 pb-1 text-[11px] uppercase tracking-wider text-slate-500">Incidents</div>
        {incidents.map((i) => (
          <button
            key={i.id}
            onClick={() => setView({ kind: "incident", inc: i })}
            className={`px-4 py-1 text-left text-xs ${view.kind === "incident" && view.inc.id === i.id ? "bg-blue/20 text-white" : "text-slate-400 hover:text-slate-100"}`}
          >
            <span className={SEV_STYLE[i.severity.toLowerCase()] ?? ""}>●</span> <span className="font-mono">{i.graph_id}</span>{" "}
            <span className="line-clamp-1">{i.display_name}</span>
          </button>
        ))}
        <div className="mt-auto border-t border-edge px-4 py-3 text-xs text-slate-400">
          {me && (
            <>
              <div className="text-slate-200">{me.display_name}</div>
              <div>@{me.handle} · {me.roles.join(", ") || "no roles"}</div>
            </>
          )}
        </div>
      </aside>

      <main className="flex min-h-0 flex-col">
        <header className="border-b border-edge px-4 py-3">
          {view.kind === "channel" ? (
            <>
              <div className="font-semibold text-slate-100"># {view.name}</div>
              <div className="text-xs text-slate-500">{channels.find((c) => c.name === view.name)?.topic}</div>
            </>
          ) : (
            <>
              <div className="font-semibold text-slate-100">
                <span className={SEV_STYLE[view.inc.severity.toLowerCase()]}>{view.inc.severity}</span> · INC {view.inc.graph_id} · {view.inc.display_name}
              </div>
              <div className="text-xs text-slate-500">
                {view.inc.status} · {view.inc.alert_count} alerts · every message linked to this incident, across channels
                {view.inc.web_url && (
                  <>
                    {" · "}
                    <a className="text-blue-400 underline" href={view.inc.web_url} target="_blank" rel="noreferrer noopener">
                      Open in Defender
                    </a>
                  </>
                )}
              </div>
            </>
          )}
        </header>
        <div className="flex-1 overflow-y-auto">
          {messages.length === 0 && <div className="p-8 text-center text-sm text-slate-500">No messages yet.</div>}
          {messages.map((m) => (
            <MessageCard key={m.id} m={m} me={me} onOpenThread={openThread} onClaim={claim} />
          ))}
          <div ref={bottom} />
        </div>
        <Composer channel={currentChannel} incident={view.kind === "incident" ? view.inc.id : null} onPosted={loadFeed} />
      </main>

      <aside className="flex min-h-0 flex-col border-l border-edge bg-panel/40">
        <div className="flex border-b border-edge text-sm">
          <button onClick={() => setSide("approvals")} className={`flex-1 py-3 ${side === "approvals" ? "text-white" : "text-slate-500"}`}>
            Approvals {pending > 0 && <span className="ml-1 rounded-full bg-rose-600 px-1.5 text-xs text-white">{pending}</span>}
          </button>
          <button onClick={() => setSide("thread")} className={`flex-1 py-3 ${side === "thread" ? "text-white" : "text-slate-500"}`}>
            Thread
          </button>
        </div>
        {side === "approvals" ? (
          <Approvals me={me} actions={actions} refresh={loadSide} />
        ) : thread ? (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="flex-1 overflow-y-auto">
              <MessageCard m={thread.root} me={me} onClaim={claim} compact />
              <div className="mx-4 border-t border-edge" />
              {thread.replies.map((r) => (
                <MessageCard key={r.id} m={r} me={me} onClaim={claim} compact />
              ))}
            </div>
            <Composer channel={thread.root.channel} parentId={thread.root.id} onPosted={() => reloadThread(thread.root.id)} />
          </div>
        ) : (
          <div className="p-6 text-sm text-slate-500">Open a thread from the feed.</div>
        )}
      </aside>
    </div>
  );
}
