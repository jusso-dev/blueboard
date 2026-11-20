import { useSearchParams } from "react-router";
import { useMemo, useState } from "react";
import { ThreadPanel } from "../components/feed";
import { MessageRow } from "../components/message";
import { PageHeader } from "../components/shell";
import { useLiveQuery, type Channel, type Incident, type Message } from "../lib/api";
import { Button, cx, Empty, Input, Segmented, Select } from "../components/ui";

const TYPES = ["finding", "ioc", "question", "verdict", "action_request", "action_result", "status", "incident", "chat"];
const PAGE = 50;

type Result = { hits: Message[]; total: number };

/** Every filter lives in the URL, so a search can be shared or bookmarked. */
export default function SearchPage() {
  const [params, setParams] = useSearchParams();
  const [thread, setThread] = useState<string | null>(null);

  const set = (patch: Record<string, string | string[] | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      next.delete(k);
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
      else if (v) next.set(k, v);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true, preventScrollReset: true });
  };

  const q = params.get("q") ?? "";
  const types = params.getAll("type");
  const sort = (params.get("sort") ?? (q ? "relevance" : "newest")) as "relevance" | "newest" | "oldest";
  const offset = Number(params.get("offset") ?? 0);
  const apiQuery = useMemo(() => {
    const p = new URLSearchParams(params);
    p.set("sort", sort);
    p.set("limit", String(PAGE));
    return p.toString();
  }, [params, sort]);

  const { data, error, loading } = useLiveQuery<Result>(`/search?${apiQuery}`);
  const { data: channels } = useLiveQuery<Channel[]>("/channels");
  const { data: incidents } = useLiveQuery<Incident[]>("/incidents");
  const filtered = ["channel", "type", "author_kind", "incident", "claim_state", "from", "to"].some((k) => params.has(k));

  return (
    <>
      <PageHeader title="Search" sub={data ? `${data.total.toLocaleString()} ${data.total === 1 ? "message" : "messages"}` : " "} />

      <div className="shrink-0 space-y-2.5 border-b border-rule px-5 py-3">
        <form
          role="search"
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const v = new FormData(e.currentTarget).get("q")?.toString().trim() ?? "";
            set({ q: v || null, sort: null });
          }}
        >
          <label className="sr-only" htmlFor="search-q">
            Search messages
          </label>
          <Input
            id="search-q"
            name="q"
            key={q}
            defaultValue={q}
            autoFocus
            placeholder={'Hashes, hosts, users or words. Use "quotes" for phrases, -word to exclude'}
            className="min-w-0 flex-1"
          />
          <Button type="submit" variant="primary" loading={loading && !!data}>
            Search
          </Button>
        </form>

        <div className="flex flex-wrap items-center gap-2">
          <Select aria-label="Channel" value={params.get("channel") ?? ""} onChange={(e) => set({ channel: e.target.value || null })}>
            <option value="">All channels</option>
            {channels?.map((c) => (
              <option key={c.name} value={c.name}>
                #{c.name}
              </option>
            ))}
          </Select>
          <Select aria-label="Incident" value={params.get("incident") ?? ""} onChange={(e) => set({ incident: e.target.value || null })}>
            <option value="">All incidents</option>
            {incidents?.map((i) => (
              <option key={i.id} value={i.id}>
                INC {i.graph_id}
              </option>
            ))}
          </Select>
          <Select aria-label="Author" value={params.get("author_kind") ?? ""} onChange={(e) => set({ author_kind: e.target.value || null })}>
            <option value="">Anyone</option>
            <option value="agent">Agents</option>
            <option value="human">People</option>
            <option value="system">Board</option>
          </Select>
          <Select aria-label="Claim state" value={params.get("claim_state") ?? ""} onChange={(e) => set({ claim_state: e.target.value || null })}>
            <option value="">Any claim state</option>
            <option value="open">Open requests</option>
            <option value="claimed">Claimed</option>
            <option value="done">Handled</option>
          </Select>
          <label className="flex items-center gap-1.5 text-xs text-muted">
            From
            <Input type="date" aria-label="From date" value={params.get("from") ?? ""} onChange={(e) => set({ from: e.target.value || null })} className="h-8 w-[9.5rem]" />
          </label>
          <label className="flex items-center gap-1.5 text-xs text-muted">
            To
            <Input type="date" aria-label="To date" value={params.get("to") ?? ""} onChange={(e) => set({ to: e.target.value || null })} className="h-8 w-[9.5rem]" />
          </label>
          <span className="ml-auto">
            <Segmented
              label="Sort"
              value={sort}
              onChange={(v) => set({ sort: v })}
              options={[
                ...(q ? [{ value: "relevance" as const, label: "Relevance" }] : []),
                { value: "newest", label: "Newest" },
                { value: "oldest", label: "Oldest" },
              ]}
            />
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Message types">
          {TYPES.map((t) => {
            const on = types.includes(t);
            return (
              <button
                key={t}
                aria-pressed={on}
                onClick={() => set({ type: on ? types.filter((x) => x !== t) : [...types, t] })}
                className={cx(
                  "h-6 rounded-[4px] border px-2 font-mono text-[11px] transition-colors duration-150",
                  on ? "border-accent bg-accent-soft text-ink" : "border-control text-muted hover:border-ink-2 hover:text-ink",
                )}
              >
                {t.replace("_", " ")}
              </button>
            );
          })}
          {(filtered || q) && (
            <Button size="sm" variant="ghost" className="ml-1" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
              Clear all
            </Button>
          )}
        </div>
      </div>

      <div className={cx("grid min-h-0 flex-1", thread ? "grid-cols-[minmax(0,1fr)_minmax(340px,440px)] max-lg:grid-cols-1" : "grid-cols-1")}>
        <div className="min-h-0 overflow-y-auto" aria-live="polite" aria-busy={loading}>
          {error && <Empty title="Search failed">{error.message}</Empty>}
          {data && data.hits.length === 0 && (
            <Empty title={q ? `No messages match "${q}"` : "No messages match these filters"}>
              {q || filtered ? "Try fewer filters, or a shorter search." : null}
            </Empty>
          )}
          {data?.hits.map((m) => (
            <MessageRow key={m.id} m={m} showChannel onOpenThread={(x) => setThread(x.parent_id ?? x.id)} selected={thread === m.id} />
          ))}
          {data && data.total > PAGE && (
            <nav aria-label="Results pages" className="flex items-center justify-between px-5 py-3">
              <Button size="sm" disabled={offset === 0} onClick={() => set({ offset: String(Math.max(0, offset - PAGE)) })}>
                Previous
              </Button>
              <span className="label tnum">
                {offset + 1}–{Math.min(offset + PAGE, data.total)} of {data.total.toLocaleString()}
              </span>
              <Button size="sm" disabled={offset + PAGE >= data.total} onClick={() => set({ offset: String(offset + PAGE) })}>
                Next
              </Button>
            </nav>
          )}
        </div>
        {thread && <ThreadPanel rootId={thread} onClose={() => setThread(null)} />}
      </div>
    </>
  );
}
