import { Link } from "react-router";
import { useMemo, useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, refreshAll, useLiveQuery } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Input, KindBadge, Select, Tag, Time } from "../components/ui";

type SharedMemory = {
  id: string;
  key: string;
  category: "environment" | "baseline" | "asset" | "threat" | "procedure" | "preference" | "general";
  title: string;
  content: string;
  tags: string[];
  entities: string[];
  confidence: number | null;
  verified: boolean;
  verified_by: string | null;
  verified_at: string | null;
  pinned: boolean;
  archived: boolean;
  source_incident_id: string | null;
  source_incident_graph_id: string | null;
  source_message_id: string | null;
  expires_at: string | null;
  created_by: { handle: string; display_name: string; kind: "agent" | "human" | "system" };
  updated_by: { handle: string; display_name: string; kind: "agent" | "human" | "system" };
  created_at: string;
  updated_at: string;
};

const CATEGORIES: SharedMemory["category"][] = ["environment", "baseline", "asset", "threat", "procedure", "preference", "general"];

const CATEGORY_HINT: Record<SharedMemory["category"], string> = {
  environment: "Egress IPs, tenant layout, cloud subscriptions",
  baseline: "Known-benign jobs, scanners, expected alerts",
  asset: "VIP laptops, servers, critical app ownership",
  threat: "Recurring threat actors, campaign TTPs",
  procedure: "Escalation nuances, shift handover rules",
  preference: "Team conventions and alert formatting",
  general: "Other shared SOC context",
};

function slugify(cat: string, title: string) {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug ? `${cat}/${slug}` : "";
}

/** Shared SOC memory: persistent baselines, asset context and procedures shared across all agents and analysts. */
export default function MemoryPage() {
  const me = useMe();
  const isHuman = me?.kind === "human";
  const [category, setCategory] = useState<string>("all");
  const [trust, setTrust] = useState<"all" | "verified" | "unverified">("all");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [search, setSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const query = useMemo(() => {
    const p = new URLSearchParams();
    p.set("limit", "100");
    if (category !== "all") p.set("category", category);
    if (trust === "verified") p.set("verified_only", "true");
    if (includeArchived) p.set("include_archived", "true");
    if (search.trim()) p.set("q", search.trim());
    return `/memories?${p.toString()}`;
  }, [category, trust, includeArchived, search]);

  const { data, error } = useLiveQuery<SharedMemory[]>(query);
  const rows = useMemo(() => {
    const list = data ?? [];
    if (trust === "unverified") return list.filter((m) => !m.verified);
    return list;
  }, [data, trust]);

  const mutate = async (id: string, fn: () => Promise<unknown>) => {
    setBusyId(id);
    setErr(null);
    try {
      await fn();
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  if (error) return <Empty title="Couldn't load shared memory">{error.message}</Empty>;

  const verifiedCount = (data ?? []).filter((m) => m.verified && !m.archived).length;
  const unverifiedCount = (data ?? []).filter((m) => !m.verified && !m.archived).length;

  return (
    <>
      <PageHeader
        title="Shared memory"
        sub="Persistent SOC knowledge shared across every AI agent and analyst. Agents write unverified entries; humans verify baselines so prompt injection can't overwrite trusted context."
      >
        <Button type="button" variant={showForm ? "secondary" : "primary"} onClick={() => setShowForm((v) => !v)}>
          {showForm ? "Cancel" : "Add memory"}
        </Button>
      </PageHeader>

      <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4 max-sm:px-4">
        {showForm && <AddMemoryForm onDone={() => setShowForm(false)} />}

        <div className="flex flex-wrap items-center gap-2 pb-4">
          <Select aria-label="Filter by category" value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="all">All categories</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </Select>
          <Select aria-label="Filter by verification" value={trust} onChange={(e) => setTrust(e.target.value as never)}>
            <option value="all">All trust levels</option>
            <option value="verified">Human-verified ({verifiedCount})</option>
            <option value="unverified">Agent unverified ({unverifiedCount})</option>
          </Select>
          <Input
            aria-label="Search shared memory"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title, key, entity (IP/host/UPN), tag…"
            className="w-72 max-sm:w-full"
          />
          <label className="ml-auto flex items-center gap-1.5 text-xs text-muted">
            <input type="checkbox" checked={includeArchived} onChange={(e) => setIncludeArchived(e.target.checked)} />
            Show archived
          </label>
        </div>

        {err && (
          <div className="pb-3">
            <ErrorLine>{err}</ErrorLine>
          </div>
        )}

        {rows.length === 0 ? (
          <div className="rounded-lg border border-rule bg-paper-2 px-6 py-10 text-center">
            <p className="text-sm font-medium text-ink-2">No shared memories match yet</p>
            <p className="mt-1 text-xs text-muted">
              Add your known-benign baselines, egress IPs, VIP asset notes, or change freezes here — or tell an agent in chat and it will store them via{" "}
              <code className="font-mono text-ink-2">remember</code> and recall them via <code className="font-mono text-ink-2">recall_memory</code>.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {rows.map((m) => (
              <article
                key={m.id}
                className={cx(
                  "rounded-lg border bg-paper-2 p-4 transition-colors",
                  m.archived ? "border-rule opacity-60" : m.pinned ? "border-accent/60" : "border-rule",
                )}
              >
                <header className="flex flex-wrap items-center gap-2">
                  {m.pinned && <Tag tone="accent">pinned</Tag>}
                  {m.verified ? (
                    <Tag tone="good" title={m.verified_by ? `Verified by @${m.verified_by}` : undefined}>
                      verified{m.verified_by ? ` · @${m.verified_by}` : ""}
                    </Tag>
                  ) : (
                    <Tag tone="warning">unverified</Tag>
                  )}
                  <Tag tone="neutral">{m.category}</Tag>
                  {m.archived && <Tag tone="neutral">archived</Tag>}
                  <code className="label font-mono text-ink-2">{m.key}</code>
                  <span className="ml-auto flex items-center gap-2">
                    {m.expires_at && (
                      <span className="label text-warning" title={new Date(m.expires_at).toLocaleString()}>
                        expires <Time iso={m.expires_at} />
                      </span>
                    )}
                    <Time iso={m.updated_at} />
                  </span>
                </header>

                <h2 className="mt-2 text-sm font-semibold text-ink">{m.title}</h2>
                <p className="mt-1 whitespace-pre-wrap text-ui text-ink-2 [overflow-wrap:anywhere]">{m.content}</p>

                {(m.entities.length > 0 || m.tags.length > 0) && (
                  <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                    {m.entities.map((e) => (
                      <Link
                        key={`e:${e}`}
                        to={`/search?q=${encodeURIComponent(e)}`}
                        className="rounded-[4px] border border-rule bg-paper px-1.5 py-0.5 font-mono text-meta text-accent hover:border-accent"
                      >
                        {e}
                      </Link>
                    ))}
                    {m.tags.map((t) => (
                      <span key={`t:${t}`} className="rounded-[4px] border border-rule px-1.5 py-0.5 text-meta text-muted">
                        #{t}
                      </span>
                    ))}
                  </div>
                )}

                <footer className="mt-3 flex flex-wrap items-center gap-2 border-t border-rule pt-2.5 text-xs text-muted">
                  <span className="flex items-center gap-1.5">
                    Updated by <span className="text-ink-2">@{m.updated_by.handle}</span>
                    {m.updated_by.kind === "agent" && <KindBadge kind="agent" />}
                  </span>
                  {m.confidence != null && <span className="tnum">· {Math.round(m.confidence * 100)}% confidence</span>}
                  {m.source_incident_id && m.source_incident_graph_id && (
                    <Link to={`/incidents/${m.source_incident_id}`} className="text-accent hover:underline">
                      · INC {m.source_incident_graph_id}
                    </Link>
                  )}

                  {isHuman && !m.archived && (
                    <div className="ml-auto flex flex-wrap items-center gap-1.5">
                      <Button
                        type="button"
                        size="sm"
                        variant={m.verified ? "ghost" : "secondary"}
                        disabled={busyId === m.id}
                        onClick={() => void mutate(m.id, () => api(`/memories/${m.id}/verify`, { method: "POST", body: JSON.stringify({ verified: !m.verified }) }))}
                      >
                        {m.verified ? "Unverify" : "Verify"}
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        disabled={busyId === m.id}
                        onClick={() => void mutate(m.id, () => api(`/memories/${m.id}/verify`, { method: "POST", body: JSON.stringify({ pinned: !m.pinned }) }))}
                      >
                        {m.pinned ? "Unpin" : "Pin"}
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="danger"
                        disabled={busyId === m.id}
                        onClick={() => void mutate(m.id, () => api(`/memories/${m.id}`, { method: "DELETE" }))}
                      >
                        Archive
                      </Button>
                    </div>
                  )}
                </footer>
              </article>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function AddMemoryForm({ onDone }: { onDone: () => void }) {
  const [category, setCategory] = useState<SharedMemory["category"]>("baseline");
  const [title, setTitle] = useState("");
  const [key, setKey] = useState("");
  const [content, setContent] = useState("");
  const [entities, setEntities] = useState("");
  const [tags, setTags] = useState("");
  const [expiresHours, setExpiresHours] = useState("");
  const [pinned, setPinned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const effectiveKey = key.trim() || slugify(category, title);

  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const splitList = (s: string) =>
        s
          .split(/[,;\n]/)
          .map((x) => x.trim())
          .filter(Boolean);
      const exp = expiresHours.trim() ? Number(expiresHours.trim()) : undefined;
      await api("/memories", {
        method: "POST",
        body: JSON.stringify({
          key: effectiveKey,
          category,
          title,
          content,
          entities: splitList(entities),
          tags: splitList(tags),
          expires_in_hours: exp && Number.isFinite(exp) ? exp : undefined,
          pinned,
        }),
      });
      refreshAll();
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="mb-4 space-y-2.5 rounded-lg border border-rule-strong bg-paper-2 p-4"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-[160px_1fr_220px]">
        <Select aria-label="Memory category" value={category} onChange={(e) => setCategory(e.target.value as SharedMemory["category"])}>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </Select>
        <Input
          aria-label="Memory title"
          required
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Title (e.g. Sydney corporate egress proxy IP)"
        />
        <Input
          aria-label="Stable key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder={effectiveKey || "baseline/sydney-egress"}
          className="font-mono text-xs"
        />
      </div>
      <p className="text-meta text-faint">{CATEGORY_HINT[category]}</p>
      <textarea
        aria-label="Memory content"
        required
        rows={3}
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="Write concise, factual context all agents should know (never store passwords, keys, or tokens)…"
        className="w-full rounded-[var(--radius-control)] border border-control bg-paper px-2.5 py-2 text-ui text-ink placeholder:text-faint focus:border-accent focus:outline-none"
      />
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <Input
          aria-label="Entities"
          value={entities}
          onChange={(e) => setEntities(e.target.value)}
          placeholder="Entities (IP, host, UPN, CVE — comma-separated)"
          className="font-mono"
        />
        <Input aria-label="Tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Tags (comma-separated, e.g. egress, benign)" />
        <Input
          aria-label="Expires in hours"
          type="number"
          min={1}
          max={8760}
          value={expiresHours}
          onChange={(e) => setExpiresHours(e.target.value)}
          placeholder="Expires in hours (optional, e.g. 48)"
        />
      </div>
      <div className="flex flex-wrap items-center gap-3 pt-1">
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={pinned} onChange={(e) => setPinned(e.target.checked)} />
          Pin to top for all agents
        </label>
        <div className="ml-auto flex items-center gap-2">
          {err && <ErrorLine>{err}</ErrorLine>}
          <Button type="submit" variant="primary" size="sm" loading={busy} disabled={!title.trim() || !content.trim() || !effectiveKey}>
            Save memory
          </Button>
        </div>
      </div>
    </form>
  );
}
