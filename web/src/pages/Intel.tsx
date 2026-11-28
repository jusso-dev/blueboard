import { Link, useNavigate } from "react-router";
import { useMemo, useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, refreshAll, useLiveQuery } from "../lib/api";
import { safeHref } from "../lib/gifs";
import { Button, cx, Empty, ErrorLine, Input, KindBadge, Select, Tag, Time } from "../components/ui";

export type SourceRow = {
  id: string;
  name: string;
  flag: string;
  enabled: boolean;
  attribution: string;
  mode: string;
  permission: string | null;
  home: string;
  state: "ok" | "off" | "failing" | "not run yet" | "unavailable";
  last_fetch_at: string | null;
  last_error: string | null;
  freshness: { freshness: string | null; stale: boolean } | null;
};

type WatchRow = {
  id: string;
  kind: string;
  value: string;
  enabled: boolean;
  origin: "default" | "manual" | "inventory";
  label: string | null;
};

type Recent = {
  source: string;
  key: string;
  title: string | null;
  severity: string | null;
  url: string | null;
  retrieved_at: string;
  published_at: string | null;
  updated_at: string | null;
  watches: string[];
  cve_ids: string[];
  patch_status: string | null;
  attribution: string;
};

type TiFindingIndicator = { kind: string; value: string };

type TiFinding = {
  id: string;
  title: string;
  summary: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  status: "new" | "reviewing" | "mitigated" | "dismissed";
  tech_stack: string[];
  matched_watches: string[];
  cves: string[];
  indicators: TiFindingIndicator[];
  source: string;
  source_url: string | null;
  recommendation: string | null;
  confidence: number | null;
  author: { handle: string; display_name: string; kind: "agent" | "human" | "system" };
  message_id: string | null;
  created_at: string;
  updated_at: string;
};

type Index = {
  any_enabled: boolean;
  fixture_mode: boolean;
  can_hunt: boolean;
  sources: SourceRow[];
  watches: WatchRow[];
  recent: Recent[];
  findings?: TiFinding[];
};

const STATE_TONE: Record<SourceRow["state"], "good" | "neutral" | "critical" | "warning"> = {
  ok: "good",
  off: "neutral",
  failing: "critical",
  "not run yet": "warning",
  unavailable: "neutral",
};

const SEV_TONE: Record<string, "critical" | "warning" | "accent" | "neutral"> = {
  critical: "critical",
  high: "critical",
  medium: "warning",
  low: "accent",
  informational: "neutral",
};

const STATUS_OPTIONS: TiFinding["status"][] = ["new", "reviewing", "mitigated", "dismissed"];
const STACK_PRESETS: { value: string; label: string }[] = [
  { value: "Microsoft Entra ID", label: "Identity" },
  { value: "Exchange Online", label: "Email" },
  { value: "Windows Server", label: "OS" },
  { value: "FortiOS", label: "Edge" },
  { value: "PAN-OS", label: "Edge" },
  { value: "Cisco", label: "Network" },
  { value: "VMware", label: "Virtualisation" },
  { value: "Kubernetes", label: "Containers" },
  { value: "PostgreSQL", label: "Database" },
  { value: ".NET", label: "Runtime" },
  { value: "Docker", label: "Containers" },
  { value: "Linux", label: "OS" },
];

/** Threat intel: bot & analyst findings for your tech stack, stack/watchlists config, newest feeds, and sources. */
export default function IntelPage() {
  const { data, error } = useLiveQuery<Index>("/intel");
  const navigate = useNavigate();
  const [key, setKey] = useState("");

  if (error) return <Empty title="Couldn't load threat intel">{error.message}</Empty>;
  const stale = data?.sources.find((s) => s.id === "pwn.watch" && s.enabled && s.freshness?.stale);

  return (
    <>
      <PageHeader title="Threat intel" sub="Tech-stack findings from threat intel agents, outside feeds, and this tenant's intel — side by side.">
        <form
          role="search"
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (key.trim()) navigate(`/intel/${encodeURIComponent(key.trim())}`);
          }}
        >
          <label className="sr-only" htmlFor="intel-key">
            CVE or indicator
          </label>
          <Input id="intel-key" value={key} onChange={(e) => setKey(e.target.value)} placeholder="CVE-2021-44228, IP, domain, hash" className="w-72 max-sm:w-full" />
          <Button type="submit" variant="primary">
            Look up
          </Button>
        </form>
      </PageHeader>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {data && !data.any_enabled && (
          <section className="border-b border-rule px-6 py-4 max-sm:px-4">
            <p className="text-sm font-medium text-ink-2">External threat intel feeds are off, so feed polling is paused.</p>
            <p className="mt-1 text-ui text-muted">
              Threat intel agents and analysts can still post findings for your tech stack below. Turn external feeds on with these Function App settings (see docs/THREAT_INTEL.md):
            </p>
            <ul className="mt-2 flex flex-wrap gap-1.5">
              {data.sources
                .filter((s) => s.state !== "unavailable")
                .map((s) => (
                  <li key={s.id}>
                    <code className="label rounded-[4px] border border-rule px-1.5 py-0.5 text-ink-2">{s.flag}=true</code>
                  </li>
                ))}
            </ul>
          </section>
        )}
        {data?.fixture_mode && (
          <p className="border-b border-rule px-6 py-2 text-xs text-warning max-sm:px-4">Demo mode: every source is served from recorded fixtures (TI_FIXTURES_DIR).</p>
        )}
        {stale && (
          <p role="status" className="border-b border-rule px-6 py-2 text-xs text-warning max-sm:px-4">
            Warning: {stale.freshness?.freshness}. pwn.watch can go quiet for days; check the site before relying on it.
          </p>
        )}

        <FindingsSection watches={data?.watches ?? []} initial={data?.findings} />

        <WatchList watches={data?.watches ?? []} canEdit={!!data?.can_hunt} />

        <section aria-labelledby="recent-h" className="border-b border-rule">
          <h2 id="recent-h" className="label px-6 pb-1 pt-4 max-sm:px-4">
            Newest on your watchlists
          </h2>
          {data && data.recent.length === 0 && (
            <p className="px-6 pb-4 text-ui text-muted max-sm:px-4">
              {data.sources.some((s) => (s.id === "pwn.watch" || s.id === "cisa-kev") && s.enabled)
                ? "Nothing on your watchlists yet."
                : "pwn.watch and CISA KEV are off, so there is nothing to list."}
            </p>
          )}
          <ul>
            {data?.recent.map((r) => {
              const href = safeHref(r.url);
              return (
                <li key={`${r.source}:${r.key}`} className="border-t border-rule px-6 py-2.5 first:border-t-0 max-sm:px-4">
                  <div className="flex min-w-0 items-center gap-2">
                    <Tag>{r.source}</Tag>
                    {r.severity && <Tag tone={r.severity === "critical" || r.severity === "known exploited" ? "critical" : r.severity === "high" ? "warning" : "neutral"}>{r.severity}</Tag>}
                    {r.patch_status && <span className="label">patch: {r.patch_status}</span>}
                    <span className="ml-auto shrink-0">
                      <Time iso={r.updated_at ?? r.published_at ?? r.retrieved_at} />
                    </span>
                  </div>
                  <p className="mt-1 text-ui text-ink">
                    {href ? (
                      <a href={href} target="_blank" rel="noreferrer noopener" className="hover:text-accent">
                        {r.title ?? r.key}
                      </a>
                    ) : (
                      (r.title ?? r.key)
                    )}
                  </p>
                  <p className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                    {r.cve_ids.slice(0, 6).map((c) => (
                      <Link key={c} to={`/intel/${c}`} className="label tnum text-accent hover:underline">
                        {c}
                      </Link>
                    ))}
                    <span>watched: {r.watches.join(", ")}</span>
                    <span>{r.attribution}</span>
                  </p>
                </li>
              );
            })}
          </ul>
        </section>

        <SourcesTable sources={data?.sources ?? []} />
      </div>
    </>
  );
}

/** Structured Threat Intel findings table where bots and analysts post advisories tied to the org's tech stack. */
function FindingsSection({ watches, initial }: { watches: WatchRow[]; initial?: TiFinding[] }) {
  const [statusFilter, setStatusFilter] = useState<"open" | "all" | TiFinding["status"]>("open");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [stackFilter, setStackFilter] = useState<string>("all");
  const [searchText, setSearchText] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showForm, setShowForm] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const query = useMemo(() => {
    const p = new URLSearchParams();
    p.set("limit", "100");
    if (statusFilter !== "open" && statusFilter !== "all") p.set("status", statusFilter);
    if (severityFilter !== "all") p.set("severity", severityFilter);
    if (stackFilter !== "all") p.set("stack", stackFilter);
    return `/intel/findings?${p.toString()}`;
  }, [statusFilter, severityFilter, stackFilter]);

  const { data: queried } = useLiveQuery<TiFinding[]>(query);
  const allFindings = queried ?? initial ?? [];

  const stackOptions = useMemo(() => {
    const set = new Set<string>();
    for (const w of watches) if (w.enabled) set.add(w.value);
    for (const f of allFindings) for (const s of f.tech_stack) set.add(s);
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [watches, allFindings]);

  const rows = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    return allFindings.filter((f) => {
      if (statusFilter === "open" && (f.status === "mitigated" || f.status === "dismissed")) return false;
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        f.summary.toLowerCase().includes(q) ||
        f.source.toLowerCase().includes(q) ||
        f.tech_stack.some((s) => s.toLowerCase().includes(q)) ||
        f.cves.some((c) => c.toLowerCase().includes(q)) ||
        f.author.handle.toLowerCase().includes(q)
      );
    });
  }, [allFindings, statusFilter, searchText]);

  const updateStatus = async (id: string, status: TiFinding["status"]) => {
    setBusyId(id);
    setErr(null);
    try {
      await api(`/intel/findings/${id}/status`, { method: "POST", body: JSON.stringify({ status }) });
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section aria-labelledby="findings-h" className="border-b border-rule px-6 py-4 max-sm:px-4">
      <div className="flex flex-wrap items-center gap-2 pb-3">
        <div className="min-w-0 flex-1">
          <h2 id="findings-h" className="label text-ink-2">
            Threat intel findings ({rows.length})
          </h2>
          <p className="text-xs text-muted">
            Findings posted by threat intel bots and analysts pertaining to your configured tech stack and watchlists.
          </p>
        </div>
        <Button type="button" size="sm" variant={showForm ? "secondary" : "primary"} onClick={() => setShowForm((v) => !v)}>
          {showForm ? "Cancel" : "Post finding"}
        </Button>
      </div>

      {showForm && <PostFindingForm onDone={() => setShowForm(false)} />}

      <div className="flex flex-wrap items-center gap-2 pb-3">
        <Select aria-label="Filter by status" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as never)}>
          <option value="open">Open (new + reviewing)</option>
          <option value="all">All statuses</option>
          <option value="new">New</option>
          <option value="reviewing">Reviewing</option>
          <option value="mitigated">Mitigated</option>
          <option value="dismissed">Dismissed</option>
        </Select>
        <Select aria-label="Filter by severity" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </Select>
        <Select aria-label="Filter by tech stack" value={stackFilter} onChange={(e) => setStackFilter(e.target.value)}>
          <option value="all">All tech stack</option>
          {stackOptions.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
        <Input
          aria-label="Filter findings"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          placeholder="Search title, CVE, stack, source…"
          className="w-64 max-sm:w-full"
        />
        {err && <ErrorLine>{err}</ErrorLine>}
      </div>

      {rows.length === 0 ? (
        <div className="rounded-lg border border-rule bg-paper-2 px-4 py-6 text-center">
          <p className="text-sm font-medium text-ink-2">No matching threat intel findings yet</p>
          <p className="mt-1 text-xs text-muted">
            Configure your tech stack below — bots call <code className="font-mono text-ink-2">list_ti_watches</code> and publish relevant findings here via{" "}
            <code className="font-mono text-ink-2">post_ti_finding</code>.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-rule">
          <table className="w-full min-w-[880px] text-left text-xs">
            <thead className="label border-b border-rule bg-paper-2">
              <tr>
                <th className="w-24 px-3 py-2 font-normal">Severity</th>
                <th className="px-3 py-2 font-normal">Finding</th>
                <th className="w-52 px-3 py-2 font-normal">Tech stack</th>
                <th className="w-36 px-3 py-2 font-normal">CVEs</th>
                <th className="w-44 px-3 py-2 font-normal">Source / Author</th>
                <th className="w-32 px-3 py-2 font-normal">Status</th>
                <th className="w-24 px-3 py-2 text-right font-normal">Posted</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => {
                const isOpen = !!expanded[f.id];
                const href = safeHref(f.source_url);
                return (
                  <tr key={f.id} className="border-t border-rule align-top hover:bg-paper-2/60">
                    <td className="px-3 py-2.5">
                      <Tag tone={SEV_TONE[f.severity] ?? "neutral"}>{f.severity}</Tag>
                    </td>
                    <td className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() => setExpanded((e) => ({ ...e, [f.id]: !e[f.id] }))}
                        aria-expanded={isOpen}
                        className="text-left text-ui font-medium text-ink hover:text-accent"
                      >
                        {f.title}
                      </button>
                      <p className={cx("mt-0.5 text-xs text-muted [overflow-wrap:anywhere]", !isOpen && "line-clamp-2")}>{f.summary}</p>
                      {isOpen && (
                        <div className="mt-2 space-y-1.5 border-l-2 border-rule pl-3 text-xs">
                          {f.recommendation && (
                            <p className="text-ink-2">
                              <span className="label mr-1.5">Recommended action:</span>
                              {f.recommendation}
                            </p>
                          )}
                          {f.indicators.length > 0 && (
                            <div>
                              <span className="label block pb-0.5">Indicators ({f.indicators.length})</span>
                              <ul className="space-y-0.5 font-mono">
                                {f.indicators.map((ind, idx) => (
                                  <li key={`${ind.kind}:${ind.value}:${idx}`} className="flex flex-wrap items-center gap-2">
                                    <span className="text-faint">{ind.kind}</span>
                                    <Link to={`/intel/${encodeURIComponent(ind.value)}`} className="text-accent hover:underline">
                                      {ind.value}
                                    </Link>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                          <div className="flex flex-wrap items-center gap-3 pt-0.5">
                            {href && (
                              <a href={href} target="_blank" rel="noreferrer noopener" className="text-accent underline-offset-4 hover:underline">
                                Open source ↗
                              </a>
                            )}
                            {f.message_id && (
                              <Link to={`/channels/intel#m-${f.message_id}`} className="text-accent underline-offset-4 hover:underline">
                                Discuss in #intel
                              </Link>
                            )}
                            <RunPlaybookButton findingId={f.id} />
                          </div>
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {f.tech_stack.map((s) => (
                          <Tag key={s} tone={f.matched_watches.some((w) => w.toLowerCase().includes(s.toLowerCase())) ? "accent" : "neutral"}>
                            {s}
                          </Tag>
                        ))}
                        {f.tech_stack.length === 0 && f.matched_watches.map((w) => <Tag key={w} tone="accent">{w}</Tag>)}
                        {f.tech_stack.length === 0 && f.matched_watches.length === 0 && <span className="text-faint">—</span>}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {f.cves.length > 0 ? (
                          f.cves.map((c) => (
                            <Link key={c} to={`/intel/${encodeURIComponent(c)}`} className="label tnum text-accent hover:underline">
                              {c}
                            </Link>
                          ))
                        ) : (
                          <span className="text-faint">—</span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <p className="truncate font-medium text-ink-2">{f.source}</p>
                      <p className="mt-0.5 flex flex-wrap items-center gap-1 text-muted">
                        <span>@{f.author.handle}</span>
                        {f.author.kind === "agent" && <KindBadge kind="agent" />}
                        {f.confidence != null && <span className="tnum text-faint">· {Math.round(f.confidence * 100)}%</span>}
                      </p>
                    </td>
                    <td className="px-3 py-2.5">
                      <Select
                        aria-label={`Status for ${f.title}`}
                        value={f.status}
                        disabled={busyId === f.id}
                        onChange={(e) => void updateStatus(f.id, e.target.value as TiFinding["status"])}
                        className="h-8 w-full text-xs"
                      >
                        {STATUS_OPTIONS.map((st) => (
                          <option key={st} value={st}>
                            {st}
                          </option>
                        ))}
                      </Select>
                    </td>
                    <td className="tnum px-3 py-2.5 text-right">
                      <Time iso={f.created_at} />
                      {f.message_id && (
                        <Link to={`/channels/intel#m-${f.message_id}`} className="mt-0.5 block text-meta text-accent hover:underline">
                          #intel
                        </Link>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * "Run emerging-threat playbook": posts the emerging-threat-detection checklist (intel → exposure → hunt → detection →
 * human review) as claimable steps in a #intel thread for this finding. No incident is created; running it twice
 * opens the existing run.
 */
function RunPlaybookButton({ findingId }: { findingId: string }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api<{ root_message_id: string | null; existing: boolean }>(`/intel/findings/${findingId}/playbook`, { method: "POST", body: "{}" });
      refreshAll();
      navigate(`/channels/intel${r.root_message_id ? `#m-${r.root_message_id}` : ""}`);
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <>
      <Button size="sm" variant="secondary" disabled={busy} onClick={() => void run()} title="Post the emerging-threat-detection checklist in #intel for this finding">
        Run emerging-threat playbook
      </Button>
      {err && <ErrorLine>{err}</ErrorLine>}
    </>
  );
}

function PostFindingForm({ onDone }: { onDone: () => void }) {
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [severity, setSeverity] = useState<TiFinding["severity"]>("high");
  const [techStack, setTechStack] = useState("");
  const [cves, setCves] = useState("");
  const [source, setSource] = useState("analyst");
  const [sourceUrl, setSourceUrl] = useState("");
  const [recommendation, setRecommendation] = useState("");
  const [postToChannel, setPostToChannel] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const splitList = (s: string) =>
        s
          .split(/[,;\n]/)
          .map((x) => x.trim())
          .filter(Boolean);
      await api("/intel/findings", {
        method: "POST",
        body: JSON.stringify({
          title,
          summary,
          severity,
          tech_stack: splitList(techStack),
          cves: splitList(cves),
          source,
          source_url: sourceUrl.trim() || undefined,
          recommendation: recommendation.trim() || undefined,
          post_to_channel: postToChannel,
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
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_140px_180px]">
        <Input aria-label="Finding title" required value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title (e.g. Critical auth bypass in FortiOS SSL VPN)" />
        <Select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value as TiFinding["severity"])}>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="informational">informational</option>
        </Select>
        <Input aria-label="Source" required value={source} onChange={(e) => setSource(e.target.value)} placeholder="Source (e.g. CISA, vendor)" />
      </div>
      <textarea
        aria-label="Finding summary"
        required
        rows={3}
        value={summary}
        onChange={(e) => setSummary(e.target.value)}
        placeholder="Summary of impact, affected versions, and relevance to our environment…"
        className="w-full rounded-[var(--radius-control)] border border-control bg-paper px-2.5 py-2 text-ui text-ink placeholder:text-faint focus:border-accent focus:outline-none"
      />
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <Input aria-label="Tech stack" value={techStack} onChange={(e) => setTechStack(e.target.value)} placeholder="Tech stack (comma-separated, e.g. FortiOS, Entra ID)" />
        <Input aria-label="CVEs" value={cves} onChange={(e) => setCves(e.target.value)} placeholder="CVEs (comma-separated, e.g. CVE-2026-1234)" className="font-mono" />
        <Input aria-label="Source URL" value={sourceUrl} onChange={(e) => setSourceUrl(e.target.value)} placeholder="https://advisory.example/..." />
      </div>
      <Input aria-label="Recommended action" value={recommendation} onChange={(e) => setRecommendation(e.target.value)} placeholder="Recommended action / mitigation (optional)" className="w-full" />
      <div className="flex flex-wrap items-center gap-3 pt-1">
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={postToChannel} onChange={(e) => setPostToChannel(e.target.checked)} />
          Also cross-post summary to #intel
        </label>
        <div className="ml-auto flex items-center gap-2">
          {err && <ErrorLine>{err}</ErrorLine>}
          <Button type="submit" variant="primary" size="sm" loading={busy} disabled={!title.trim() || !summary.trim()}>
            Save finding
          </Button>
        </div>
      </div>
    </form>
  );
}

function SourcesTable({ sources }: { sources: SourceRow[] }) {
  return (
    <section aria-labelledby="sources-h" className="px-6 py-4 max-sm:px-4">
      <h2 id="sources-h" className="label pb-2">
        Sources
      </h2>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-xs">
          <thead className="label">
            <tr>
              <th className="py-1 pr-3 font-normal">Source</th>
              <th className="py-1 pr-3 font-normal">State</th>
              <th className="py-1 pr-3 font-normal">Setting</th>
              <th className="py-1 pr-3 font-normal">Last run</th>
              <th className="py-1 font-normal">Detail</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => {
              const home = safeHref(s.home);
              return (
                <tr key={s.id} className="border-t border-rule align-top">
                  <td className="py-1.5 pr-3">
                    {home ? (
                      <a href={home} target="_blank" rel="noreferrer noopener" className="text-ink-2 hover:text-accent">
                        {s.name}
                      </a>
                    ) : (
                      <span className="text-ink-2">{s.name}</span>
                    )}
                    <span className="label block">{s.mode}</span>
                  </td>
                  <td className="py-1.5 pr-3">
                    <Tag tone={STATE_TONE[s.state]}>{s.state}</Tag>
                  </td>
                  <td className="py-1.5 pr-3">
                    <code className="label text-ink-2">{s.flag}</code>
                    {s.permission && <span className="block text-faint">{s.permission}</span>}
                  </td>
                  <td className="tnum py-1.5 pr-3">{s.last_fetch_at ? <Time iso={s.last_fetch_at} /> : <span className="text-faint">never</span>}</td>
                  <td className={cx("py-1.5 [overflow-wrap:anywhere]", s.state === "failing" ? "text-critical" : "text-muted")}>
                    {s.freshness?.freshness && (
                      <span className={cx("block", s.freshness.stale && "text-warning")}>
                        {s.freshness.freshness}
                        {s.freshness.stale ? " (stale)" : ""}
                      </span>
                    )}
                    {s.last_error}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function WatchList({ watches, canEdit }: { watches: WatchRow[]; canEdit: boolean }) {
  const me = useMe();
  const [kind, setKind] = useState("stack");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (f: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await f();
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const existingValues = useMemo(() => new Set(watches.map((w) => w.value.toLowerCase())), [watches]);

  const groups: [string, WatchRow[]][] = [
    ["Configured tech stack", watches.filter((w) => w.kind === "stack" || w.kind === "vendor")],
    ["Product, CVE, tag & keyword watches", watches.filter((w) => w.origin !== "inventory" && w.kind !== "stack" && w.kind !== "vendor")],
    ["From Defender inventory", watches.filter((w) => w.origin === "inventory")],
  ];

  return (
    <section aria-labelledby="watch-h" className="border-b border-rule px-6 py-4 max-sm:px-4">
      <h2 id="watch-h" className="label text-ink-2">
        Tech stack &amp; watchlists
      </h2>
      <p className="pb-2.5 text-xs text-muted">
        Configure the technologies, vendors, products, CVEs, and keywords your organisation runs. Threat intel bots read this list (<code className="font-mono">list_ti_watches</code>) and post matching findings into the table above; enabled pwn.watch and KEV items also match against it.
      </p>
      {canEdit && me && (
        <>
          <form
            className="flex flex-wrap items-center gap-2 pb-2.5"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await api("/intel/watches", { method: "POST", body: JSON.stringify({ kind, value, label: label.trim() || undefined }) });
                setValue("");
                setLabel("");
              });
            }}
          >
            <Select aria-label="Watch kind" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="stack">tech stack</option>
              <option value="vendor">vendor</option>
              <option value="product">product</option>
              <option value="tag">tag</option>
              <option value="cve">cve</option>
              <option value="keyword">keyword</option>
            </Select>
            <Input aria-label="Watch value" value={value} onChange={(e) => setValue(e.target.value)} placeholder="e.g. FortiOS, Entra ID, PostgreSQL" className="w-60" />
            <Input aria-label="Optional category or note" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Category / note (optional)" className="w-44" />
            <Button type="submit" size="md" loading={busy} disabled={!value.trim()}>
              Add
            </Button>
            {err && <ErrorLine>{err}</ErrorLine>}
          </form>

          <div className="flex flex-wrap items-center gap-1.5 pb-3">
            <span className="label pr-1">Quick add stack:</span>
            {STACK_PRESETS.filter((p) => !existingValues.has(p.value.toLowerCase())).map((p) => (
              <button
                key={p.value}
                type="button"
                disabled={busy}
                onClick={() => void run(() => api("/intel/watches", { method: "POST", body: JSON.stringify({ kind: "stack", value: p.value, label: p.label }) }))}
                className="rounded-full border border-rule bg-paper-2 px-2 py-0.5 text-meta text-muted transition-colors hover:border-accent hover:text-ink disabled:opacity-50"
              >
                + {p.value}
              </button>
            ))}
          </div>
        </>
      )}

      {groups.map(([title, list]) => (
        <div key={title} className="pb-3 last:pb-0">
          <p className="label pb-1 text-ink-2">{title}</p>
          {list.length === 0 && <p className="text-xs text-faint">None.</p>}
          <ul className="flex flex-wrap gap-1.5">
            {list.map((w) => (
              <li key={w.id} className={cx("flex items-center gap-1.5 rounded-[4px] border border-rule bg-paper-2 px-2 py-1 text-xs", !w.enabled && "opacity-60")}>
                <span className="label">{w.kind}</span>
                <span className="text-ink-2" title={w.label ?? undefined}>
                  {w.value}
                </span>
                {w.label && <span className="text-faint">({w.label})</span>}
                {!w.enabled && <span className="label">off</span>}
                {canEdit && (
                  <>
                    <button
                      type="button"
                      disabled={busy}
                      className="label hover:text-accent disabled:opacity-50"
                      onClick={() => void run(() => api(`/intel/watches/${w.id}`, { method: "POST", body: JSON.stringify({ enabled: !w.enabled }) }))}
                      aria-label={`${w.enabled ? "Turn off" : "Turn on"} watch ${w.kind} ${w.value}`}
                    >
                      {w.enabled ? "off" : "on"}
                    </button>
                    {w.origin !== "inventory" && (
                      <button
                        type="button"
                        disabled={busy}
                        className="label text-faint hover:text-critical disabled:opacity-50"
                        onClick={() => void run(() => api(`/intel/watches/${w.id}`, { method: "DELETE" }))}
                        aria-label={`Remove watch ${w.kind} ${w.value}`}
                        title="Remove"
                      >
                        ×
                      </button>
                    )}
                  </>
                )}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}
