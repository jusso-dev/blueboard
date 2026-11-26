import { Link, useNavigate } from "react-router";
import { useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, refreshAll, useLiveQuery } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Input, Select, Tag, Time } from "../components/ui";

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
type WatchRow = { id: string; kind: string; value: string; enabled: boolean; origin: "default" | "manual" | "inventory"; label: string | null };
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
type Index = { any_enabled: boolean; fixture_mode: boolean; can_hunt: boolean; sources: SourceRow[]; watches: WatchRow[]; recent: Recent[] };

const STATE_TONE: Record<SourceRow["state"], "good" | "neutral" | "critical" | "warning"> = {
  ok: "good",
  off: "neutral",
  failing: "critical",
  "not run yet": "warning",
  unavailable: "neutral",
};

/** Threat intel: look up a CVE or indicator, newest watched records, source setup and watchlists. */
export default function IntelPage() {
  const { data, error } = useLiveQuery<Index>("/intel");
  const navigate = useNavigate();
  const [key, setKey] = useState("");

  if (error) return <Empty title="Couldn't load threat intel">{error.message}</Empty>;
  const stale = data?.sources.find((s) => s.id === "pwn.watch" && s.enabled && s.freshness?.stale);

  return (
    <>
      <PageHeader title="Threat intel" sub="Outside feeds and this tenant's intel, side by side. Every card names its source.">
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
          <section className="border-b border-rule px-6 max-sm:px-4 py-4">
            <p className="text-sm font-medium text-ink-2">Every threat intel source is off, so nothing is fetched.</p>
            <p className="mt-1 text-ui text-muted">
              Turn sources on with these Function App settings, then each card below changes from "off" to its status. See docs/THREAT_INTEL.md.
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
          <p className="border-b border-rule px-6 max-sm:px-4 py-2 text-xs text-warning">Demo mode: every source is served from recorded fixtures (TI_FIXTURES_DIR).</p>
        )}
        {stale && (
          <p role="status" className="border-b border-rule px-6 max-sm:px-4 py-2 text-xs text-warning">
            Warning: {stale.freshness?.freshness}. pwn.watch can go quiet for days; check the site before relying on it.
          </p>
        )}

        <section aria-labelledby="recent-h" className="border-b border-rule">
          <h2 id="recent-h" className="label px-6 max-sm:px-4 pb-1 pt-4">
            Newest on your watchlists
          </h2>
          {data && data.recent.length === 0 && (
            <p className="px-6 max-sm:px-4 pb-4 text-ui text-muted">
              {data.sources.some((s) => (s.id === "pwn.watch" || s.id === "cisa-kev") && s.enabled)
                ? "Nothing on your watchlists yet."
                : "pwn.watch and CISA KEV are off, so there is nothing to list."}
            </p>
          )}
          <ul>
            {data?.recent.map((r) => (
              <li key={`${r.source}:${r.key}`} className="border-t border-rule px-6 max-sm:px-4 py-2.5 first:border-t-0">
                <div className="flex min-w-0 items-center gap-2">
                  <Tag>{r.source}</Tag>
                  {r.severity && <Tag tone={r.severity === "critical" || r.severity === "known exploited" ? "critical" : r.severity === "high" ? "warning" : "neutral"}>{r.severity}</Tag>}
                  {r.patch_status && <span className="label">patch: {r.patch_status}</span>}
                  <span className="ml-auto shrink-0">
                    <Time iso={r.updated_at ?? r.published_at ?? r.retrieved_at} />
                  </span>
                </div>
                <p className="mt-1 text-ui text-ink">
                  {r.url ? (
                    <a href={r.url} target="_blank" rel="noreferrer noopener" className="hover:text-accent">
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
            ))}
          </ul>
        </section>

        <SourcesTable sources={data?.sources ?? []} />
        <WatchList watches={data?.watches ?? []} canEdit={!!data?.can_hunt} />
      </div>
    </>
  );
}

function SourcesTable({ sources }: { sources: SourceRow[] }) {
  return (
    <section aria-labelledby="sources-h" className="border-b border-rule px-6 max-sm:px-4 py-4">
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
            {sources.map((s) => (
              <tr key={s.id} className="border-t border-rule align-top">
                <td className="py-1.5 pr-3">
                  <a href={s.home} target="_blank" rel="noreferrer noopener" className="text-ink-2 hover:text-accent">
                    {s.name}
                  </a>
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
                  {s.freshness?.freshness && <span className={cx("block", s.freshness.stale && "text-warning")}>{s.freshness.freshness}{s.freshness.stale ? " (stale)" : ""}</span>}
                  {s.last_error}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function WatchList({ watches, canEdit }: { watches: WatchRow[]; canEdit: boolean }) {
  const me = useMe();
  const [kind, setKind] = useState("product");
  const [value, setValue] = useState("");
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
  const groups: [string, WatchRow[]][] = [
    ["Defaults and yours", watches.filter((w) => w.origin !== "inventory")],
    ["From Defender inventory", watches.filter((w) => w.origin === "inventory")],
  ];
  return (
    <section aria-labelledby="watch-h" className="px-6 max-sm:px-4 py-4">
      <h2 id="watch-h" className="label">
        Watchlists
      </h2>
      <p className="pb-2 text-xs text-muted">pwn.watch and KEV items matching an enabled watch are listed above and posted once to #intel.</p>
      {canEdit && me && (
        <form
          className="flex flex-wrap items-center gap-2 pb-3"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              await api("/intel/watches", { method: "POST", body: JSON.stringify({ kind, value }) });
              setValue("");
            });
          }}
        >
          <Select aria-label="Watch kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="product">product</option>
            <option value="tag">tag</option>
            <option value="cve">cve</option>
            <option value="keyword">keyword</option>
          </Select>
          <Input aria-label="Watch value" value={value} onChange={(e) => setValue(e.target.value)} placeholder="e.g. fortios, ransomware" className="w-56" />
          <Button type="submit" size="md" loading={busy} disabled={!value.trim()}>
            Add watch
          </Button>
          {err && <ErrorLine>{err}</ErrorLine>}
        </form>
      )}
      {groups.map(([title, list]) => (
        <div key={title} className="pb-3">
          <p className="label pb-1 text-ink-2">{title}</p>
          {list.length === 0 && <p className="text-xs text-faint">None.</p>}
          <ul className="flex flex-wrap gap-1.5">
            {list.map((w) => (
              <li key={w.id} className={cx("flex items-center gap-1.5 rounded-[4px] border border-rule px-2 py-1 text-xs", !w.enabled && "opacity-60")}>
                <span className="label">{w.kind}</span>
                <span className="text-ink-2" title={w.label ?? undefined}>
                  {w.value}
                </span>
                {!w.enabled && <span className="label">off</span>}
                {canEdit && (
                  <button
                    type="button"
                    disabled={busy}
                    className="label hover:text-accent disabled:opacity-50"
                    onClick={() => void run(() => api(`/intel/watches/${w.id}`, { method: "POST", body: JSON.stringify({ enabled: !w.enabled }) }))}
                    aria-label={`${w.enabled ? "Turn off" : "Turn on"} watch ${w.kind} ${w.value}`}
                  >
                    {w.enabled ? "turn off" : "turn on"}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}
