import { Link, useParams } from "react-router";
import { useState, type ReactNode } from "react";
import { PageHeader } from "../components/shell";
import { MessageRow } from "../components/message";
import { Markdown } from "../components/markdown";
import { BadgeTags, pct, useCveBadge } from "../components/cve";
import { api, refreshAll, useLiveQuery, type Message } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Severity, Tag, Time } from "../components/ui";

type Card = {
  source: string;
  name: string;
  status: "found" | "not_found" | "not_checked";
  attribution: string;
  url: string | null;
  retrieved_at: string | null;
  title: string | null;
  severity: string | null;
  data: Record<string, any> | null;
  reason: string | null;
};
type Lookup = {
  key: string;
  kind: string;
  cards: Card[];
  agree: string[];
  differ: string[];
  incidents: { id: string; graph_id: string; display_name: string; severity: string; status: string }[];
  messages: Message[];
  checked_at: string;
};

const STATUS: Record<Card["status"], { label: string; tone: "good" | "neutral" | "warning" }> = {
  found: { label: "has a record", tone: "good" },
  not_found: { label: "no record", tone: "neutral" },
  not_checked: { label: "not checked", tone: "warning" },
};

/** One CVE or indicator: a card per source, agree / differ, related board incidents and messages. */
export default function IntelKeyPage() {
  const { key = "" } = useParams();
  const { data, error } = useLiveQuery<Lookup>(`/intel/lookup?key=${encodeURIComponent(key)}`);
  const badge = useCveBadge(key.toUpperCase());
  const [posting, setPosting] = useState(false);
  const [postErr, setPostErr] = useState<string | null>(null);
  const [posted, setPosted] = useState<string | null>(null);

  if (error) return <Empty title={`Couldn't look up ${key}`}>{error.message}</Empty>;
  const post = async () => {
    setPosting(true);
    setPostErr(null);
    try {
      const m = await api<Message>("/intel/post", { method: "POST", body: JSON.stringify({ key }) });
      setPosted(m.id);
      refreshAll();
    } catch (e) {
      setPostErr((e as Error).message);
    } finally {
      setPosting(false);
    }
  };

  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Link to="/intel" className="label hover:text-accent">
              Intel
            </Link>
            <span className="label">/</span>
            <span className="tnum">{data?.key ?? key}</span>
            {data && <Tag>{data.kind}</Tag>}
            {badge && <BadgeTags b={badge} />}
          </span>
        }
        sub={data ? <>Checked <Time iso={data.checked_at} />. Outside text is shown as quoted data.</> : " "}
      >
        {posted ? (
          <Link to="/?channel=intel" className="text-[13px] text-accent underline-offset-4 hover:underline">
            Posted to #intel
          </Link>
        ) : (
          <Button onClick={() => void post()} loading={posting} disabled={!data}>
            Post to #intel
          </Button>
        )}
        {postErr && <ErrorLine>{postErr}</ErrorLine>}
      </PageHeader>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {!data && <p className="px-5 py-4 text-[13px] text-muted">Checking every enabled source…</p>}
        {data && (
          <>
            {(data.agree.length > 0 || data.differ.length > 0) && (
              <section aria-label="Agree and differ" className="border-b border-rule px-5 py-3 text-[13px]">
                {data.agree.map((a) => (
                  <p key={a}>
                    <span className="label mr-2 text-good">agree</span>
                    {a}
                  </p>
                ))}
                {data.differ.map((d) => (
                  <p key={d}>
                    <span className="label mr-2 text-warning">differ</span>
                    {d}
                  </p>
                ))}
              </section>
            )}
            <section aria-label="Sources" className="border-b border-rule">
              {data.cards.map((c) => (
                <SourceCard key={c.source} c={c} />
              ))}
            </section>
            <section aria-labelledby="rel-h" className="px-5 py-4">
              <h2 id="rel-h" className="label pb-2">
                On the board
              </h2>
              {data.incidents.length === 0 && data.messages.length === 0 && <p className="text-[13px] text-muted">No incident or message mentions {data.key}.</p>}
              <ul className="space-y-1 pb-2">
                {data.incidents.map((i) => (
                  <li key={i.id} className="flex items-center gap-2 text-[13px]">
                    <Severity value={i.severity} />
                    <Link to={`/incidents/${i.id}`} className="label tnum text-ink-2 hover:text-accent">
                      INC {i.graph_id}
                    </Link>
                    <span className="truncate text-muted">{i.display_name}</span>
                    <span className="label">{i.status}</span>
                  </li>
                ))}
              </ul>
            </section>
            {data.messages.map((m) => (
              <MessageRow key={m.id} m={m} showChannel />
            ))}
          </>
        )}
      </div>
    </>
  );
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 py-0.5">
      <dt className="label w-36 shrink-0">{k}</dt>
      <dd className="min-w-0 text-ink-2 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

const list = (v: unknown) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []) as string[];

function Details({ c }: { c: Card }) {
  const d = c.data ?? {};
  switch (c.source) {
    case "pwn.watch":
      return (
        <>
          {d.freshness && <Row k="freshness"><span className={cx(d.stale && "text-warning")}>{d.freshness}{d.stale ? " (stale)" : ""}</span></Row>}
          <Row k="patch status">{d.patch_status ?? "unknown"}</Row>
          {list(d.fixed_versions).length > 0 && <Row k="fixed versions">{list(d.fixed_versions).join("; ")}</Row>}
          {list(d.affected_versions).length > 0 && <Row k="affected">{list(d.affected_versions).join("; ")}</Row>}
          {d.product && <Row k="product">{d.product}</Row>}
          {d.started_at && <Row k="started">{d.started_at}</Row>}
          {d.summary && <Quoted text={d.summary} />}
          <PwnBrief slug={d.slug} />
        </>
      );
    case "cisa-kev":
      return (
        <>
          <Row k="known exploited">yes{d.known_ransomware ? ", used in ransomware campaigns" : ""}</Row>
          <Row k="vendor / product">{[d.vendor, d.product].filter(Boolean).join(" / ")}</Row>
          <Row k="date added">{d.date_added}</Row>
          <Row k="due date">{d.due_date}</Row>
          <Row k="required action">{d.required_action}</Row>
          {d.short_description && <Quoted text={d.short_description} />}
        </>
      );
    case "first-epss":
      return (
        <>
          <Row k="EPSS">
            {pct(d.epss)} likelihood of exploitation in the next 30 days (percentile {Math.floor((d.percentile ?? 0) * 100)})
          </Row>
          <Row k="score date">{d.date}</Row>
          <p className="pt-1 text-xs text-faint">A probability, not a verdict.</p>
        </>
      );
    case "nvd":
      return (
        <>
          {d.cvss && (
            <Row k={`CVSS ${d.cvss.version}`}>
              {d.cvss.score} {d.cvss.severity} <span className="label">{d.cvss.vector}</span>
            </Row>
          )}
          {list(d.cwes).length > 0 && <Row k="CWE">{list(d.cwes).join(", ")}</Row>}
          <Row k="published / modified">{d.published?.slice(0, 10)} / {d.last_modified?.slice(0, 10)}</Row>
          {d.description && <Quoted text={d.description} />}
        </>
      );
    case "osv":
      return (
        <>
          {list(d.aliases).length > 0 && <Row k="aliases">{list(d.aliases).join(", ")}</Row>}
          {(d.packages ?? []).slice(0, 10).map((p: any, i: number) => (
            <Row key={i} k={p.ecosystem ?? "package"}>
              {p.name}: {list(p.fixed).length > 0 ? `fixed in ${list(p.fixed).join(", ")}` : "no fixed version listed"}
            </Row>
          ))}
          {d.packages_from && <p className="text-xs text-faint">Package versions from {d.packages_from}.</p>}
        </>
      );
    case "sentinel-ti":
      return (
        <>
          {(d.matches ?? []).slice(0, 10).map((m: any) => (
            <Row key={m.id} k={m.observable_key ?? "indicator"}>
              confidence {m.confidence ?? "unknown"} · {m.source_system ?? "unknown source"}
              {m.valid_until ? ` · valid until ${String(m.valid_until).slice(0, 10)}` : ""}
              {m.name ? ` · ${m.name}` : ""}
            </Row>
          ))}
        </>
      );
    case "microsoft-ti":
      return d.host ? (
        <>
          <Row k="reputation">{d.classification ?? "unknown"} (score {d.score ?? "?"})</Row>
          {(d.rules ?? []).slice(0, 5).map((r: any, i: number) => (
            <Row key={i} k={r.severity ?? "rule"}>{r.name}</Row>
          ))}
        </>
      ) : (
        <>
          <Row k="severity">{d.severity} {d.priority_score != null ? `(priority ${d.priority_score})` : ""}</Row>
          <Row k="exploitation">
            {d.active_exploits_observed ? "active exploits observed" : "no active exploits observed"}
            {d.exploits_available ? ", public exploits available" : ""}
          </Row>
          {d.cvss3_score != null && <Row k="CVSS 3">{d.cvss3_score} <span className="label">{d.cvss3_vector}</span></Row>}
          {(d.articles ?? []).length > 0 && <Row k="articles">{d.articles.map((a: any) => a.title).join("; ")}</Row>}
          {d.remediation && <Quoted text={d.remediation} />}
        </>
      );
    case "defender-tvm":
      return (
        <>
          <Row k="devices">
            {d.devices} {d.devices > list(d.device_names).length ? `(showing ${list(d.device_names).length})` : ""}
          </Row>
          {list(d.device_names).length > 0 && <Row k="device names">{list(d.device_names).join(", ")}</Row>}
          {list(d.software).length > 0 && <Row k="software">{list(d.software).join("; ")}</Row>}
          {list(d.remediation).length > 0 && <Row k="remediation">{list(d.remediation).join("; ")}</Row>}
          {d.age_seconds != null && <Row k="checked">{Math.round(d.age_seconds / 60)} min ago (cached 6 h)</Row>}
        </>
      );
    default:
      return null;
  }
}

function Quoted({ text }: { text: string }) {
  return (
    <div className="mt-1.5">
      <Markdown text={text.split("\n").map((l) => `> ${l}`).join("\n")} />
    </div>
  );
}

/** pwn.watch's agent brief: fetched only when asked for, and shown as quoted, untrusted text. */
function PwnBrief({ slug }: { slug?: string }) {
  const [brief, setBrief] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!slug) return null;
  if (brief !== null)
    return (
      <details open className="mt-2">
        <summary className="label cursor-pointer">pwn.watch brief (outside text, quoted as data)</summary>
        <Quoted text={brief || "No brief."} />
      </details>
    );
  return (
    <div className="mt-1.5 flex items-center gap-2">
      <Button
        size="sm"
        variant="ghost"
        className="-ml-2.5"
        loading={busy}
        onClick={async () => {
          setBusy(true);
          try {
            setBrief((await api<{ brief: string | null }>(`/intel/pwnwatch/${encodeURIComponent(slug)}`)).brief ?? "");
          } catch (e) {
            setErr((e as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        Show remediation brief
      </Button>
      {err && <ErrorLine>{err}</ErrorLine>}
    </div>
  );
}

function SourceCard({ c }: { c: Card }) {
  const s = STATUS[c.status];
  return (
    <article className="border-t border-rule px-5 py-3 first:border-t-0">
      <header className="flex min-w-0 flex-wrap items-center gap-2">
        <h3 className="text-[13px] font-medium text-ink">{c.name}</h3>
        <Tag tone={s.tone}>{s.label}</Tag>
        {c.severity && c.status === "found" && <Tag>{c.severity}</Tag>}
        <span className="ml-auto flex shrink-0 items-center gap-3">
          {c.retrieved_at && c.status !== "not_checked" && (
            <span className="label">
              retrieved <Time iso={c.retrieved_at} />
            </span>
          )}
          {c.url && (
            <a href={c.url} target="_blank" rel="noreferrer noopener" className="whitespace-nowrap text-xs text-accent underline-offset-4 hover:underline">
              Open source ↗
            </a>
          )}
        </span>
      </header>
      {c.title && c.status !== "not_checked" && <p className="mt-1 text-[13px] text-ink-2">{c.title}</p>}
      {c.status === "not_checked" && <p className="mt-1 text-xs text-muted">Not checked: {c.reason}. This is not the same as "no data".</p>}
      {c.status === "found" && (
        <dl className="mt-1.5 text-xs">
          <Details c={c} />
        </dl>
      )}
      <p className="label mt-1.5">{c.attribution}</p>
    </article>
  );
}
