import { useMemo, useState } from "react";
import { useParams } from "react-router";
import { Feed } from "../components/feed";
import { PageHeader } from "../components/shell";
import { usePaletteCommands } from "../components/shortcuts";
import { CopySummaryButton, SummaryPanel } from "../components/summary";
import { useLiveQuery, type IncidentSummary, type SummaryEntity } from "../lib/api";
import { statusWords } from "../lib/queue";
import { targetsFromEntities, type ActionTarget, type IncidentEntities } from "../lib/actions";
import { RequestActionButton, useCanRequest } from "../components/request-action";
import { safeHref } from "../lib/gifs";
import { Button, Empty, Severity, useStoredState } from "../components/ui";
import { CveRef } from "../components/cve";
import { TraceList } from "../components/agent-trace";
import type { TraceCall } from "../lib/agents";

type IncidentDetail = {
  id: string;
  graph_id: string;
  display_name: string;
  severity: string;
  status: string;
  web_url: string | null;
  alerts: { id: string; title?: string }[];
  entities: IncidentEntities;
  summary: IncidentSummary;
  cves?: { cve: string }[];
};

export default function IncidentPage() {
  const { id = "" } = useParams();
  const { data: inc, error } = useLiveQuery<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`);
  const [thread, setThread] = useState<string | null>(null);
  const markdown = inc?.summary.markdown;
  const commands = useMemo(
    () => (markdown ? [{ id: "copy-summary", label: "Copy summary (Markdown)", run: () => void navigator.clipboard.writeText(markdown) }] : null),
    [markdown],
  );
  usePaletteCommands("incident", commands);

  const canRequest = useCanRequest();
  const [summary, setSummary] = useStoredState<"shown" | "hidden">("bb_incident_summary", () =>
    // Short or narrow screens start with the summary folded so the feed keeps most of the height.
    typeof window !== "undefined" && (window.innerHeight < 720 || window.innerWidth < 640) ? "hidden" : "shown",
  );
  const targets = useMemo(() => (inc ? targetsFromEntities(inc.entities, inc.graph_id) : []), [inc]);
  if (error) return <Empty title="Couldn't load this incident">{error.message}</Empty>;
  if (!inc) return null;
  const e = inc.entities;
  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Severity value={inc.severity} />
            <span className="label tnum text-ink-2">INC {inc.graph_id}</span>
            <span className="truncate">{inc.display_name}</span>
          </span>
        }
        sub={
          <span className="tnum">
            {statusWords(inc.status)} · {inc.alerts.length} alerts · {e.devices.length} devices · {e.users.length} users · {e.ips.length} IPs · {e.files.length} files
            {e.mitre.length > 0 && <> · {e.mitre.join(", ")}</>}
            {inc.cves && inc.cves.length > 0 && (
              <>
                {" · "}
                {inc.cves.slice(0, 5).map((c, i) => (
                  <span key={c.cve}>
                    {i > 0 && ", "}
                    <CveRef id={c.cve} />
                  </span>
                ))}
              </>
            )}
          </span>
        }
      >
        <Button size="sm" variant="ghost" aria-expanded={summary === "shown"} aria-controls="incident-summary" onClick={() => setSummary(summary === "shown" ? "hidden" : "shown")}>
          {summary === "shown" ? "Hide summary" : "Show summary"}
        </Button>
        <RequestActionButton targets={targets} incident={inc.id} />
        <CopySummaryButton markdown={inc.summary.markdown} />
        {safeHref(inc.web_url) && (
          <a
            href={safeHref(inc.web_url)!}
            target="_blank"
            rel="noreferrer noopener"
            className="whitespace-nowrap text-ui text-accent underline-offset-4 hover:underline"
          >
            Open in Defender ↗
          </a>
        )}
      </PageHeader>
      {/* Capped so the feed always keeps most of the height; it scrolls on its own when the roll-up is long. */}
      <div id="incident-summary" hidden={summary === "hidden"} className="max-h-[38dvh] shrink-0 overflow-y-auto overflow-x-hidden">
        <SummaryPanel
          s={inc.summary}
          onOpenThread={setThread}
          entityAction={canRequest ? (ent) => <EntityAction entity={ent} targets={targets} incident={inc.id} /> : undefined}
        />
        <IncidentTrace id={inc.id} />
      </div>
      <Feed
        query={`incident=${inc.id}`}
        composer={{ channel: "incidents", incident: inc.id, placeholder: `Message about INC ${inc.graph_id}` }}
        emptyTitle="No messages linked to this incident yet"
        showChannel
        label={`INC ${inc.graph_id}`}
        thread={thread}
        onThread={setThread}
      />
    </>
  );
}

/** Every agent MCP call linked to this incident, fetched when opened (how the agents got to their conclusions). */
function IncidentTrace({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const { data, error } = useLiveQuery<TraceCall[]>(open ? `/incidents/${id}/trace` : null);
  return (
    <details className="border-b border-rule px-6 py-2 max-sm:px-4" onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="cursor-pointer text-sm font-semibold text-ink-2 hover:text-ink">Agent trace{data ? ` (${data.length} calls)` : ""}</summary>
      <div className="mt-2 max-h-[40dvh] overflow-y-auto">
        {error && <p className="text-xs text-critical">{error.message}</p>}
        {data && <TraceList calls={data} showAgent />}
      </div>
    </details>
  );
}

/** "Act" next to a user or device chip in the summary: the request form, pre-filled with that entity. */
function EntityAction({ entity, targets, incident }: { entity: SummaryEntity; targets: ActionTarget[]; incident: string }) {
  const t = targets.find(
    (x) =>
      x.type === entity.kind &&
      (x.label === entity.label || Object.values(x.params).some((v) => typeof v === "string" && v.toLowerCase() === entity.id.toLowerCase())),
  );
  return t ? <RequestActionButton targets={[t]} incident={incident} size="sm" label="Act" /> : null;
}
