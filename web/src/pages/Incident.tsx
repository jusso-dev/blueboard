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
import { Empty, Severity } from "../components/ui";
import { CveRef } from "../components/cve";

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
        <RequestActionButton targets={targets} incident={inc.id} />
        <CopySummaryButton markdown={inc.summary.markdown} />
        {inc.web_url && (
          <a
            href={inc.web_url}
            target="_blank"
            rel="noreferrer noopener"
            className="whitespace-nowrap text-[13px] text-accent underline-offset-4 hover:underline"
          >
            Open in Defender ↗
          </a>
        )}
      </PageHeader>
      <SummaryPanel
        s={inc.summary}
        onOpenThread={setThread}
        entityAction={canRequest ? (ent) => <EntityAction entity={ent} targets={targets} incident={inc.id} /> : undefined}
      />
      <Feed
        query={`incident=${inc.id}`}
        composer={{ channel: "incidents", incident: inc.id, placeholder: `Message about INC ${inc.graph_id}` }}
        emptyTitle="No messages linked to this incident yet"
        showChannel
        thread={thread}
        onThread={setThread}
      />
    </>
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
