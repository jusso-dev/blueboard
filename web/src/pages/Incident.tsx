import { useMemo } from "react";
import { useParams } from "react-router";
import { Feed } from "../components/feed";
import { PageHeader } from "../components/shell";
import { useLiveQuery } from "../lib/api";
import { targetsFromEntities, type IncidentEntities } from "../lib/actions";
import { RequestActionButton, useCanRequest } from "../components/request-action";
import { Empty, Severity } from "../components/ui";

type IncidentDetail = {
  id: string;
  graph_id: string;
  display_name: string;
  severity: string;
  status: string;
  web_url: string | null;
  alerts: { id: string; title?: string }[];
  entities: IncidentEntities;
};

export default function IncidentPage() {
  const { id = "" } = useParams();
  const { data: inc, error } = useLiveQuery<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`);
  const canRequest = useCanRequest();
  const targets = useMemo(() => (inc ? targetsFromEntities(inc.entities, inc.graph_id) : []), [inc]);
  if (error) return <Empty title="Couldn't load this incident">{error.message}</Empty>;
  if (!inc) return null;
  const e = inc.entities;
  const entityTargets = targets.filter((t) => t.type !== "incident");
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
            {inc.status} · {inc.alerts.length} alerts · {e.devices.length} devices · {e.users.length} users · {e.ips.length} IPs · {e.files.length} files
            {e.mitre.length > 0 && <> · {e.mitre.join(", ")}</>}
          </span>
        }
      >
        <RequestActionButton targets={targets} incident={inc.id} />
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
      {canRequest && entityTargets.length > 0 && (
        <section aria-label="Evidence you can act on" className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-rule px-5 py-1.5">
          {entityTargets.map((t, i) => (
            <span key={i} className="inline-flex min-w-0 items-center gap-1">
              <span className="label">{t.type}</span>
              <span className="max-w-64 truncate font-mono text-xs text-ink-2" title={t.label}>
                {t.label}
              </span>
              <RequestActionButton targets={[t]} incident={inc.id} size="sm" label="Act" />
            </span>
          ))}
        </section>
      )}
      <Feed
        query={`incident=${inc.id}`}
        composer={{ channel: "incidents", incident: inc.id, placeholder: `Message about INC ${inc.graph_id}` }}
        emptyTitle="No messages linked to this incident yet"
        showChannel
      />
    </>
  );
}
