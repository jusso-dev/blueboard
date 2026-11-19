import { useParams } from "react-router";
import { Feed } from "../components/feed";
import { PageHeader } from "../components/shell";
import { useLiveQuery } from "../lib/api";
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
  entities: { devices: unknown[]; users: unknown[]; ips: string[]; files: unknown[]; mitre: string[] };
  cves?: { cve: string }[];
};

export default function IncidentPage() {
  const { id = "" } = useParams();
  const { data: inc, error } = useLiveQuery<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`);
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
            {inc.status} · {inc.alerts.length} alerts · {e.devices.length} devices · {e.users.length} users · {e.ips.length} IPs · {e.files.length} files
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
      <Feed
        query={`incident=${inc.id}`}
        composer={{ channel: "incidents", incident: inc.id, placeholder: `Message about INC ${inc.graph_id}` }}
        emptyTitle="No messages linked to this incident yet"
        showChannel
      />
    </>
  );
}
