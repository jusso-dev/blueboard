import { Link } from "react-router";
import { PageHeader, useMe } from "../components/shell";
import { RequestActionButton } from "../components/request-action";
import { useLiveQuery } from "../lib/api";
import { remediationTargets, scoreBand, type ExposureItem } from "../lib/exposure";
import { Empty, Severity, Tag } from "../components/ui";

/**
 * Exposure (Board.Hunt): the tenant's vulnerabilities ranked by what makes them urgent (KEV, public exploit,
 * internet-facing, high-value devices, devices already in open incidents), each with a "Request remediation" button
 * that files an Intune action through the normal request → policy → approval flow.
 */
export default function ExposurePage() {
  const me = useMe();
  const canHunt = !!me?.roles.includes("hunter");
  const { data, error } = useLiveQuery<ExposureItem[]>(canHunt ? "/exposure/prioritized?limit=50" : null);
  if (me && !canHunt) {
    return (
      <>
        <PageHeader title="Exposure" />
        <Empty title="Exposure needs Board.Hunt">Ask an admin for the Board.Hunt role.</Empty>
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Exposure"
        sub="Vulnerabilities from Defender Vulnerability Management, ranked by known exploitation, public exploits, internet exposure, device value and open incidents."
      />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't load exposures">{error.message}</Empty>}
        {data && data.length === 0 && <Empty title="No exposures found">Defender Vulnerability Management reported no critical, high or medium vulnerabilities.</Empty>}
        {data && data.length > 0 && (
          <ol aria-label="Prioritised exposures" className="divide-y divide-rule">
            {data.map((x, i) => (
              <ExposureRow key={x.id} item={x} rank={i + 1} />
            ))}
          </ol>
        )}
      </div>
    </>
  );
}

function ExposureRow({ item: x, rank }: { item: ExposureItem; rank: number }) {
  const band = scoreBand(x.score);
  const targets = remediationTargets(x);
  return (
    <li className="grid grid-cols-[3rem_minmax(0,1fr)_auto] items-start gap-x-4 gap-y-2 px-6 py-4 max-sm:grid-cols-[minmax(0,1fr)] max-sm:px-4">
      <div className="text-right max-sm:text-left">
        <p className="tnum text-lg font-semibold leading-tight" aria-label={`Rank ${rank}, score ${x.score}`}>{x.score}</p>
        <p className="label">{band}</p>
      </div>
      <div className="min-w-0">
        <p className="flex flex-wrap items-center gap-2">
          <Severity value={x.severity} />
          {x.cve_id ? (
            <Link to={`/intel/${encodeURIComponent(x.cve_id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{x.cve_id}</Link>
          ) : null}
          <span className="min-w-0 text-ui text-ink-2 [overflow-wrap:anywhere]">{x.title.replace(`${x.cve_id} in `, "")}</span>
          {x.known_exploited && <Tag tone="critical">Known exploited</Tag>}
          {!x.known_exploited && x.exploit_available && <Tag tone="warning">Public exploit</Tag>}
          {x.cvss !== null && <Tag>CVSS {x.cvss.toFixed(1)}</Tag>}
        </p>
        <p className="mt-1 text-ui text-muted">{x.reasons.join(" · ")}</p>
        <p className="mt-1 text-xs text-muted">
          {x.devices} device{x.devices === 1 ? "" : "s"}
          {x.internet_facing_devices > 0 && ` · ${x.internet_facing_devices} internet-facing`}
          {x.critical_devices > 0 && ` · ${x.critical_devices} high value`}
          {x.in_open_incidents > 0 && ` · ${x.in_open_incidents} in open incidents`}
          {x.remediation && ` · fix: ${x.remediation}`}
        </p>
        <ul aria-label={`Devices affected by ${x.id}`} className="mt-2 flex flex-wrap gap-1.5">
          {x.top_devices.map((d) => (
            <li key={d.mde_device_id ?? d.name ?? ""} className="rounded-[4px] border border-rule px-1.5 py-0.5 font-mono text-xs text-ink-2">
              {d.name ?? d.mde_device_id}
              {d.in_open_incident && <span className="ml-1 text-critical">· incident</span>}
              {d.internet_facing && <span className="ml-1 text-warning">· internet</span>}
            </li>
          ))}
        </ul>
      </div>
      <div className="max-sm:justify-self-start">
        <RequestActionButton targets={targets} incident={null} size="sm" label="Request remediation" />
      </div>
    </li>
  );
}
