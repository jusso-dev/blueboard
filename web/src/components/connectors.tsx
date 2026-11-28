import { useState } from "react";
import { api, ApiError, refreshAll, useLiveQuery } from "../lib/api";
import { CONNECTOR_NAME, oktaStatusTone, type IncidentConnectors } from "../lib/connectors";
import { safeHref } from "../lib/gifs";
import { Button, ErrorLine, Tag, Time } from "./ui";

/**
 * Incident page strip: Okta context for the incident's users (stored by the connector's lookups and enrichment, labelled
 * as Okta data) and linked ServiceNow / Jira tickets. Renders nothing when no connector is configured.
 */
export function ConnectorStrip({ incident, canRequest }: { incident: string; canRequest: boolean }) {
  const { data } = useLiveQuery<IncidentConnectors>(`/incidents/${encodeURIComponent(incident)}/connectors`);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!data || (!data.okta_enabled && data.ticket_systems.length === 0)) return null;
  const unlinked = data.ticket_systems.filter((s) => !data.tickets.some((t) => t.system === s));

  const open = async (system: string) => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/incidents/${encodeURIComponent(incident)}/ticket`, { method: "POST", body: JSON.stringify({ system }) });
      refreshAll();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-label="Connected systems" className="flex shrink-0 flex-wrap items-center gap-2 border-b border-rule px-6 py-2 text-ui max-sm:px-4">
      {data.okta.map((o) => (
        <span
          key={o.okta_user_id}
          className="inline-flex items-center gap-1.5 rounded-[var(--radius-control)] border border-rule bg-paper-2 px-2 py-1"
          title={`Okta user ${o.okta_user_id}; data from Okta, refreshed ${new Date(o.refreshed_at).toLocaleString()}`}
        >
          <span className="label text-muted">Okta</span>
          <span className="[overflow-wrap:anywhere]">{o.upn}</span>
          <Tag tone={oktaStatusTone(o.status)}>{o.status ?? "unknown"}</Tag>
          <span className="tnum text-meta text-muted">
            {o.factors} factor{o.factors === 1 ? "" : "s"} · {o.groups} group{o.groups === 1 ? "" : "s"}
            {o.admin_roles && o.admin_roles.length > 0 && <> · admin: {o.admin_roles.join(", ")}</>}
            {o.last_login && (
              <>
                {" · last login "}
                <Time iso={o.last_login} />
              </>
            )}
          </span>
        </span>
      ))}
      {data.okta_enabled && data.okta.length === 0 && <span className="text-meta text-muted">Okta: no linked user yet (agents can run lookup_okta_user)</span>}
      {data.tickets.map((t) => {
        const href = safeHref(t.url);
        const label = `${CONNECTOR_NAME[t.system] ?? t.system} ${t.key}`;
        return (
          <span key={`${t.system}-${t.key}`} className="inline-flex items-center gap-1.5 rounded-[var(--radius-control)] border border-rule bg-paper-2 px-2 py-1" title={t.reason}>
            <span className="label text-muted">Ticket</span>
            {href ? (
              <a href={href} target="_blank" rel="noreferrer noopener" className="text-accent underline-offset-4 hover:underline">
                {label} ↗
              </a>
            ) : (
              <span>{label}</span>
            )}
            {t.last_error && <Tag tone="warning" title={t.last_error}>sync error</Tag>}
          </span>
        );
      })}
      {canRequest &&
        unlinked.map((s) => (
          <Button key={s} size="sm" variant="ghost" disabled={busy} onClick={() => void open(s)}>
            Open {CONNECTOR_NAME[s] ?? s} ticket
          </Button>
        ))}
      {err && <ErrorLine>{err}</ErrorLine>}
    </section>
  );
}
