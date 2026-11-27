import { useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, ApiError, refreshAll, useLiveQuery } from "../lib/api";
import { Button, Empty, ErrorLine, Tag, Time } from "../components/ui";
import { CONNECTOR_NAME, healthTag, type ConnectorsView, type ConnectorView } from "../lib/connectors";

type TestResult = { connector: string; ok: boolean; error: string | null };

function Row({ c, onTest, busy, result }: { c: ConnectorView; onTest: () => void; busy: boolean; result?: TestResult }) {
  const h = healthTag(c);
  return (
    <li className="grid grid-cols-[7rem_minmax(0,1fr)_auto] items-start gap-x-4 border-b border-rule px-6 py-4 max-sm:grid-cols-1 max-sm:gap-y-2 max-sm:px-4">
      <span className="pt-0.5">
        <Tag tone={h.tone}>{h.word}</Tag>
      </span>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold">{CONNECTOR_NAME[c.connector] ?? c.connector}</h2>
        {c.configured ? (
          <dl className="mt-1 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-ui text-ink-2">
            <dt className="text-muted">Host</dt>
            <dd className="font-mono text-xs [overflow-wrap:anywhere]">{c.host}</dd>
            <dt className="text-muted">Credential</dt>
            <dd>{c.auth}</dd>
            {c.inbound_enabled !== null && (
              <>
                <dt className="text-muted">Inbound</dt>
                <dd>{c.inbound_enabled ? "Signed webhook on (comments and playbook requests; never approvals)" : "Off (no webhook secret)"}</dd>
              </>
            )}
            <dt className="text-muted">{c.connector === "okta" ? "Identities" : "Linked tickets"}</dt>
            <dd className="tnum">{c.links}</dd>
            <dt className="text-muted">Last success</dt>
            <dd>{c.last_ok_at ? <Time iso={c.last_ok_at} /> : "never"}</dd>
            {c.last_error_at && (
              <>
                <dt className="text-muted">Last error</dt>
                <dd className="[overflow-wrap:anywhere]">
                  <Time iso={c.last_error_at} />: {c.last_error}
                </dd>
              </>
            )}
          </dl>
        ) : (
          <p className="mt-0.5 text-ui text-muted">Not configured. See docs/INTEGRATIONS.md for the settings and Key Vault secrets.</p>
        )}
        {result &&
          (result.ok ? (
            <p className="mt-1.5 text-ui" role="status">
              Test read succeeded.
            </p>
          ) : (
            <ErrorLine>Test failed: {result.error}</ErrorLine>
          ))}
      </div>
      {c.configured && (
        <Button size="sm" variant="ghost" disabled={busy} onClick={onTest}>
          {busy ? "Testing…" : "Test"}
        </Button>
      )}
    </li>
  );
}

/**
 * Admin → Connectors (Board.Admin): Okta, ServiceNow and Jira health, last sync and errors, with a Test button that makes
 * one harmless read. Credentials are never shown: the API returns hosts and modes only.
 */
export default function ConnectorsPage() {
  const me = useMe();
  const isAdmin = me?.roles.includes("admin");
  const { data, error } = useLiveQuery<ConnectorsView>(isAdmin ? "/manage/connectors" : null);
  const [busy, setBusy] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, TestResult>>({});

  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Connectors" />
        <Empty title="Connectors are for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }

  const test = async (connector: string) => {
    setBusy(connector);
    try {
      const r = await api<TestResult>("/manage/connectors/test", { method: "POST", body: JSON.stringify({ connector }) });
      setResults((x) => ({ ...x, [connector]: r }));
      refreshAll();
    } catch (e) {
      setResults((x) => ({ ...x, [connector]: { connector, ok: false, error: e instanceof ApiError ? e.message : String(e) } }));
    } finally {
      setBusy(null);
    }
  };

  const t = data?.tickets;
  return (
    <>
      <PageHeader title="Connectors" sub="Okta context and actions, ServiceNow and Jira tickets. Every write still goes through policy and a human approver." />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't load connectors">{String((error as Error).message ?? error)}</Empty>}
        {data && (
          <>
            <ul>
              {data.connectors.map((c) => (
                <Row key={c.connector} c={c} busy={busy === c.connector} onTest={() => void test(c.connector)} result={results[c.connector]} />
              ))}
            </ul>
            <section className="border-b border-rule px-6 py-4 max-sm:px-4" aria-labelledby="ticket-rules">
              <h2 id="ticket-rules" className="text-sm font-semibold">
                When tickets open
              </h2>
              {t && (
                <ul className="mt-1 list-disc space-y-0.5 pl-5 text-ui text-ink-2">
                  <li>{t.min_severity === "off" ? "Not by severity" : `Incidents of severity ${t.min_severity} or higher`}</li>
                  {t.on_playbook && <li>When a playbook is attached</li>}
                  {t.on_action_approved && <li>When a containment action is approved</li>}
                  <li>Board events written back: {t.sync_events.length ? t.sync_events.join(", ") : "none"}</li>
                  <li>People with Board.RequestActions can also open one from the incident page.</li>
                </ul>
              )}
            </section>
            {Object.keys(data.reverse_kinds).length > 0 && (
              <section className="px-6 py-4 max-sm:px-4" aria-labelledby="reverse">
                <h2 id="reverse" className="text-sm font-semibold">
                  Reversible connector actions
                </h2>
                <ul className="mt-1 space-y-0.5 font-mono text-xs text-muted">
                  {Object.entries(data.reverse_kinds).map(([k, v]) => (
                    <li key={k}>
                      {k} ↔ {v}
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </>
        )}
      </div>
    </>
  );
}
