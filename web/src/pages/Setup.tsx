import { useState } from "react";
import { Link } from "react-router";
import { PageHeader, useMe } from "../components/shell";
import { api, ApiError, useLiveQuery } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Tag, Time } from "../components/ui";

type Check = { id: string; name: string; status: "ok" | "warning" | "failed"; detail: string; fix: string | null; lines: string[] | null };
type Report = { checked_at: string; ok: boolean; checks: Check[] };
type TestResult = { sink: string; ok: boolean; detail: string };

const TONE = { ok: "good", warning: "warning", failed: "critical" } as const;
const WORD = { ok: "OK", warning: "Warning", failed: "Failed" } as const;

function Row({ c }: { c: Check }) {
  return (
    <li className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-4 border-b border-rule px-5 py-3 max-sm:grid-cols-1">
      <span className="pt-0.5">
        <Tag tone={TONE[c.status]}>{WORD[c.status]}</Tag>
      </span>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold">{c.name}</h2>
        <p className="mt-0.5 text-[13px] text-ink-2 [overflow-wrap:anywhere]">{c.detail}</p>
        {c.lines && c.lines.length > 0 && (
          <ul className="mt-1.5 space-y-0.5 font-mono text-xs text-muted">
            {c.lines.map((l, i) => (
              <li key={i} className="[overflow-wrap:anywhere]">
                {l}
              </li>
            ))}
          </ul>
        )}
        {c.fix && c.status !== "ok" && (
          <p className="mt-1.5 text-xs text-ink-2">
            <span className="font-medium text-ink">How to fix:</span> {c.fix}
          </p>
        )}
      </div>
    </li>
  );
}

/** The setup checklist (Board.Admin): is the board ready, one line per check, each failing line says what to do. */
export default function SetupPage() {
  const me = useMe();
  const isAdmin = me?.roles.includes("admin");
  const [fresh, setFresh] = useState(0);
  const { data: r, error, loading } = useLiveQuery<Report>(isAdmin ? `/setup${fresh ? `?fresh=true&n=${fresh}` : ""}` : null);
  const [test, setTest] = useState<TestResult[] | null>(null);
  const [testing, setTesting] = useState(false);
  const [testErr, setTestErr] = useState<string | null>(null);

  if (me && !isAdmin) {
    return (
      <>
        <PageHeader title="Setup" />
        <Empty title="Setup is for board admins">Ask an admin for the Board.Admin role.</Empty>
      </>
    );
  }

  const sendTest = async () => {
    setTesting(true);
    setTestErr(null);
    try {
      setTest(await api<TestResult[]>("/setup/test-notification", { method: "POST" }));
    } catch (e) {
      setTestErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setTesting(false);
    }
  };

  const counts = r ? (["failed", "warning", "ok"] as const).map((s) => [s, r.checks.filter((c) => c.status === s).length] as const) : [];

  return (
    <>
      <PageHeader
        title="Setup"
        sub={
          r ? (
            <span>
              {r.ok ? "No failures." : "At least one check failed."} {counts.map(([s, n]) => `${n} ${WORD[s].toLowerCase()}`).join(" · ")} · checked <Time iso={r.checked_at} />
            </span>
          ) : (
            "Is the board ready? Each check runs a harmless read; nothing is written to your tenant."
          )
        }
      >
        <Button onClick={() => setFresh(Date.now())} loading={loading && fresh > 0} title="Results are cached for 60 seconds">
          Run checks again
        </Button>
      </PageHeader>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't run the checks">{error.message}</Empty>}
        {!r && !error && <Empty title="Running checks…" />}
        {r && (
          <ul aria-label="Setup checks">
            {r.checks.map((c) => (
              <Row key={c.id} c={c} />
            ))}
          </ul>
        )}

        <section aria-labelledby="notify-test" className="px-5 py-4">
          <h2 id="notify-test" className="text-sm font-semibold">
            Test notification
          </h2>
          <p className="mt-0.5 max-w-2xl text-[13px] text-muted">
            Sends a sample notice to every configured sink (Teams, email, webhook) so you can check approvers will hear about waiting actions.
          </p>
          <p className="mt-0.5 max-w-2xl text-[13px] text-muted">
            Who gets which notices, quiet hours and the board defaults are on{" "}
            <Link to="/settings/notifications" className="whitespace-nowrap text-accent underline-offset-4 hover:underline">
              Notifications
            </Link>
            .
          </p>
          <div className="mt-2">
            <Button onClick={() => void sendTest()} loading={testing}>
              Send test notification
            </Button>
          </div>
          {testErr && (
            <div className="mt-1.5">
              <ErrorLine>{testErr}</ErrorLine>
            </div>
          )}
          {test && test.length === 0 && <p className="mt-2 text-xs text-warning">Nobody is notified outside the board: no webhook, Teams or email sink is configured.</p>}
          {test && test.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-xs">
              {test.map((t) => (
                <li key={t.sink} className={cx(t.ok ? "text-ink-2" : "text-critical")}>
                  <span className="font-mono">{t.sink}</span>: {t.ok ? "sent" : `not sent (${t.detail})`}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  );
}
