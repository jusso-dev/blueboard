import { useEffect, useId, useState } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, useLiveQuery, type Assessment, type CatalogEntry, type Incident } from "../lib/api";
import { initialParams, MODE_WORDS } from "../lib/actions";
import { SchemaFields } from "../components/request-action";
import { Button, cx, Empty, ErrorLine, Select, Tag } from "../components/ui";

type PolicyView = {
  version: number;
  actions: { kind: string; title: string; target: string; destructive: boolean; mode: string; words: string; confirm_target: boolean; expiry_hours: number }[];
  protected: { users: number; devices: number; indicators: number; apps?: number };
  require_target_in_incident: boolean;
  limits: { bucket: string; agent: string; human: string }[];
  pending_actions_per_incident: number;
  warnings: string[];
  lists: { users: string[]; devices: string[]; indicators: string[]; apps?: string[] } | null;
};

const MODE_TONE: Record<string, "good" | "warning" | "neutral" | "critical"> = { auto: "good", approval: "warning", on_instruction: "good", two_approvers: "warning", disabled: "neutral" };

/** Read-only view of the effective policy (issue #11). Policy is file-based; there is no editing here. */
export default function PolicyPage() {
  const me = useMe();
  const { data: p, error } = useLiveQuery<PolicyView>("/policy");
  const isAdmin = !!me?.roles.includes("admin");
  return (
    <>
      <PageHeader title="Policy" sub="What the board does with each action request: runs it, waits for people, or refuses. Set in policy.json; read-only here." />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't load the policy">{error.message}</Empty>}
        {p && (
          <>
            <section aria-label="Actions" className="overflow-x-auto border-b border-rule">
              <table className="w-full min-w-[44rem] text-left text-[13px]">
                <caption className="sr-only">How policy treats each action</caption>
                <thead className="label">
                  <tr className="border-b border-rule">
                    <th className="px-5 py-2 font-normal">Action</th>
                    <th className="py-2 pr-4 font-normal">Target</th>
                    <th className="py-2 pr-4 font-normal">Mode</th>
                    <th className="py-2 pr-4 font-normal">What happens</th>
                    <th className="py-2 pr-5 text-right font-normal">Expires after</th>
                  </tr>
                </thead>
                <tbody>
                  {p.actions.map((a) => (
                    <tr key={a.kind} className="border-b border-rule last:border-0">
                      <td className="px-5 py-2">
                        <span className="text-ink">{a.title}</span>
                        <span className="label ml-2">{a.kind}</span>
                        {a.destructive && <span className="label ml-2 text-ink-2">destructive</span>}
                      </td>
                      <td className="label py-2 pr-4 text-ink-2">{a.target}</td>
                      <td className="py-2 pr-4">
                        <Tag tone={MODE_TONE[a.mode] ?? "neutral"}>{MODE_WORDS[a.mode] ?? a.mode}</Tag>
                      </td>
                      <td className="py-2 pr-4 text-ink-2">
                        {a.words}
                        {a.confirm_target && <span className="text-muted">. The approver types the target to confirm</span>}
                      </td>
                      <td className="label tnum py-2 pr-5 text-right">{a.mode === "auto" || a.mode === "disabled" ? "—" : `${a.expiry_hours} h`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>

            <section aria-label="Protected and limits" className="grid gap-8 border-b border-rule px-5 py-5 lg:grid-cols-2">
              <div>
                <h2 className="text-sm font-semibold">Protected</h2>
                <p className="mt-1 text-xs text-muted">Requests aimed at these are always rejected, by any name the evidence gives them.</p>
                <dl className="mt-2 space-y-1.5 text-[13px]">
                  <Protected label="Users" n={p.protected.users} values={p.lists?.users} />
                  <Protected label="Devices" n={p.protected.devices} values={p.lists?.devices} />
                  <Protected label="Indicators" n={p.protected.indicators} values={p.lists?.indicators} />
                  <Protected label="Apps" n={p.protected.apps ?? 0} values={p.lists?.apps} />
                </dl>
                {!isAdmin && <p className="label mt-2">Board admins can see the values.</p>}
                <p className="mt-3 text-[13px] text-ink-2">
                  Targets outside the incident evidence are {p.require_target_in_incident ? "flagged for the approver and never run on their own" : <strong className="text-warning">not checked</strong>}.
                </p>
              </div>
              <div>
                <h2 className="text-sm font-semibold">Rate limits</h2>
                <p className="mt-1 text-xs text-muted">Per principal. At most {p.pending_actions_per_incident} actions can wait for approval on one incident.</p>
                <table className="mt-2 w-full max-w-md text-[13px]">
                  <thead className="label">
                    <tr className="border-b border-rule">
                      <th className="py-1.5 text-left font-normal">Bucket</th>
                      <th className="py-1.5 text-left font-normal">Agents</th>
                      <th className="py-1.5 text-left font-normal">People</th>
                    </tr>
                  </thead>
                  <tbody className="tnum">
                    {p.limits.map((l) => (
                      <tr key={l.bucket} className="border-b border-rule last:border-0">
                        <td className="label py-1.5 text-ink-2">{l.bucket}</td>
                        <td className="py-1.5 text-ink-2">{l.agent}</td>
                        <td className="py-1.5 text-ink-2">{l.human}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            {p.warnings.length > 0 && (
              <section aria-label="Warnings" className="border-b border-rule px-5 py-4">
                <h2 className="text-sm font-semibold">Warnings</h2>
                <ul className="mt-2 space-y-0.5">
                  {p.warnings.map((w, i) => (
                    <li key={i} className="flex gap-2 text-xs text-warning">
                      <span aria-hidden>⚠</span>
                      <span>{w}</span>
                    </li>
                  ))}
                </ul>
              </section>
            )}

            <Simulator />
            <p className="label px-5 py-3">policy version {p.version}</p>
          </>
        )}
      </div>
    </>
  );
}

function Protected({ label, n, values }: { label: string; n: number; values?: string[] }) {
  return (
    <div>
      <dt className="inline text-ink-2">{label}</dt>{" "}
      <dd className="inline">
        {values ? (
          <details className="inline">
            <summary className="tnum inline cursor-pointer text-ink hover:text-accent">{n}</summary>
            <ul className="mt-1 ml-4 font-mono text-xs text-ink-2">
              {values.length === 0 && <li className="text-faint">none</li>}
              {values.map((v) => (
                <li key={v} className="[overflow-wrap:anywhere]">
                  {v}
                </li>
              ))}
            </ul>
          </details>
        ) : (
          <span className={cx("tnum", n === 0 ? "text-warning" : "text-ink")}>{n === 0 ? "none" : n}</span>
        )}
      </dd>
    </div>
  );
}

/** "What would happen if an agent asked to isolate dc01?" Same server-side evaluation as a real request; nothing is filed. */
function Simulator() {
  const id = useId();
  const { data: catalog } = useLiveQuery<CatalogEntry[]>("/actions?catalog=true");
  const { data: incidents } = useLiveQuery<Incident[]>("/incidents");
  const [kind, setKind] = useState("isolate_device");
  const [incident, setIncident] = useState("");
  const [params, setParams] = useState<Record<string, unknown>>({});
  const [result, setResult] = useState<Assessment | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const def = catalog?.find((c) => c.kind === kind);
  // Keyed on the kind, not the catalogue object: the poll refreshes it every few seconds and must not clear the form.
  const loaded = !!def;
  useEffect(() => {
    if (def) setParams(initialParams(def.params, {}));
    setResult(null);
  }, [kind, loaded]);

  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setResult(await api<Assessment>("/policy/simulate", { method: "POST", body: JSON.stringify({ kind, params, incident: incident || undefined }) }));
    } catch (e) {
      setResult(null);
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby={`${id}-h`} className="border-b border-rule px-5 py-5">
      <h2 id={`${id}-h`} className="text-sm font-semibold">
        What would happen if…
      </h2>
      <p className="mt-1 text-xs text-muted">Runs the same policy check as a real request. Nothing is filed and nothing runs.</p>
      <form
        className="mt-3 grid max-w-2xl gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor={`${id}-kind`} className="mb-1 block text-xs text-ink-2">
              Action
            </label>
            <Select id={`${id}-kind`} className="w-full" value={kind} onChange={(e) => setKind(e.target.value)}>
              {catalog?.map((c) => (
                <option key={c.kind} value={c.kind}>
                  {c.title}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label htmlFor={`${id}-inc`} className="mb-1 block text-xs text-ink-2">
              Incident (optional)
            </label>
            <Select id={`${id}-inc`} className="w-full" value={incident} onChange={(e) => setIncident(e.target.value)}>
              <option value="">Not linked to an incident</option>
              {incidents?.map((i) => (
                <option key={i.id} value={i.id}>
                  INC {i.graph_id} · {i.display_name}
                </option>
              ))}
            </Select>
          </div>
        </div>
        {def && <SchemaFields schema={def.params} values={params} onChange={setParams} idPrefix={id} />}
        <div className="flex items-center gap-3">
          <Button type="submit" loading={busy}>
            Check
          </Button>
          {err && <ErrorLine>{err}</ErrorLine>}
        </div>
      </form>
      {result && (
        <div className="mt-3 max-w-2xl" role="status">
          <p className={cx("text-[13px] font-medium", result.outcome === "reject" ? "text-critical" : result.outcome === "auto" ? "text-good" : "text-warning")}>{result.summary}</p>
          <p className="mt-0.5 text-xs text-muted">{result.describe}</p>
          {result.notes.length > 0 && result.outcome !== "reject" && (
            <ul className="mt-1.5 space-y-0.5">
              {result.notes.map((n, i) => (
                <li key={i} className="flex gap-2 text-xs text-warning">
                  <span aria-hidden>⚠</span>
                  <span>{n}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
