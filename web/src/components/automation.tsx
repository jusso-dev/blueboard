/**
 * Conditional automation on /policy: kill switch, per-kind overrides (policy.json ceiling vs effective), the conditions
 * form, pending loosening changes for a second admin, playbook triggers and change history. Every write goes through
 * the API, which re-checks the ceiling, the human-admin role and the second-admin rule; the page only explains.
 */
import { useId, useState } from "react";
import { api, refreshAll, useLiveQuery } from "../lib/api";
import { MODE_WORDS } from "../lib/actions";
import {
  allowedModes,
  defaultRule,
  ruleProblems,
  SEVERITIES,
  splitList,
  targetLabel,
  type AutoRule,
  type AutomationView,
  type KindView,
  type PlaybookTrigger,
  type PolicyChange,
} from "../lib/automation";
import { Button, cx, ErrorLine, Input, Select, Tag, Time } from "./ui";

function useAction() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async (f: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await f();
      refreshAll();
      return true;
    } catch (e) {
      setErr((e as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, err, run };
}

const json = (body: unknown) => ({ body: JSON.stringify(body) });

export function AutomationAdmin({ me }: { me: string | undefined }) {
  const { data: v, error } = useLiveQuery<AutomationView>("/policy/automation");
  if (error) return <p className="px-6 max-sm:px-4 py-4 text-xs text-critical">Couldn't load automation: {error.message}</p>;
  if (!v) return null;
  return (
    <>
      <KillSwitch v={v} />
      {v.pending.length > 0 && <Pending changes={v.pending} me={me} canDecide={v.can_edit} />}
      <Kinds v={v} />
      <Triggers v={v} />
      <History changes={v.history} />
    </>
  );
}

/** One click for any admin to pause; resuming loosens, so it files a change for a second admin. */
function KillSwitch({ v }: { v: AutomationView }) {
  const id = useId();
  const [reason, setReason] = useState("");
  const { busy, err, run } = useAction();
  const paused = v.pause.paused;
  return (
    <section
      aria-labelledby={`${id}-h`}
      className={cx("border-b border-rule px-6 max-sm:px-4 py-4", paused ? "bg-warning-soft/40" : "bg-paper")}
    >
      <div className="flex flex-wrap items-center gap-3">
        <h2 id={`${id}-h`} className="text-sm font-semibold">
          Automation
        </h2>
        <Tag tone={paused ? "warning" : "good"}>{paused ? "paused" : "on"}</Tag>
        <p className="text-xs text-ink-2">
          {paused
            ? `Paused by @${v.pause.by ?? "an admin"}${v.pause.reason ? `: ${v.pause.reason}` : ""}. Every request waits for a person.`
            : "Kinds with automation rules may run on their own when every condition holds. This is separate from the broker pause."}
        </p>
      </div>
      {v.can_edit && (
        <form
          className="mt-2 flex max-w-2xl flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => api("/policy/automation/pause", { method: "POST", ...json({ paused: !paused, reason }) })).then((ok) => ok && setReason(""));
          }}
        >
          <label htmlFor={`${id}-r`} className="sr-only">
            Reason
          </label>
          <Input id={`${id}-r`} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (recorded in the audit log)" className="min-w-64 flex-1" />
          <Button type="submit" variant={paused ? "secondary" : "danger"} loading={busy} disabled={reason.trim().length < 5}>
            {paused ? "Ask to resume (needs a second admin)" : "Pause automation now"}
          </Button>
        </form>
      )}
      {err && <ErrorLine>{err}</ErrorLine>}
    </section>
  );
}

function Pending({ changes, me, canDecide }: { changes: PolicyChange[]; me: string | undefined; canDecide: boolean }) {
  return (
    <section aria-label="Changes waiting for a second admin" className="border-b border-rule px-6 max-sm:px-4 py-4">
      <h2 className="text-sm font-semibold">Waiting for a second admin</h2>
      <p className="mt-1 text-xs text-muted">Loosening changes apply only when a different board admin approves them. They expire if nobody does.</p>
      <ul className="mt-2 space-y-3">
        {changes.map((c) => (
          <PendingRow key={c.id} c={c} mine={c.requested_by === me} canDecide={canDecide} />
        ))}
      </ul>
    </section>
  );
}

function PendingRow({ c, mine, canDecide }: { c: PolicyChange; mine: boolean; canDecide: boolean }) {
  const [note, setNote] = useState("");
  const { busy, err, run } = useAction();
  const decide = (decision: "approve" | "deny") => run(() => api(`/policy/changes/${c.id}`, { method: "POST", ...json({ decision, note: note || undefined }) }));
  return (
    <li className="max-w-3xl rounded-[var(--radius-control)] border border-rule px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs text-ink">{targetLabel(c.target)}</span>
        <Tag tone="warning">loosening</Tag>
        <span className="label">requested by @{c.requested_by}</span>
        <span className="label ml-auto">
          expires <Time iso={c.expires_at} />
        </span>
      </div>
      <p className="mt-1 text-ui text-ink-2">{c.reason}</p>
      <Diff before={c.before} after={c.after} />
      {canDecide && !mine ? (
        <div className="mt-2 flex flex-wrap gap-2">
          <label className="sr-only" htmlFor={`note-${c.id}`}>
            Note
          </label>
          <Input id={`note-${c.id}`} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (optional)" className="min-w-48 flex-1" />
          <Button size="sm" variant="primary" loading={busy} onClick={() => void decide("approve")}>
            Approve change
          </Button>
          <Button size="sm" loading={busy} onClick={() => void decide("deny")}>
            Deny
          </Button>
        </div>
      ) : (
        <p className="label mt-1.5">{mine ? "You asked for this, so a different admin has to decide it." : "Only board admins can decide."}</p>
      )}
      {err && <ErrorLine>{err}</ErrorLine>}
    </li>
  );
}

function Diff({ before, after }: { before: unknown; after: unknown }) {
  return (
    <details className="mt-1">
      <summary className="label cursor-pointer hover:text-accent">before / after</summary>
      <div className="mt-1 grid gap-2 sm:grid-cols-2">
        <pre className="overflow-x-auto rounded bg-paper-2 p-2 font-mono text-[11px] text-ink-2">{before == null ? "policy.json (no override)" : JSON.stringify(before, null, 2)}</pre>
        <pre className="overflow-x-auto rounded bg-paper-2 p-2 font-mono text-[11px] text-ink">{after == null ? "policy.json (override removed)" : JSON.stringify(after, null, 2)}</pre>
      </div>
    </details>
  );
}

/** Per-kind table: what policy.json allows (the ceiling) against what is in force, with an editor for admins. */
function Kinds({ v }: { v: AutomationView }) {
  const [open, setOpen] = useState<string | null>(null);
  const shown = v.kinds.filter((k) => k.destructive || k.override);
  return (
    <section aria-label="Action overrides" className="border-b border-rule">
      <div className="px-6 max-sm:px-4 pt-4">
        <h2 className="text-sm font-semibold">Overrides and automation rules</h2>
        <p className="mt-1 text-xs text-muted">
          policy.json is the ceiling: an override can only make a kind stricter, or add a rule for a kind policy.json lists in automation.conditional_auto_allowed
          ({v.ceiling.conditional_auto_allowed.length ? v.ceiling.conditional_auto_allowed.join(", ") : "none"}). Tightening applies at once; loosening waits for a second admin.
          Protected lists always win.
        </p>
      </div>
      <div className="mt-2 overflow-x-auto">
        <table className="w-full min-w-[48rem] text-left text-ui">
          <thead className="label">
            <tr className="border-b border-rule">
              <th className="px-6 max-sm:px-4 py-2 font-normal">Action</th>
              <th className="py-2 pr-4 font-normal">policy.json</th>
              <th className="py-2 pr-4 font-normal">In force</th>
              <th className="py-2 pr-4 font-normal">Rule</th>
              <th className="py-2 pr-6 max-sm:pr-4 font-normal" />
            </tr>
          </thead>
          <tbody>
            {shown.map((k) => (
              <KindRow key={k.kind} k={k} v={v} open={open === k.kind} onToggle={() => setOpen(open === k.kind ? null : k.kind)} />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function KindRow({ k, v, open, onToggle }: { k: KindView; v: AutomationView; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className="border-b border-rule last:border-0">
        <td className="px-6 max-sm:px-4 py-2">
          <span className="text-ink">{k.title}</span>
          <span className="label ml-2">{k.kind}</span>
          {!k.reversible && k.destructive && <span className="label ml-2 text-warning">irreversible</span>}
        </td>
        <td className="py-2 pr-4 text-ink-2">{MODE_WORDS[k.file.mode] ?? k.file.mode}</td>
        <td className="py-2 pr-4">
          <Tag tone={k.mode === "conditional" ? "good" : k.mode === "disabled" ? "neutral" : "warning"}>{MODE_WORDS[k.mode] ?? k.mode}</Tag>
          {k.override && <span className="label ml-2">override v{k.override_version}</span>}
        </td>
        <td className="py-2 pr-4 font-mono text-xs text-ink-2">{k.rule_id ?? (k.ceiling_allows_rule ? "none (allowed)" : "—")}</td>
        <td className="py-2 pr-6 max-sm:pr-4 text-right">
          {v.can_edit && (
            <Button size="sm" variant="ghost" onClick={onToggle} aria-expanded={open}>
              {open ? "Close" : "Edit"}
            </Button>
          )}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-rule bg-paper-2/40">
          <td colSpan={5} className="px-6 max-sm:px-4 py-3">
            <KindEditor k={k} v={v} />
          </td>
        </tr>
      )}
    </>
  );
}

function KindEditor({ k, v }: { k: KindView; v: AutomationView }) {
  const id = useId();
  const start = k.override ?? k.effective;
  const [mode, setMode] = useState(start.mode === "conditional" ? "approval" : start.mode);
  const [confirm, setConfirm] = useState(start.confirm_target);
  const [useRule, setUseRule] = useState(!!start.rule);
  const [rule, setRule] = useState<AutoRule>(start.rule ?? defaultRule(k, v.ceiling));
  const [sources, setSources] = useState((start.rule?.sources ?? []).join(", "));
  const [requesters, setRequesters] = useState((start.rule?.requesters ?? []).join(", "));
  const [reason, setReason] = useState("");
  const { busy, err, run } = useAction();
  const fullRule: AutoRule = { ...rule, sources: splitList(sources), requesters: splitList(requesters) };
  const problems = useRule ? ruleProblems(k, fullRule, v.ceiling) : [];
  const ruleModes = mode === "approval" || mode === "on_instruction";
  const submit = (reset: boolean) =>
    run(() =>
      api(`/policy/kinds/${k.kind}`, {
        method: "PUT",
        ...json(reset ? { reason, reset: true } : { reason, mode, confirm_target: confirm, rule: useRule && ruleModes ? fullRule : undefined }),
      }),
    );

  return (
    <form
      className="grid max-w-3xl gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        void submit(false);
      }}
    >
      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <label htmlFor={`${id}-mode`} className="mb-1 block text-xs text-ink-2">
            Mode
          </label>
          <Select id={`${id}-mode`} className="w-full" value={mode} onChange={(e) => setMode(e.target.value)}>
            {allowedModes(k).map((m) => (
              <option key={m} value={m}>
                {MODE_WORDS[m] ?? m}
              </option>
            ))}
          </Select>
        </div>
        <label className="flex items-center gap-2 self-end text-xs text-ink-2">
          <input type="checkbox" checked={confirm} disabled={k.file.confirm_target} onChange={(e) => setConfirm(e.target.checked)} />
          Approver types the target
        </label>
        {k.ceiling_allows_rule && (
          <label className="flex items-center gap-2 self-end text-xs text-ink-2">
            <input type="checkbox" checked={useRule} disabled={!ruleModes} onChange={(e) => setUseRule(e.target.checked)} />
            Conditional automation rule
          </label>
        )}
      </div>

      {useRule && ruleModes && (
        <fieldset className="grid gap-3 rounded-[var(--radius-control)] border border-rule p-3 sm:grid-cols-2">
          <legend className="px-1 text-xs text-ink-2">Runs on its own only when all of these hold (otherwise it waits for a person)</legend>
          <Num id={`${id}-conf`} label={`Verdict confidence at least (≥ ${v.ceiling.min_confidence_floor})`} step={0.01} min={v.ceiling.min_confidence_floor} max={1}
            value={rule.min_confidence} onChange={(n) => setRule({ ...rule, min_confidence: n })} />
          <div>
            <span className="mb-1 block text-xs text-ink-2">Incident severities</span>
            <div className="flex flex-wrap gap-3">
              {SEVERITIES.map((s) => (
                <label key={s} className="flex items-center gap-1 text-xs text-ink-2">
                  <input
                    type="checkbox"
                    checked={!!rule.severities?.includes(s)}
                    onChange={(e) => setRule({ ...rule, severities: e.target.checked ? [...(rule.severities ?? []), s] : (rule.severities ?? []).filter((x) => x !== s) })}
                  />
                  {s}
                </label>
              ))}
            </div>
          </div>
          <Num id={`${id}-hour`} label={`Max automatic runs per hour (≤ ${v.ceiling.max_per_hour})`} min={1} max={v.ceiling.max_per_hour}
            value={rule.max_per_hour} onChange={(n) => setRule({ ...rule, max_per_hour: n })} />
          <Num id={`${id}-inc`} label={`Max automatic runs per incident (≤ ${v.ceiling.max_per_incident})`} min={1} max={v.ceiling.max_per_incident}
            value={rule.max_per_incident} onChange={(n) => setRule({ ...rule, max_per_incident: n })} />
          {k.reversible ? (
            <Num id={`${id}-rev`} label={`Undo automatically after (minutes, ≤ ${v.ceiling.max_revert_after_minutes}) via ${k.reverse_kind}`} min={5}
              max={v.ceiling.max_revert_after_minutes} value={rule.revert_after_minutes ?? 60} onChange={(n) => setRule({ ...rule, revert_after_minutes: n })} />
          ) : (
            <p className="self-end text-xs text-warning">Irreversible: nothing undoes it once it runs.</p>
          )}
          <label className="flex items-center gap-2 self-end text-xs text-ink-2">
            <input type="checkbox" checked={rule.require_human_verdict} onChange={(e) => setRule({ ...rule, require_human_verdict: e.target.checked })} />
            Only a person's verdict counts
          </label>
          <Text id={`${id}-src`} label="Only alerts from (service sources, comma-separated, optional)" value={sources} onChange={setSources} placeholder="microsoftDefenderForEndpoint" />
          <Text id={`${id}-req`} label="Only these requesters (handles, optional)" value={requesters} onChange={setRequesters} placeholder="triage-bot" />
          <p className="text-xs text-muted sm:col-span-2">
            Always also required: every target in the incident evidence, a truePositive verdict from someone other than the requester, no dissenting verdict and no protected-list match.
          </p>
          {problems.length > 0 && (
            <ul className="space-y-0.5 sm:col-span-2">
              {problems.map((p) => (
                <li key={p} className="text-xs text-warning">
                  ⚠ {p}
                </li>
              ))}
            </ul>
          )}
        </fieldset>
      )}

      <div className="flex flex-wrap gap-2">
        <label htmlFor={`${id}-why`} className="sr-only">
          Reason
        </label>
        <Input id={`${id}-why`} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (recorded in the audit log)" className="min-w-64 flex-1" />
        <Button type="submit" variant="primary" loading={busy} disabled={reason.trim().length < 5 || problems.length > 0}>
          Save
        </Button>
        {k.override && (
          <Button type="button" loading={busy} disabled={reason.trim().length < 5} onClick={() => void submit(true)}>
            Reset to policy.json
          </Button>
        )}
      </div>
      {err && <ErrorLine>{err}</ErrorLine>}
    </form>
  );
}

function Num({ id, label, value, onChange, min, max, step = 1 }: { id: string; label: string; value: number; onChange: (n: number) => void; min: number; max: number; step?: number }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs text-ink-2">
        {label}
      </label>
      <Input id={id} type="number" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full tnum" />
    </div>
  );
}

function Text({ id, label, value, onChange, placeholder }: { id: string; label: string; value: string; onChange: (s: string) => void; placeholder?: string }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs text-ink-2">
        {label}
      </label>
      <Input id={id} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className="w-full" />
    </div>
  );
}

/** Playbook auto-attach triggers: file triggers (from each playbook's match) plus custom ones. */
function Triggers({ v }: { v: AutomationView }) {
  const [editing, setEditing] = useState<string | null>(null);
  return (
    <section aria-label="Playbook triggers" className="border-b border-rule">
      <div className="flex flex-wrap items-baseline gap-3 px-6 max-sm:px-4 pt-4">
        <h2 className="text-sm font-semibold">Playbook triggers</h2>
        <p className="text-xs text-muted">Which playbook attaches to a new incident. Disabling applies at once; adding or widening a trigger waits for a second admin.</p>
        {v.can_edit && (
          <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setEditing(editing === "__new" ? null : "__new")}>
            {editing === "__new" ? "Close" : "Add trigger"}
          </Button>
        )}
      </div>
      {editing === "__new" && (
        <div className="px-6 max-sm:px-4 py-3">
          <TriggerEditor playbooks={[...new Set(v.triggers.map((t) => t.playbook_id))]} onDone={() => setEditing(null)} />
        </div>
      )}
      <div className="mt-2 overflow-x-auto">
        <table className="w-full min-w-[48rem] text-left text-ui">
          <thead className="label">
            <tr className="border-b border-rule">
              <th className="px-6 max-sm:px-4 py-2 font-normal">Trigger</th>
              <th className="py-2 pr-4 font-normal">Playbook</th>
              <th className="py-2 pr-4 font-normal">Matches</th>
              <th className="py-2 pr-4 text-right font-normal">Priority</th>
              <th className="py-2 pr-6 max-sm:pr-4 font-normal" />
            </tr>
          </thead>
          <tbody>
            {v.triggers.map((t) => (
              <tr key={t.id} className={cx("border-b border-rule last:border-0 align-top", !t.enabled && "opacity-60")}>
                <td className="px-6 max-sm:px-4 py-2">
                  <span className="font-mono text-xs text-ink">{t.id}</span>
                  <span className="label ml-2">{t.source}{t.edited ? ` · edited v${t.version}` : ""}</span>
                  {!t.enabled && <span className="label ml-2">off</span>}
                </td>
                <td className="py-2 pr-4 font-mono text-xs text-ink-2">{t.playbook_id}</td>
                <td className="py-2 pr-4 text-xs text-ink-2">{describeMatch(t)}</td>
                <td className="label tnum py-2 pr-4 text-right">{t.priority}</td>
                <td className="py-2 pr-6 max-sm:pr-4 text-right">
                  {v.can_edit && (
                    <Button size="sm" variant="ghost" onClick={() => setEditing(editing === t.id ? null : t.id)}>
                      {editing === t.id ? "Close" : "Edit"}
                    </Button>
                  )}
                  {editing === t.id && (
                    <div className="mt-2 text-left">
                      <TriggerEditor t={t} playbooks={[t.playbook_id]} onDone={() => setEditing(null)} />
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function describeMatch(t: PlaybookTrigger) {
  const m = t.match;
  const parts = [
    m.titles.length && `title has ${m.titles.join(" / ")}`,
    m.categories.length && `category ${m.categories.join(" / ")}`,
    m.techniques.length && `MITRE ${m.techniques.join(" / ")}`,
    m.sources.length && `source ${m.sources.join(" / ")}`,
  ].filter(Boolean);
  return `${parts.join("; ") || "nothing"}${m.severities.length ? ` (severity ${m.severities.join("/")})` : ""}`;
}

function TriggerEditor({ t, playbooks, onDone }: { t?: PlaybookTrigger; playbooks: string[]; onDone: () => void }) {
  const id = useId();
  const [tid, setTid] = useState(t?.id ?? "");
  const [playbook, setPlaybook] = useState(t?.playbook_id ?? playbooks[0] ?? "");
  const [priority, setPriority] = useState(t?.priority ?? 0);
  const [titles, setTitles] = useState(t?.match.titles.join(", ") ?? "");
  const [categories, setCategories] = useState(t?.match.categories.join(", ") ?? "");
  const [techniques, setTechniques] = useState(t?.match.techniques.join(", ") ?? "");
  const [sources, setSources] = useState(t?.match.sources.join(", ") ?? "");
  const [severities, setSeverities] = useState(t?.match.severities.join(", ") ?? "");
  const [enabled, setEnabled] = useState(t?.enabled ?? true);
  const [reason, setReason] = useState("");
  const { busy, err, run } = useAction();
  const body = (remove = false) => ({
    reason,
    remove,
    playbook_id: playbook,
    priority,
    enabled,
    titles: splitList(titles),
    categories: splitList(categories),
    techniques: splitList(techniques),
    sources: splitList(sources),
    severities: splitList(severities),
  });
  const save = (remove = false) => run(() => api(`/policy/triggers/${tid}`, { method: "PUT", ...json(body(remove)) })).then((ok) => ok && onDone());
  return (
    <form
      className="grid max-w-3xl gap-2 sm:grid-cols-2"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      {!t && <Text id={`${id}-id`} label="Trigger id (lower-case slug)" value={tid} onChange={setTid} placeholder="phish-high" />}
      {!t ? (
        <div>
          <label htmlFor={`${id}-pb`} className="mb-1 block text-xs text-ink-2">
            Playbook
          </label>
          <Select id={`${id}-pb`} className="w-full" value={playbook} onChange={(e) => setPlaybook(e.target.value)}>
            {playbooks.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </Select>
        </div>
      ) : null}
      <Text id={`${id}-t`} label="Title contains (comma-separated)" value={titles} onChange={setTitles} />
      <Text id={`${id}-c`} label="Alert category" value={categories} onChange={setCategories} />
      <Text id={`${id}-m`} label="MITRE techniques" value={techniques} onChange={setTechniques} placeholder="T1566" />
      <Text id={`${id}-s`} label="Service sources" value={sources} onChange={setSources} placeholder="microsoftDefenderForOffice365" />
      <Text id={`${id}-v`} label="Only severities (optional)" value={severities} onChange={setSeverities} placeholder="high, medium" />
      <Num id={`${id}-p`} label="Priority (higher wins)" min={-100} max={1000} value={priority} onChange={setPriority} />
      <label className="flex items-center gap-2 text-xs text-ink-2">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        Enabled
      </label>
      <div className="flex flex-wrap gap-2 sm:col-span-2">
        <label htmlFor={`${id}-why`} className="sr-only">
          Reason
        </label>
        <Input id={`${id}-why`} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (recorded in the audit log)" className="min-w-64 flex-1" />
        <Button type="submit" variant="primary" size="sm" loading={busy} disabled={reason.trim().length < 5 || !tid}>
          Save
        </Button>
        {t?.source === "custom" && (
          <Button type="button" size="sm" loading={busy} disabled={reason.trim().length < 5} onClick={() => void save(true)}>
            Remove
          </Button>
        )}
      </div>
      {err && <ErrorLine>{err}</ErrorLine>}
    </form>
  );
}

function History({ changes }: { changes: PolicyChange[] }) {
  if (changes.length === 0) return null;
  return (
    <section aria-label="Policy change history" className="border-b border-rule">
      <h2 className="px-6 max-sm:px-4 pt-4 text-sm font-semibold">Change history</h2>
      <div className="mt-2 overflow-x-auto">
        <table className="w-full min-w-[44rem] text-left text-ui">
          <thead className="label">
            <tr className="border-b border-rule">
              <th className="px-6 max-sm:px-4 py-2 font-normal">Change</th>
              <th className="py-2 pr-4 font-normal">Status</th>
              <th className="py-2 pr-4 font-normal">Requested by</th>
              <th className="py-2 pr-4 font-normal">Decided by</th>
              <th className="py-2 pr-6 max-sm:pr-4 text-right font-normal">When</th>
            </tr>
          </thead>
          <tbody>
            {changes.map((c) => (
              <tr key={c.id} className="border-b border-rule last:border-0">
                <td className="px-6 max-sm:px-4 py-2">
                  <span className="font-mono text-xs text-ink">{targetLabel(c.target)}</span>
                  <span className="label ml-2">{c.loosening ? "loosening" : "tightening"}</span>
                  <p className="text-xs text-muted">{c.reason}</p>
                </td>
                <td className="py-2 pr-4">
                  <Tag tone={c.status === "applied" ? "good" : c.status === "denied" ? "critical" : "neutral"}>{c.status}</Tag>
                </td>
                <td className="py-2 pr-4 text-ink-2">@{c.requested_by}</td>
                <td className="py-2 pr-4 text-ink-2">{c.decided_by ? `@${c.decided_by}` : "—"}</td>
                <td className="py-2 pr-6 max-sm:pr-4 text-right">
                  <Time iso={c.decided_at ?? c.requested_at} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
