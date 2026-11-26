import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { PageHeader, useMe } from "../components/shell";
import { api, ApiError, useLiveQuery } from "../lib/api";
import { Button, cx, Empty, ErrorLine, Input, Select, Tag, Time } from "../components/ui";
import {
  browserTimeZone,
  CLASSIFICATIONS,
  clearOverride,
  describeValue,
  diffPatch,
  EVENT_LABELS,
  fieldState,
  getAt,
  isEmptyPatch,
  mergeSettings,
  normalizeMine,
  setOverride,
  SEVERITIES,
  SINK_KEYS,
  SINK_LABELS,
  timeZones,
  type DeepPartial,
  type Delivery,
  type EventKey,
  type FieldState,
  type NotificationSettings,
  type Patch,
  type SettingsResponse,
  type SinkKey,
  type SinkStatus,
  type TestResult,
} from "../lib/notifications";

const SAVE_DELAY_MS = 500;
type Save = { kind: "idle" } | { kind: "saving" } | { kind: "saved" } | { kind: "error"; message: string };
type Obj = Record<string, unknown>;

/**
 * Optimistic, debounced autosave of one slice of the settings response (mine or defaults). Each change updates the
 * draft at once; 500 ms after the last change the smallest patch goes out. A failed save rolls the draft back to what
 * the server last confirmed and says why.
 */
function useAutosave(resp: SettingsResponse | null, select: (r: SettingsResponse) => Obj, put: (p: Patch) => Promise<SettingsResponse>, onSaved: (r: SettingsResponse) => void) {
  const [draft, setDraftState] = useState<Obj>({});
  const [save, setSave] = useState<Save>({ kind: "idle" });
  const draftRef = useRef<Obj>({});
  const confirmedRef = useRef<Obj | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const busy = useRef(false);
  const again = useRef(false);

  const setDraft = (d: Obj) => {
    draftRef.current = d;
    setDraftState(d);
  };

  // First load: adopt the server's copy.
  useEffect(() => {
    if (resp && confirmedRef.current === null) {
      confirmedRef.current = select(resp);
      setDraft(confirmedRef.current);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resp]);

  const flush = useCallback(async () => {
    timer.current = undefined;
    if (confirmedRef.current === null) return;
    if (busy.current) {
      again.current = true;
      return;
    }
    const sent = draftRef.current;
    const patch = diffPatch(confirmedRef.current, sent);
    if (isEmptyPatch(patch)) return;
    busy.current = true;
    setSave({ kind: "saving" });
    try {
      const r = await put(patch);
      confirmedRef.current = select(r);
      onSaved(r);
      // Changes made while the request was out stay in the draft and go in the next save.
      if (draftRef.current === sent) setDraft(confirmedRef.current);
      else again.current = true;
      setSave({ kind: "saved" });
    } catch (e) {
      again.current = false;
      setDraft(confirmedRef.current);
      setSave({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    } finally {
      busy.current = false;
      if (again.current) {
        again.current = false;
        void flush();
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** Apply a change to the latest draft (not the render's copy), so two changes in one handler both land. */
  const update = (change: (d: Obj) => Obj) => {
    setDraft(change(draftRef.current));
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => void flush(), SAVE_DELAY_MS);
  };

  // Leaving the page with a change still waiting: send it now rather than drop it.
  useEffect(
    () => () => {
      if (timer.current) {
        clearTimeout(timer.current);
        void flush();
      }
    },
    [flush],
  );

  return { draft, update, save };
}

/** Settings → Notifications: when blueboard pings you outside the board (webhook, Teams, email, ntfy). */
export default function NotificationsPage() {
  const me = useMe();
  const isAdmin = !!me?.roles.includes("admin");
  const [resp, setResp] = useState<SettingsResponse | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [tab, setTab] = useState<"mine" | "defaults" | "recent">("mine");

  useEffect(() => {
    api<SettingsResponse>("/notifications/settings")
      .then(setResp)
      .catch((e: unknown) => setLoadErr(e instanceof ApiError ? e.message : String(e)));
  }, []);

  const mine = useAutosave(
    resp,
    (r) => normalizeMine(r.mine) as Obj,
    (p) => api<SettingsResponse>("/notifications/settings/mine", { method: "PUT", body: JSON.stringify(p) }),
    setResp,
  );
  const defaults = useAutosave(
    resp,
    (r) => r.defaults as unknown as Obj,
    (p) => api<SettingsResponse>("/notifications/settings/defaults", { method: "PUT", body: JSON.stringify(p) }),
    setResp,
  );

  const tabs = [
    { id: "mine" as const, label: "My notifications" },
    ...(resp?.can_edit_defaults ? [{ id: "defaults" as const, label: "Board defaults" }] : []),
    ...(isAdmin ? [{ id: "recent" as const, label: "Recent deliveries" }] : []),
  ];
  const active = tab === "mine" ? mine : tab === "defaults" ? defaults : null;

  return (
    <>
      <PageHeader title="Notifications" sub="When blueboard pings you outside the board. Changes save as you make them.">
        {active && <SaveStatus save={active.save} />}
      </PageHeader>
      <div className="min-h-0 flex-1 overflow-y-auto [color-scheme:dark]">
        {loadErr && <Empty title="Couldn't load notification settings">{loadErr}</Empty>}
        {!resp && !loadErr && <Empty title="Loading…" />}
        {resp && (
          <>
            {tabs.length > 1 && <Tabs tabs={tabs} value={tab} onChange={setTab} />}
            {tab === "mine" && (
              <div role={tabs.length > 1 ? "tabpanel" : undefined} id="panel-mine" aria-labelledby={tabs.length > 1 ? "tab-mine" : undefined}>
                <SettingsForm
                  mode="mine"
                  values={mergeSettings(resp.defaults, mine.draft as DeepPartial<NotificationSettings>)}
                  field={(path) => fieldState(resp.defaults, mine.draft as DeepPartial<NotificationSettings>, path)}
                  set={(path, v) => mine.update((d) => setOverride(d, path, v) as Obj)}
                  reset={(path) => mine.update((d) => clearOverride(d, path) as Obj)}
                  sinks={resp.sinks}
                />
                <SendTest />
              </div>
            )}
            {tab === "defaults" && resp.can_edit_defaults && (
              <div role="tabpanel" id="panel-defaults" aria-labelledby="tab-defaults">
                <p className="mx-6 max-sm:mx-4 mt-4 max-w-[52rem] text-ui text-muted">
                  What everyone gets unless they change it. People who changed a setting keep their own choice.
                </p>
                <SettingsForm
                  mode="defaults"
                  values={(Object.keys(defaults.draft).length ? defaults.draft : resp.defaults) as unknown as NotificationSettings}
                  field={(path) => ({ value: getAt(defaults.draft, path), overridden: false, defaultValue: undefined })}
                  set={(path, v) => defaults.update((d) => setOverride(d, path, v) as Obj)}
                  sinks={resp.sinks}
                />
              </div>
            )}
            {tab === "recent" && isAdmin && (
              <div role="tabpanel" id="panel-recent" aria-labelledby="tab-recent">
                <RecentDeliveries />
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}

function SaveStatus({ save }: { save: Save }) {
  return (
    <span role="status" aria-live="polite" className="min-h-4 text-xs">
      {save.kind === "saving" && <span className="text-muted">Saving…</span>}
      {save.kind === "saved" && <span className="text-muted">Saved</span>}
      {save.kind === "error" && <span className="text-critical">Couldn't save: {save.message}. Your last change was undone.</span>}
    </span>
  );
}

/** APG tabs: arrow keys move between tabs, Home/End jump, only the selected tab is in the tab order. */
function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    const n = tabs.length;
    const to = e.key === "ArrowRight" ? (i + 1) % n : e.key === "ArrowLeft" ? (i - 1 + n) % n : e.key === "Home" ? 0 : e.key === "End" ? n - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    onChange(tabs[to]!.id);
    refs.current[to]?.focus();
  };
  return (
    <div role="tablist" aria-label="Notification settings" className="flex gap-1 overflow-x-auto border-b border-rule px-6 max-sm:px-4">
      {tabs.map((t, i) => (
        <button
          key={t.id}
          ref={(el) => {
            refs.current[i] = el;
          }}
          id={`tab-${t.id}`}
          role="tab"
          type="button"
          aria-selected={value === t.id}
          aria-controls={`panel-${t.id}`}
          tabIndex={value === t.id ? 0 : -1}
          onClick={() => onChange(t.id)}
          onKeyDown={(e) => onKey(e, i)}
          className={cx(
            "-mb-px whitespace-nowrap border-b-2 px-2 py-2.5 text-ui transition-colors duration-150 focus-visible:outline-offset-[-2px]",
            value === t.id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink",
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

type FormProps = {
  mode: "mine" | "defaults";
  values: NotificationSettings;
  field: (path: string) => FieldState;
  set: (path: string, v: unknown) => void;
  reset?: (path: string) => void;
  sinks: SinkStatus[];
};

const EVENT_HELP: Record<EventKey, string> = {
  approvals: "An action needs your approval before it runs.",
  mention: "Your @handle appears in a message.",
  question: "An agent posts a question and is waiting for a person.",
  reply: "Someone replies in a thread you started or posted in.",
  verdict: "An agent classifies an incident.",
  finding: "An agent posts a finding.",
  incident: "The poller posts a new incident to the queue.",
  action_result: "An action you requested finishes, fails or is denied.",
};

function SettingsForm({ mode, values, field, set, reset, sinks }: FormProps) {
  const id = useId();
  const off = !values.enabled;
  const p = { field, set, reset, mode };
  const zones = timeZones(values.quiet_hours?.time_zone);
  const tz = values.quiet_hours?.time_zone || browserTimeZone();

  return (
    <div className="max-w-[52rem] px-6 max-sm:px-4 pb-2">
      <div className="flex flex-wrap items-start gap-x-4 gap-y-1 border-b border-rule py-4">
        <div className="min-w-0 flex-1">
          <Switch
            id={`${id}-enabled`}
            checked={values.enabled}
            onChange={(v) => set("enabled", v)}
            label={mode === "mine" ? "Notify me outside the board" : "Notify people outside the board"}
          />
          <p className="mt-1 pl-11 text-xs text-muted">
            {values.enabled ? "blueboard sends the notices you pick below to the delivery channels you turn on." : "Nothing is sent. Your choices below are kept for when you turn this back on."}
          </p>
        </div>
        <Inherit {...p} path="enabled" />
      </div>

      <div className={cx("transition-opacity duration-150", off && "opacity-60")}>
        <Fieldset legend={mode === "mine" ? "Notify me about" : "Notify people about"}>
          <EventRow {...p} k="approvals" checked={values.events.approvals} />
          <EventRow {...p} k="mention" checked={values.events.mention}>
            <SubCheck {...p} path="mentions_from_people" checked={values.mentions_from_people} disabled={!values.events.mention} label="Include mentions from people, not only agents" />
          </EventRow>
          <EventRow {...p} k="question" checked={values.events.question} />
          <EventRow {...p} k="reply" checked={values.events.reply} />
          <EventRow {...p} k="verdict" checked={values.events.verdict} label="An agent's verdict is…">
            <ClassificationPicker {...p} value={values.verdict_classifications} disabled={!values.events.verdict} />
          </EventRow>
          <EventRow {...p} k="finding" checked={values.events.finding} label="Findings on incidents" />
          <EventRow {...p} k="incident" checked={values.events.incident} label="New incidents" />
          <SeverityRow {...p} value={values.min_incident_severity} disabled={!values.events.finding && !values.events.incident} />
          <EventRow {...p} k="action_result" checked={values.events.action_result} />
        </Fieldset>

        <Fieldset legend="Quiet hours" help="Hold notices during these hours. They aren't queued for later; the board still has them.">
          <Row {...p} path="quiet_hours.enabled">
            <Check
              id={`${id}-qh`}
              checked={values.quiet_hours.enabled}
              onChange={(v) => {
                set("quiet_hours.enabled", v);
                // A personal schedule should follow the person's clock: pin the browser's zone on first use.
                if (v && mode === "mine" && !field("quiet_hours.time_zone").overridden && values.quiet_hours.time_zone !== browserTimeZone())
                  set("quiet_hours.time_zone", browserTimeZone());
              }}
              label="Pause notifications during quiet hours"
            />
          </Row>
          <div className={cx("grid gap-x-4 gap-y-3 py-2 pl-6 sm:grid-cols-[10rem_10rem_minmax(0,1fr)]", !values.quiet_hours.enabled && "opacity-60")}>
            <Stacked {...p} path="quiet_hours.start" label="From" htmlFor={`${id}-qs`}>
              <Input id={`${id}-qs`} type="time" className="w-full" value={values.quiet_hours.start} disabled={!values.quiet_hours.enabled} onChange={(e) => e.target.value && set("quiet_hours.start", e.target.value)} />
            </Stacked>
            <Stacked {...p} path="quiet_hours.end" label="To" htmlFor={`${id}-qe`}>
              <Input id={`${id}-qe`} type="time" className="w-full" value={values.quiet_hours.end} disabled={!values.quiet_hours.enabled} onChange={(e) => e.target.value && set("quiet_hours.end", e.target.value)} />
            </Stacked>
            <Stacked {...p} path="quiet_hours.time_zone" label="Time zone" htmlFor={`${id}-tz`}>
              <Select id={`${id}-tz`} className="w-full" value={tz} disabled={!values.quiet_hours.enabled} onChange={(e) => set("quiet_hours.time_zone", e.target.value)}>
                {zones.map((z) => (
                  <option key={z} value={z}>
                    {z.replace(/_/g, " ")}
                    {z === browserTimeZone() ? " (this browser)" : ""}
                  </option>
                ))}
              </Select>
            </Stacked>
          </div>
          <SubCheck
            {...p}
            path="quiet_hours.except_high_severity"
            checked={values.quiet_hours.except_high_severity}
            disabled={!values.quiet_hours.enabled}
            label="Still notify me about high-severity incidents"
          />
        </Fieldset>

        <Fieldset legend="Message content">
          <Row {...p} path="include_summary">
            <Check id={`${id}-sum`} checked={values.include_summary} onChange={(v) => set("include_summary", v)} label="Include a short message summary" />
            <p className="mt-0.5 pl-6 text-xs text-muted">
              The summary is agent-written text from the board, and it leaves the board: it lands in the webhook, Teams, ntfy or mailbox. Off sends only the event, the incident and a link.
            </p>
          </Row>
        </Fieldset>

        <Fieldset legend="Delivery" help="Webhook URLs, Teams settings, the ntfy server and mail credentials are set by the board admin in the deployment's environment variables, never on this page.">
          {SINK_KEYS.map((k) => (
            <SinkRow key={k} {...p} k={k} checked={values.sinks[k]} status={sinks.find((s) => s.sink === k)} />
          ))}
        </Fieldset>
      </div>
    </div>
  );
}

type RowBase = { field: (path: string) => FieldState; reset?: (path: string) => void; mode: "mine" | "defaults" };

/** "Board default: On", or "Your setting · board default: Off" with Reset to default. Board defaults have no parent. */
function Inherit({ field, reset, mode, path, name, stacked }: RowBase & { path: string; name?: string; stacked?: boolean }) {
  if (mode !== "mine" || !reset) return null;
  const f = field(path);
  const def = describeValue(path, f.defaultValue);
  if (!f.overridden) return <span className="label whitespace-nowrap pt-0.5">Board default: {def}</span>;
  return (
    <span className={cx("flex gap-x-2 pt-0.5", stacked ? "flex-col items-start" : "flex-wrap items-center justify-end")}>
      <span className="label whitespace-nowrap text-ink-2">
        Yours <span className="text-muted">· default {def}</span>
      </span>
      <button
        type="button"
        onClick={() => reset(path)}
        aria-label={`Reset ${name ?? path} to the board default (${def})`}
        className="whitespace-nowrap rounded-[4px] text-xs text-accent underline-offset-4 hover:underline"
      >
        Reset to default
      </button>
    </span>
  );
}

function Row({ children, path, name, ...p }: RowBase & { path: string; name?: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start gap-x-4 gap-y-1 py-2">
      <div className="min-w-0 flex-[1_1_18rem]">{children}</div>
      <Inherit {...p} path={path} name={name} />
    </div>
  );
}

function Stacked({ children, path, label, htmlFor, ...p }: RowBase & { path: string; label: string; htmlFor: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <label htmlFor={htmlFor} className="mb-1 block text-xs text-ink-2">
        {label}
      </label>
      {children}
      <div className="mt-1">
        <Inherit {...p} path={path} name={label} stacked />
      </div>
    </div>
  );
}

function EventRow({ k, checked, label, children, set, ...p }: RowBase & { k: EventKey; checked: boolean; label?: string; children?: ReactNode; set: (path: string, v: unknown) => void }) {
  const id = useId();
  const text = label ?? EVENT_LABELS[k];
  return (
    <div className="border-b border-rule last:border-0">
      <Row {...p} path={`events.${k}`} name={text}>
        <Check id={id} checked={checked} onChange={(v) => set(`events.${k}`, v)} label={text} describedBy={`${id}-d`} />
        <p id={`${id}-d`} className="mt-0.5 pl-6 text-xs text-muted">
          {EVENT_HELP[k]}
        </p>
      </Row>
      {children}
    </div>
  );
}

function SubCheck({ path, checked, disabled, label, set, ...p }: RowBase & { path: string; checked: boolean; disabled?: boolean; label: string; set: (path: string, v: unknown) => void }) {
  const id = useId();
  return (
    <div className="pl-6">
      <Row {...p} path={path} name={label}>
        <Check id={id} checked={checked} disabled={disabled} onChange={(v) => set(path, v)} label={label} small />
      </Row>
    </div>
  );
}

function ClassificationPicker({ value, disabled, set, ...p }: RowBase & { value: string[]; disabled: boolean; set: (path: string, v: unknown) => void }) {
  const toggle = (c: string, on: boolean) => {
    const next = on ? [...value, c] : value.filter((x) => x !== c);
    set("verdict_classifications", CLASSIFICATIONS.map((x) => x.value).filter((x) => next.includes(x)));
  };
  return (
    <div className="pb-2 pl-6">
      <div className="flex flex-wrap items-start gap-x-4 gap-y-1">
        <fieldset className="min-w-0 flex-[1_1_18rem]" disabled={disabled}>
          <legend className="sr-only">Verdict classifications that notify</legend>
          <div className="flex flex-wrap gap-1.5">
            {CLASSIFICATIONS.map((c) => {
              const on = value.includes(c.value);
              return (
                <label
                  key={c.value}
                  className={cx(
                    "inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-[var(--radius-control)] border px-2 text-xs transition-colors duration-150 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-focus",
                    on ? "border-accent bg-accent-soft text-ink" : "border-control bg-paper-2 text-ink-2 hover:border-ink-2",
                    disabled && "cursor-not-allowed opacity-50",
                  )}
                >
                  <input type="checkbox" className="size-3.5 accent-[var(--color-accent)] focus-visible:outline-none" checked={on} onChange={(e) => toggle(c.value, e.target.checked)} />
                  {c.label}
                </label>
              );
            })}
          </div>
          {!disabled && value.length === 0 && <p className="mt-1 text-xs text-warning">No classification picked, so verdicts never notify.</p>}
        </fieldset>
        <Inherit {...p} path="verdict_classifications" name="verdict classifications" />
      </div>
    </div>
  );
}

function SeverityRow({ value, disabled, set, ...p }: RowBase & { value: string; disabled: boolean; set: (path: string, v: unknown) => void }) {
  const id = useId();
  return (
    <div className="border-b border-rule pb-2 pl-6">
      <Row {...p} path="min_incident_severity" name="incident severity threshold">
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor={id} className="text-ui text-ink-2">
            For findings and new incidents, only at or above
          </label>
          <Select id={id} value={value} disabled={disabled} onChange={(e) => set("min_incident_severity", e.target.value)}>
            {SEVERITIES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </Select>
        </div>
      </Row>
    </div>
  );
}

function SinkRow({ k, checked, status, set, ...p }: RowBase & { k: SinkKey; checked: boolean; status?: SinkStatus; set: (path: string, v: unknown) => void }) {
  const id = useId();
  const ready = !!status?.ready;
  const state = ready ? (
    <Tag tone="good">Ready</Tag>
  ) : !status?.configured ? (
    <Tag>Not configured</Tag>
  ) : (
    <Tag tone="critical">Problem</Tag>
  );
  return (
    <div className="border-b border-rule last:border-0">
      <Row {...p} path={`sinks.${k}`} name={SINK_LABELS[k]}>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Check id={id} checked={checked && ready} disabled={!ready} onChange={(v) => set(`sinks.${k}`, v)} label={SINK_LABELS[k]} describedBy={`${id}-s`} />
          {state}
        </div>
        <p id={`${id}-s`} className={cx("mt-0.5 pl-6 text-xs [overflow-wrap:anywhere]", status?.problem && !ready ? "text-critical" : "text-muted")}>
          {ready
            ? checked
              ? "Notices go here."
              : "Ready, but off for you."
            : status?.configured
              ? `Problem: ${status.problem ?? "not ready"}`
              : "The admin hasn't set this up in the deployment."}
        </p>
      </Row>
    </div>
  );
}

function Fieldset({ legend, help, children }: { legend: string; help?: string; children: ReactNode }) {
  return (
    <fieldset className="border-b border-rule py-4 last:border-0">
      <legend className="float-left w-full text-sm font-semibold">{legend}</legend>
      {help && <p className="clear-both pt-1 text-xs text-muted">{help}</p>}
      <div className="clear-both pt-1">{children}</div>
    </fieldset>
  );
}

function Check({ id, checked, onChange, label, disabled, small, describedBy }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean; small?: boolean; describedBy?: string }) {
  return (
    <span className="inline-flex items-start gap-2">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        aria-describedby={describedBy}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 size-4 shrink-0 accent-[var(--color-accent)] disabled:cursor-not-allowed"
      />
      <label htmlFor={id} className={cx(small ? "text-ui text-ink-2" : "text-ui text-ink", disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer")}>
        {label}
      </label>
    </span>
  );
}

/** The master switch: role="switch", Space/Enter toggle (native button). On/Off is also written, not colour alone. */
function Switch({ id, checked, onChange, label }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <span className="inline-flex items-center gap-3">
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cx(
          "relative inline-flex h-5 w-8 shrink-0 items-center rounded-full border transition-colors duration-150",
          checked ? "border-accent bg-accent" : "border-control bg-paper-3",
        )}
      >
        <span className={cx("absolute size-3.5 rounded-full transition-[left,background-color] duration-150", checked ? "left-[14px] bg-accent-ink" : "left-[2px] bg-muted")} />
      </button>
      <label htmlFor={id} className="cursor-pointer text-sm font-semibold text-ink">
        {label}
      </label>
      <span className="label" aria-hidden>
        {checked ? "On" : "Off"}
      </span>
    </span>
  );
}

function SendTest() {
  const id = useId();
  const [event, setEvent] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [results, setResults] = useState<TestResult[] | null>(null);
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setResults(await api<TestResult[]>("/notifications/test", { method: "POST", body: JSON.stringify(event ? { event } : {}) }));
    } catch (e) {
      setResults(null);
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section aria-labelledby={`${id}-h`} className="max-w-[52rem] px-6 max-sm:px-4 pb-6">
      <div className="border-t border-rule pt-4">
      <h2 id={`${id}-h`} className="text-sm font-semibold">
        Send a test
      </h2>
      <p className="mt-0.5 text-xs text-muted">Sends a sample notice to you, through the delivery channels above, using your current settings.</p>
      <form
        className="mt-2 flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
      >
        <div>
          <label htmlFor={`${id}-ev`} className="mb-1 block text-xs text-ink-2">
            Sample event
          </label>
          <Select id={`${id}-ev`} value={event} onChange={(e) => setEvent(e.target.value)}>
            <option value="">Generic test notice</option>
            {(Object.keys(EVENT_LABELS) as EventKey[]).map((k) => (
              <option key={k} value={k}>
                {EVENT_LABELS[k]}
              </option>
            ))}
          </Select>
        </div>
        <Button type="submit" loading={busy}>
          Send test
        </Button>
      </form>
      <div aria-live="polite">
        {err && (
          <div className="mt-2">
            <ErrorLine>{err}</ErrorLine>
          </div>
        )}
        {results && results.length === 0 && <p className="mt-2 text-xs text-warning">Nothing was sent: no delivery channel is on and ready for you.</p>}
        {results && results.length > 0 && (
          <ul className="mt-2 space-y-1 text-xs">
            {results.map((r) => (
              <li key={r.sink} className="flex flex-wrap items-baseline gap-2">
                <Tag tone={r.ok ? "good" : "critical"}>{r.ok ? "sent" : "failed"}</Tag>
                <span className="text-ink">{SINK_LABELS[r.sink as SinkKey] ?? r.sink}</span>
                <span className={cx("[overflow-wrap:anywhere]", r.ok ? "text-muted" : "text-critical")}>{r.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      </div>
    </section>
  );
}

const STATUS_TONE = { sent: "good", failed: "critical", sending: "neutral" } as const;

function RecentDeliveries() {
  const { data, error } = useLiveQuery<Delivery[]>("/notifications/recent?limit=50");
  return (
    <section aria-label="Recent deliveries">
      <p className="px-6 max-sm:px-4 pt-4 text-xs text-muted">The last 50 notices the board tried to send, newest first. Updates every few seconds.</p>
      {error && <Empty title="Couldn't load recent deliveries">{error.message}</Empty>}
      {data?.length === 0 && <Empty title="Nothing sent yet">Notices appear here once an event matches someone's settings.</Empty>}
      {data && data.length > 0 && (
        <div className="mt-2 overflow-x-auto">
          <table className="w-full min-w-[48rem] text-left text-ui">
            <caption className="sr-only">Recent notification deliveries</caption>
            <thead className="label">
              <tr className="border-b border-rule">
                <th className="px-6 max-sm:px-4 py-2 font-normal">When</th>
                <th className="py-2 pr-4 font-normal">Event</th>
                <th className="py-2 pr-4 font-normal">Channel</th>
                <th className="py-2 pr-4 font-normal">Recipient</th>
                <th className="py-2 pr-4 font-normal">Status</th>
                <th className="py-2 pr-6 max-sm:pr-4 font-normal">Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.map((d, i) => (
                <tr key={`${d.created_at}-${d.sink}-${i}`} className="border-b border-rule align-top last:border-0">
                  <td className="px-6 max-sm:px-4 py-2">
                    <Time iso={d.created_at} />
                  </td>
                  <td className="py-2 pr-4 text-ink-2">{EVENT_LABELS[d.event as EventKey] ?? d.event}</td>
                  <td className="py-2 pr-4 text-ink-2">{SINK_LABELS[d.sink as SinkKey] ?? d.sink}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-ink-2 [overflow-wrap:anywhere]">{d.recipient ?? <span className="text-faint">all</span>}</td>
                  <td className="py-2 pr-4">
                    <Tag tone={STATUS_TONE[d.status] ?? "neutral"}>{d.status}</Tag>
                  </td>
                  <td className="max-w-80 py-2 pr-6 max-sm:pr-4 text-xs">
                    {d.error && <p className="text-critical [overflow-wrap:anywhere]">{d.error}</p>}
                    {(d.message_id || d.action_id) && (
                      <p className="label [overflow-wrap:anywhere]">
                        {d.message_id && `message ${d.message_id.slice(0, 8)}`}
                        {d.message_id && d.action_id && " · "}
                        {d.action_id && `action ${d.action_id.slice(0, 8)}`}
                      </p>
                    )}
                    {!d.error && !d.message_id && !d.action_id && <span className="text-faint">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
