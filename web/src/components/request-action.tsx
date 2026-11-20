import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { api, ApiError, refreshAll, useLiveQuery, type Action, type Assessment, type CatalogEntry, type JsonSchema } from "../lib/api";
import { actionsFor, initialParams, MIN_JUSTIFICATION, MODE_WORDS, type ActionTarget } from "../lib/actions";
import { useMe } from "./shell";
import { Button, cx, ErrorLine, Input, Select, Tag } from "./ui";

/** Board.RequestActions maps to the "requester" role. Without it the button is never shown (the API also returns 403). */
export function useCanRequest() {
  const me = useMe();
  return !!me?.roles.includes("requester");
}

/**
 * "Request action" button. Opens a panel listing only the actions valid for this target and not disabled by policy,
 * a form built from the catalogue schema, and a live server-side policy preview. Hidden without Board.RequestActions.
 */
export function RequestActionButton({
  targets,
  incident,
  size = "md",
  label = "Request action",
}: {
  targets: ActionTarget[];
  incident: string | null;
  size?: "sm" | "md";
  label?: string;
}) {
  const canRequest = useCanRequest();
  const [open, setOpen] = useState(false);
  const [only] = targets;
  if (!canRequest || !only) return null;
  return (
    <>
      <Button
        size={size}
        variant={size === "sm" ? "ghost" : "secondary"}
        onClick={() => setOpen(true)}
        aria-haspopup="dialog"
        aria-label={targets.length === 1 ? `Request action on ${only.type} ${only.label}` : undefined}
      >
        {label}
      </Button>
      {open && <RequestActionPanel targets={[only, ...targets.slice(1)]} incident={incident} onClose={() => setOpen(false)} />}
    </>
  );
}

function RequestActionPanel({ targets, incident, onClose }: { targets: [ActionTarget, ...ActionTarget[]]; incident: string | null; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const navigate = useNavigate();
  const { data: catalog, error: catErr } = useLiveQuery<CatalogEntry[]>("/actions?catalog=true");
  const [targetIdx, setTargetIdx] = useState(0);
  const target = targets[targetIdx] ?? targets[0];
  const choices = useMemo(() => (catalog ? actionsFor(catalog, target.type) : []), [catalog, target.type]);
  const [kind, setKind] = useState("");
  const def = choices.find((c) => c.kind === kind) ?? choices[0];
  const [params, setParams] = useState<Record<string, unknown>>({});
  const [justification, setJustification] = useState("");
  const [lastPreview, setPreview] = useState<Assessment | null>(null);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
  }, []);

  // A new action kind or target resets the form to the schema defaults plus the target's evidence values. Keyed on
  // values, not objects: the catalogue and incident are re-polled every few seconds and must not wipe what was typed.
  const kindKey = def?.kind;
  const targetKey = JSON.stringify(target.params);
  useEffect(() => {
    if (def) setParams(initialParams(def.params, target.params));
  }, [kindKey, targetKey]);

  // Live preview: the server runs the same policy evaluation as a real request, without filing anything.
  useEffect(() => {
    if (!kindKey) return;
    let stale = false;
    const t = setTimeout(async () => {
      try {
        const r = await api<Assessment>("/actions/preview", { method: "POST", body: JSON.stringify({ kind: kindKey, params, incident }) });
        if (!stale) {
          setPreview(r);
          setPreviewErr(null);
        }
      } catch (e) {
        if (!stale) {
          setPreview(null);
          setPreviewErr((e as Error).message);
        }
      }
    }, 250);
    return () => {
      stale = true;
      clearTimeout(t);
    };
  }, [kindKey, params, incident]);

  const submit = async () => {
    if (!def || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const a = await api<Action>("/actions", { method: "POST", body: JSON.stringify({ kind: def.kind, params, justification: justification.trim(), incident }) });
      refreshAll();
      onClose();
      // Show the request where approvers see it: its thread in #containment.
      navigate(`/channels/containment${a.request_message_id ? `#m-${a.request_message_id}` : ""}`);
    } catch (e) {
      const ae = e as ApiError;
      setErr(ae.status === 429 && ae.retryAfter ? `${ae.message} (try again in ${ae.retryAfter}s)` : ae.message);
      setBusy(false);
    }
  };

  const shortJustification = justification.trim().length < MIN_JUSTIFICATION;
  // Never show (or act on) a preview for a different action than the one selected while the next one loads.
  const preview = lastPreview?.kind === def?.kind ? lastPreview : null;
  const rejected = preview?.outcome === "reject";

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      onCancel={onClose}
      className="fixed inset-y-0 right-0 left-auto m-0 h-dvh max-h-dvh w-[min(480px,100vw)] max-w-none border-l border-rule bg-paper p-0 text-ink backdrop:bg-paper/70"
    >
      <form
        className="flex h-full flex-col"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="flex h-12 shrink-0 items-center border-b border-rule pl-5 pr-2">
          <h2 id={titleId} className="flex-1 text-sm font-semibold">
            Request action
          </h2>
          <Button type="button" variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {targets.length > 1 && (
            <Field label="Target" htmlFor={`${titleId}-target`}>
              <Select id={`${titleId}-target`} className="w-full" value={targetIdx} onChange={(e) => setTargetIdx(Number(e.target.value))}>
                {targets.map((t, i) => (
                  <option key={i} value={i}>
                    {t.type}: {t.label}
                  </option>
                ))}
              </Select>
            </Field>
          )}
          {targets.length === 1 && (
            <p className="text-[13px] text-ink-2">
              <span className="label mr-2">{target.type}</span>
              <span className="[overflow-wrap:anywhere]">{target.label}</span>
            </p>
          )}

          {catErr && <ErrorLine>{catErr.message}</ErrorLine>}
          {catalog && choices.length === 0 && <p className="text-[13px] text-muted">Policy allows no actions on a {target.type}.</p>}
          {def && (
            <>
              <Field label="Action" htmlFor={`${titleId}-kind`}>
                <Select id={`${titleId}-kind`} className="w-full" value={def.kind} onChange={(e) => setKind(e.target.value)}>
                  {choices.map((c) => (
                    <option key={c.kind} value={c.kind}>
                      {c.title}
                      {c.mode ? ` · ${MODE_WORDS[c.mode] ?? c.mode}` : ""}
                    </option>
                  ))}
                </Select>
              </Field>

              <SchemaFields schema={def.params} values={params} onChange={setParams} idPrefix={titleId} />

              <Field
                label="Justification"
                htmlFor={`${titleId}-why`}
                hint={`Cite the evidence. At least ${MIN_JUSTIFICATION} characters (${justification.trim().length} so far).`}
              >
                <textarea
                  id={`${titleId}-why`}
                  required
                  minLength={MIN_JUSTIFICATION}
                  maxLength={4000}
                  rows={4}
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  aria-describedby={`${titleId}-why-hint`}
                  className="block w-full resize-y rounded-[var(--radius-control)] border border-control bg-paper-2 px-2.5 py-2 text-[13px] text-ink placeholder:text-faint transition-colors duration-150 hover:border-ink-2 focus-visible:border-accent focus-visible:outline-none"
                />
              </Field>

              <section aria-label="Policy preview" aria-live="polite" className="border-t border-rule pt-3">
                <p className="label pb-1">Policy preview</p>
                {previewErr && <ErrorLine>{previewErr}</ErrorLine>}
                {preview && (
                  <>
                    <p className={cx("text-[13px] font-medium", rejected ? "text-critical" : preview.outcome === "auto" ? "text-good" : "text-warning")}>
                      {preview.summary}
                    </p>
                    <p className="mt-0.5 text-xs text-muted">{preview.describe}</p>
                    {preview.outcome === "needs_approval" && (
                      <p className="label mt-1">
                        expires {preview.expires_in_hours} h after the request
                        {preview.confirm_target ? " · approver types the target to confirm" : ""}
                      </p>
                    )}
                    {preview.notes.length > 0 && !rejected && (
                      <ul className="mt-1.5 space-y-0.5">
                        {preview.notes.map((n, i) => (
                          <li key={i} className="flex gap-2 text-xs text-warning">
                            <span aria-hidden>⚠</span>
                            <span>{n}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </>
                )}
              </section>
            </>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2 border-t border-rule px-5 py-3">
          {err ? <ErrorLine>{err}</ErrorLine> : <span className="text-xs text-muted">{def?.destructive ? "Destructive: a person must approve it." : ""}</span>}
          <Button type="submit" variant="primary" className="ml-auto" loading={busy} disabled={!def || shortJustification || rejected}>
            Request
          </Button>
        </div>
      </form>
    </dialog>
  );
}

function Field({ label, htmlFor, hint, children }: { label: string; htmlFor: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label htmlFor={htmlFor} className="mb-1 block text-xs text-ink-2">
        {label}
      </label>
      {children}
      {hint && (
        <p id={`${htmlFor}-hint`} className="mt-1 text-[11px] text-faint">
          {hint}
        </p>
      )}
    </div>
  );
}

/** Inputs generated from an action's JSON schema: enums become selects, integers number inputs, the rest text. */
export function SchemaFields({
  schema,
  values,
  onChange,
  idPrefix,
}: {
  schema: JsonSchema;
  values: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
  idPrefix: string;
}) {
  const required = new Set(schema.required ?? []);
  return (
    <>
      {Object.entries(schema.properties ?? {}).map(([name, p]) => {
        const id = `${idPrefix}-p-${name}`;
        const set = (v: unknown) => {
          const next = { ...values };
          if (v === "" || v === undefined) delete next[name];
          else next[name] = v;
          onChange(next);
        };
        const label = `${name.replaceAll("_", " ")}${required.has(name) ? "" : " (optional)"}`;
        const v = values[name];
        if (p.type === "array") {
          // Arrays (purge_email messages) come from the evidence; show them read-only rather than as a raw JSON box.
          const items = Array.isArray(v) ? v : [];
          return (
            <Field key={name} label={label} htmlFor={id}>
              <ul id={id} className="space-y-0.5 font-mono text-xs text-ink-2">
                {items.length === 0 && <li className="text-faint">none in the evidence</li>}
                {items.map((it, i) => (
                  <li key={i} className="[overflow-wrap:anywhere]">
                    {Object.values(it as Record<string, unknown>).join(" · ")}
                  </li>
                ))}
              </ul>
            </Field>
          );
        }
        if (p.enum) {
          return (
            <Field key={name} label={label} htmlFor={id}>
              <Select id={id} className="w-full" value={String(v ?? "")} onChange={(e) => set(e.target.value)} required={required.has(name)}>
                {!required.has(name) && p.default === undefined && <option value="">(leave unchanged)</option>}
                {p.enum.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </Select>
            </Field>
          );
        }
        return (
          <Field key={name} label={label} htmlFor={id} hint={p.description}>
            <Input
              id={id}
              className="w-full font-mono"
              type={p.type === "integer" ? "number" : "text"}
              min={p.minimum}
              max={p.maximum}
              minLength={p.minLength}
              maxLength={p.maxLength}
              required={required.has(name)}
              value={v === undefined ? "" : String(v)}
              onChange={(e) => set(p.type === "integer" ? (e.target.value === "" ? "" : Number(e.target.value)) : e.target.value)}
              aria-describedby={p.description ? `${id}-hint` : undefined}
            />
          </Field>
        );
      })}
    </>
  );
}

/** Status tag shared by the incident panel and the approvals page. */
export function ActionStatusTag({ status }: { status: string }) {
  const tone = status === "succeeded" ? "good" : status === "failed" || status === "rejected" ? "critical" : status === "pending_approval" || status === "approved_once" ? "warning" : "neutral";
  return <Tag tone={tone}>{status === "approved_once" ? "1 of 2 approved" : status.replace("_", " ")}</Tag>;
}
