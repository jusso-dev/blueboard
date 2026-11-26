import { Link } from "react-router";
import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent, type Ref } from "react";
import { Markdown } from "./markdown";
import { api, refreshAll, useLiveQuery, type Action, type Message } from "../lib/api";
import { quickReactions, reactedBy, reactionLabel, shortcodeOf, toggleReaction, type Reaction } from "../lib/emoji";
import { EmojiPicker, usePicker } from "./emoji";
import { useDisplayNames } from "./mentions";
import { InlineApproval, useCanDecide } from "./approval";
import { clockTime, fullTime, gutterTime, relativeTime, type ReplySummary } from "../lib/chat";
import { useMe } from "./shell";
import type { NavRowProps } from "./shortcuts";
import { Avatar, Button, cx, ErrorLine, KindBadge, Tag } from "./ui";
import { IconCheck, IconChevronRight, IconLink, IconReply, IconSmilePlus } from "./icons";
import { RequestActionButton, useCanRequest } from "./request-action";
import { targetFromIoc } from "../lib/actions";

const CLAIMABLE = new Set(["question", "finding", "ioc"]);

/** Only the few types that change what a reader should do get a tone; the rest stay neutral. */
const TYPE_TONE: Record<string, "critical" | "warning" | "accent" | "good" | "neutral"> = {
  incident: "critical",
  action_request: "warning",
  action_result: "good",
  question: "accent",
};

const TYPE_LABEL: Record<string, string> = { action_request: "action", action_result: "result" };

const VERDICT_LABEL: Record<string, string> = {
  truePositive: "true positive",
  falsePositive: "false positive",
  informationalExpectedActivity: "expected activity",
  unknown: "unknown",
};

/** Bodies taller than this (about 24 lines at 20 px) collapse to CLAMP_TO with "Show more". */
const CLAMP_OVER = 480;
const CLAMP_TO = 240;

/** Permalink to a message: its channel, scrolled to the thread root (the feed opens the thread). */
export function permalink(m: Message): string {
  return `${location.origin}/channels/${encodeURIComponent(m.channel)}#m-${m.parent_id ?? m.id}`;
}

export type TimeStyle = "clock" | "relative";

function useClamp(enabled: boolean) {
  const ref = useRef<HTMLDivElement>(null);
  const [tall, setTall] = useState(false);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || !enabled) return;
    const check = () => setTall(el.scrollHeight > CLAMP_OVER);
    check();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(check);
    ro.observe(el);
    return () => ro.disconnect();
  }, [enabled]);
  return { ref, tall };
}

/** Arrow keys move between the toolbar's buttons (one tab stop's worth of controls, APG toolbar). */
function toolbarKeys(e: KeyboardEvent<HTMLDivElement>) {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  const items = [...e.currentTarget.querySelectorAll<HTMLElement>("button:not([disabled])")];
  const i = items.indexOf(document.activeElement as HTMLElement);
  if (i < 0) return;
  e.preventDefault();
  e.stopPropagation();
  items[(i + (e.key === "ArrowRight" ? 1 : items.length - 1)) % items.length]?.focus();
}

function CopyLink({ m }: { m: Message }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <button
      type="button"
      aria-label={copied ? "Link copied" : "Copy link to message"}
      title={copied ? "Link copied" : "Copy link"}
      onClick={() => {
        void navigator.clipboard?.writeText(permalink(m)).then(() => setCopied(true));
      }}
      className="inline-flex size-7 items-center justify-center rounded-[4px] text-muted transition-colors duration-150 hover:bg-paper-3 hover:text-ink"
    >
      {copied ? <IconCheck /> : <IconLink />}
    </button>
  );
}

/** The roll-up under a thread root: who replied, how many, when. The whole row opens the thread. */
function ThreadSummary({ s, onOpen }: { s: ReplySummary; onOpen: () => void }) {
  const n = `${s.count} ${s.count === 1 ? "reply" : "replies"}`;
  const last = s.lastAt ? relativeTime(s.lastAt) : null;
  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label={`View thread: ${n}${last ? `, last reply ${last}` : ""}`}
      className="group/sum -ml-1 mt-1 flex h-8 w-full max-w-[36rem] items-center gap-2 rounded-[var(--radius-control)] border border-transparent px-1 text-left transition-colors duration-150 hover:border-rule hover:bg-paper focus-visible:border-rule focus-visible:bg-paper"
    >
      {s.authors.length > 0 && (
        <span className="flex shrink-0 items-center gap-1">
          {s.authors.map((a) => (
            <Avatar key={a.handle} handle={a.handle} name={a.display_name} kind={a.kind} size={24} />
          ))}
        </span>
      )}
      <span className="shrink-0 text-[13px] font-semibold text-accent">{n}</span>
      {last && (
        <span className="min-w-0 truncate text-[13px] text-muted">
          <span className="group-hover/sum:hidden group-focus-visible/sum:hidden">Last reply {last}</span>
          <span className="hidden group-hover/sum:inline group-focus-visible/sum:inline">View thread</span>
        </span>
      )}
      {!last && <span className="hidden text-[13px] text-muted group-hover/sum:inline group-focus-visible/sum:inline">View thread</span>}
      <IconChevronRight className="ml-auto shrink-0 text-muted opacity-0 transition-opacity duration-150 group-hover/sum:opacity-100 group-focus-visible/sum:opacity-100" />
    </button>
  );
}

const SETTLE_MS = 6000;

function sameReactions(a: readonly Reaction[], b: readonly Reaction[]) {
  return a.length === b.length && a.every((r, i) => r.emoji === b[i]!.emoji && r.count === b[i]!.count && r.handles.join() === b[i]!.handles.join());
}

/**
 * Reactions with an optimistic update: the click shows at once, the POST's answer replaces it, an error rolls it back.
 * The server's list wins again as soon as the next poll brings it.
 */
function useReactions(m: Message, me: string | undefined) {
  const [local, setLocal] = useState<Reaction[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const pending = useRef(0);
  const settledAt = useRef(0);
  const server = m.reactions;
  // A poll already in flight when the POST went out can bring the old list back: keep ours until the server agrees,
  // or for one more poll (someone else may have reacted meanwhile).
  useEffect(() => {
    if (pending.current > 0 || local === null) return;
    if (sameReactions(server ?? [], local) || Date.now() - settledAt.current > SETTLE_MS) setLocal(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server]);
  const list = local ?? server ?? [];
  const toggle = async (emoji: string) => {
    if (!me) return;
    const { op, next } = toggleReaction(list, emoji, me);
    setLocal(next);
    setErr(null);
    pending.current++;
    try {
      const out = await api<Reaction[]>(`/messages/${m.id}/reactions`, { method: "POST", body: JSON.stringify({ emoji, op }) });
      pending.current--;
      settledAt.current = Date.now();
      if (pending.current === 0 && Array.isArray(out)) setLocal(out);
    } catch (e) {
      pending.current--;
      setLocal(null);
      setErr(`Couldn't ${op === "add" ? "add" : "remove"} ${shortcodeOf(emoji)}: ${(e as Error).message}`);
    } finally {
      refreshAll();
    }
  };
  return { list, toggle, err };
}

/** Pill row under the body: emoji and count, accent when I reacted; the last pill adds a reaction. */
function Reactions({ list, me, onToggle, onAdd, interactive }: { list: Reaction[]; me: string | undefined; onToggle: (emoji: string) => void; onAdd: (el: HTMLElement) => void; interactive: boolean }) {
  const nameOf = useDisplayNames();
  if (!list.length) return null;
  return (
    <div role="group" aria-label="Reactions" className="mt-1 flex flex-wrap items-center gap-1">
      {list.map((r) => {
        const mine = reactedBy(r, me);
        const label = reactionLabel(r, nameOf);
        return (
          <button
            key={r.emoji}
            type="button"
            title={label}
            aria-label={`${label}. ${mine ? "Remove your reaction" : `React with ${shortcodeOf(r.emoji)}`}`}
            aria-pressed={mine}
            disabled={!interactive}
            onClick={() => onToggle(r.emoji)}
            className={cx(
              "inline-flex h-6 items-center gap-1 rounded-full border px-2 transition-colors duration-150 disabled:cursor-default [@media(pointer:coarse)]:h-8",
              mine ? "border-accent bg-accent-soft text-accent hover:bg-accent-soft/70" : "border-transparent bg-paper-3 text-ink-2 hover:border-rule-strong enabled:hover:text-ink",
            )}
          >
            <span aria-hidden className="text-[15px] leading-none">
              {r.emoji}
            </span>
            <span aria-hidden className="tnum text-xs font-semibold leading-none">
              {r.count}
            </span>
          </button>
        );
      })}
      {interactive && (
        <button
          type="button"
          aria-label="Add reaction"
          title="Add reaction"
          onClick={(e) => onAdd(e.currentTarget)}
          className="inline-flex h-6 w-8 items-center justify-center rounded-full border border-transparent bg-paper-3 text-muted transition-colors duration-150 hover:border-rule-strong hover:text-ink [@media(pointer:coarse)]:h-8"
        >
          <IconSmilePlus />
        </button>
      )}
    </div>
  );
}

/** Ids of actions still waiting on a person (the shell's rail polls the same path, so this costs nothing extra). */
function useOpenActionIds(enabled: boolean): Set<string> | undefined {
  const { data } = useLiveQuery<Action[]>(enabled ? "/actions?status=open" : null);
  const [ids, setIds] = useState<Set<string>>();
  useEffect(() => {
    if (data) setIds(new Set(data.map((a) => a.id)));
  }, [data]);
  return ids;
}

/**
 * The approval card under an action_request message. It appears for an approver while the action is open and stays
 * mounted after a decision, so the person sees the outcome instead of the card vanishing under their cursor.
 */
function ActionRequestCard({ m }: { m: Message }) {
  const canDecide = useCanDecide();
  const actionId: string | undefined = m.payload?.action_id;
  const maybeOpen = canDecide && !!actionId && ["pending_approval", "approved_once"].includes(m.payload?.status);
  const open = useOpenActionIds(maybeOpen);
  const [shown, setShown] = useState(false);
  useEffect(() => {
    if (actionId && open?.has(actionId)) setShown(true);
  }, [open, actionId]);
  return shown && actionId ? <InlineApproval actionId={actionId} /> : null;
}

export function MessageRow({
  m,
  onOpenThread,
  showChannel,
  showIncident = true,
  selected,
  navProps,
  grouped = false,
  orphan = false,
  replies,
  time = "relative",
  actions,
  clamp: clampLong = true,
  rootRef,
}: {
  m: Message;
  /** Open the thread this message belongs to (its root id). */
  onOpenThread?: (rootId: string) => void;
  showChannel?: boolean;
  showIncident?: boolean;
  selected?: boolean;
  navProps?: NavRowProps;
  /** Same author within 5 minutes: body only, time in the gutter on hover. */
  grouped?: boolean;
  /** A reply shown in a feed whose root isn't on the page. */
  orphan?: boolean;
  /** Thread roll-up for a root (omit in the thread panel). */
  replies?: ReplySummary | null;
  time?: TimeStyle;
  /** Hover toolbar: "full" (reply + copy link), "copy" (copy link only, in the thread panel). Default: full when the row can open a thread. */
  actions?: "full" | "copy" | "none";
  /** Collapse very long bodies behind "Show more" (off for the root in the thread panel). */
  clamp?: boolean;
  rootRef?: Ref<HTMLElement>;
}) {
  const me = useMe();
  const canRequest = useCanRequest();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const clamp = useClamp(clampLong && !m.snippet);
  const claimable = CLAIMABLE.has(m.type);
  const iocs: { kind: string; value: string; verdict: string }[] = m.type === "ioc" ? m.payload?.indicators ?? [] : [];
  const system = m.author.kind === "system";
  const mentionsMe = !!me && m.author.handle !== me.handle && (m.mentions ?? []).includes(me.handle);
  const typeWord = TYPE_LABEL[m.type] ?? m.type;
  const rootId = m.parent_id ?? m.id;
  const clamped = clamp.tall && !expanded;
  const toolbar = actions ?? (onOpenThread ? "full" : "none");
  const canReact = !!me;
  const reactions = useReactions(m, me?.handle);
  const picker = usePicker();
  const quick = canReact && toolbar !== "none" ? quickReactions() : [];

  const claim = async (op: "claim" | "done" | "release") => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/claims/${m.id}`, { method: "POST", body: JSON.stringify({ op }) });
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const when = time === "clock" ? clockTime(m.created_at) : relativeTime(m.created_at);
  const summary = `${m.author.display_name}${m.author.kind === "agent" ? ", agent" : system ? ", system" : ""}${m.type !== "chat" ? `, ${typeWord}` : ""}, ${when}${mentionsMe ? ", mentions you" : ""}: ${(m.snippet ?? m.body).replace(/<<|>>/g, "").slice(0, 140)}`;
  const tone = TYPE_TONE[m.type];

  return (
    <article
      id={`m-${m.id}`}
      ref={rootRef}
      {...navProps}
      tabIndex={navProps?.tabIndex ?? -1}
      aria-label={summary}
      className={cx(
        "group relative grid grid-cols-[36px_minmax(0,1fr)] gap-x-2 px-5 transition-colors duration-150 max-sm:px-3",
        "hover:bg-paper-2 focus-within:bg-paper-2 focus-visible:outline-offset-[-2px]",
        grouped ? "py-0.5" : "pb-1 pt-2",
        (selected || mentionsMe) && "bg-paper-2",
        mentionsMe && "before:absolute before:inset-y-0 before:left-0 before:w-0.5 before:bg-accent",
      )}
    >
      <div className="relative">
        {grouped ? (
          <a
            href={permalink(m)}
            title={fullTime(m.created_at)}
            tabIndex={-1}
            className="tnum block pt-[3px] text-right font-mono text-[10.5px] leading-4 text-faint opacity-0 transition-opacity duration-150 group-hover:opacity-100 group-has-[:focus-visible]:opacity-100 max-sm:hidden"
          >
            <time dateTime={m.created_at}>{gutterTime(m.created_at)}</time>
          </a>
        ) : (
          <Avatar handle={m.author.handle} name={m.author.display_name} kind={m.author.kind} />
        )}
      </div>

      <div className="min-w-0">
        {!grouped && (
          <header className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5 leading-5">
            <span className={cx("min-w-0 max-w-full truncate text-sm font-semibold", system ? "text-ink-2" : "text-ink")}>{m.author.display_name}</span>
            {(m.author.kind === "agent" || system) && (
              <span className="self-center">
                <KindBadge kind={m.author.kind} />
              </span>
            )}
            {m.type !== "chat" && (
              <span className="self-center">
                <Tag tone={tone ?? "neutral"}>{typeWord}</Tag>
              </span>
            )}
            {showIncident && m.incident_graph_id && m.incident_id && (
              <Link to={`/incidents/${m.incident_id}`} className="label tnum shrink-0 whitespace-nowrap hover:text-accent">
                INC {m.incident_graph_id}
              </Link>
            )}
            {showChannel && (
              <Link to={`/channels/${encodeURIComponent(m.channel)}`} className="label shrink-0 whitespace-nowrap hover:text-accent">
                #{m.channel}
              </Link>
            )}
            <a href={permalink(m)} title={fullTime(m.created_at)} className="label tnum shrink-0 whitespace-nowrap hover:text-ink-2 hover:underline">
              <time dateTime={m.created_at}>{when}</time>
            </a>
          </header>
        )}
        {mentionsMe && <span className="sr-only">Mentions you.</span>}

        {orphan && onOpenThread && (
          <p className="text-xs text-muted">
            <button type="button" onClick={() => onOpenThread(rootId)} className="hover:text-accent hover:underline">
              replied to a thread
            </button>
          </p>
        )}

        <div
          ref={clamp.ref}
          id={`b-${m.id}`}
          className={cx("chat-body relative min-w-0", clamped && "overflow-hidden", system && "[&_.md]:text-muted")}
          style={clamped ? { maxHeight: CLAMP_TO } : undefined}
        >
          <Markdown text={m.snippet ?? m.body} highlight={Boolean(m.snippet)} me={me?.handle} />
        </div>
        {clamp.tall && (
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={`b-${m.id}`}
            onClick={() => setExpanded((x) => !x)}
            className="mt-0.5 text-[13px] font-medium text-accent hover:underline"
          >
            {expanded ? "Show less" : "Show more"}
          </button>
        )}

        {iocs.length > 0 && (
          <div className="mt-1.5 max-w-2xl overflow-x-auto">
            <table className="w-full table-fixed text-xs">
              <caption className="sr-only">Indicators</caption>
              <colgroup>
                <col className="w-14" />
                <col />
                <col className="w-20" />
                {canRequest && <col className="w-14" />}
              </colgroup>
              <tbody className="font-mono">
                {iocs.map((i, k) => {
                  const target = canRequest ? targetFromIoc(i.kind, i.value) : null;
                  return (
                    <tr key={k} className="border-t border-rule first:border-t-0">
                      <td className="py-1 pr-3 align-top text-faint">{i.kind}</td>
                      <td className="py-1 pr-3 align-top text-ink-2 [overflow-wrap:anywhere]">{i.value}</td>
                      <td className={cx("py-1 text-right align-top", i.verdict === "malicious" ? "text-critical" : i.verdict === "suspicious" ? "text-warning" : "text-muted")}>
                        {i.verdict}
                      </td>
                      {canRequest && (
                        <td className="py-0.5 pl-2 text-right align-top font-sans">
                          {target ? <RequestActionButton targets={[target]} incident={m.incident_id} size="sm" label="Act" /> : null}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {m.type === "verdict" && m.payload?.classification && (
          <p className="label mt-1 text-ink-2">
            {VERDICT_LABEL[m.payload.classification] ?? m.payload.classification} · {Math.round((m.payload.confidence ?? 0) * 100)}% confidence
          </p>
        )}

        {claimable && (
          <footer className="mt-1 flex min-h-6 flex-wrap items-center gap-1">
            {m.claim_state === "open" && (
              <Button size="sm" variant="secondary" className="h-6 px-2" loading={busy} onClick={() => claim("claim")} title="Take this: others see you're on it">
                Claim
              </Button>
            )}
            {m.claim_state === "claimed" && (
              <span className="flex flex-wrap items-center gap-1">
                <span className="label">claimed by @{m.claimed_by}</span>
                {me && m.claimed_by === me.handle && (
                  <>
                    <Button size="sm" variant="secondary" className="h-6 px-2" disabled={busy} onClick={() => claim("done")}>
                      Mark done
                    </Button>
                    <Button size="sm" variant="ghost" className="h-6 px-2" disabled={busy} onClick={() => claim("release")}>
                      Release
                    </Button>
                  </>
                )}
              </span>
            )}
            {m.claim_state === "done" && <span className="label text-good">✓ handled by @{m.claimed_by}</span>}
            {err && <ErrorLine>{err}</ErrorLine>}
          </footer>
        )}

        {m.type === "action_request" && <ActionRequestCard m={m} />}

        <Reactions list={reactions.list} me={me?.handle} interactive={canReact} onToggle={(e) => void reactions.toggle(e)} onAdd={picker.toggle} />
        {reactions.err && <ErrorLine>{reactions.err}</ErrorLine>}

        {replies && onOpenThread && <ThreadSummary s={replies} onOpen={() => onOpenThread(rootId)} />}
      </div>

      {toolbar !== "none" && (
        <div
          role="toolbar"
          aria-label="Message actions"
          onKeyDown={toolbarKeys}
          className={cx(
            "absolute -top-4 right-4 z-[6] flex items-center gap-0.5 rounded-lg border border-rule-strong bg-paper-3 p-0.5 shadow-[var(--shadow-pop)]",
            "transition-opacity duration-150",
            picker.anchor
              ? "pointer-events-auto opacity-100"
              : "pointer-events-none opacity-0 group-hover:pointer-events-auto group-hover:opacity-100 group-has-[:focus-visible]:pointer-events-auto group-has-[:focus-visible]:opacity-100",
            grouped && "-top-5",
          )}
        >
          {quick.map((e) => {
            const mine = reactions.list.some((r) => r.emoji === e && reactedBy(r, me?.handle));
            return (
              <button
                key={e}
                type="button"
                aria-label={mine ? `Remove ${shortcodeOf(e)} reaction` : `React with ${shortcodeOf(e)}`}
                title={shortcodeOf(e)}
                aria-pressed={mine}
                onClick={() => void reactions.toggle(e)}
                className={cx("inline-flex size-7 items-center justify-center rounded-[4px] text-[16px] leading-none transition-colors duration-150 hover:bg-paper-2", mine && "bg-accent-soft")}
              >
                <span aria-hidden>{e}</span>
              </button>
            );
          })}
          {quick.length > 0 && (
            <>
              <button
                type="button"
                aria-haspopup="dialog"
                aria-expanded={!!picker.anchor}
                onClick={(e) => picker.toggle(e.currentTarget)}
                title="Find another reaction"
                className="inline-flex h-7 items-center gap-1.5 rounded-[4px] px-2 text-xs font-medium text-ink-2 transition-colors duration-150 hover:bg-paper-2 hover:text-ink"
              >
                <IconSmilePlus />
                React
              </button>
              <span aria-hidden className="mx-0.5 h-4 w-px bg-rule" />
            </>
          )}
          {onOpenThread && actions !== "copy" && (
            <button
              type="button"
              onClick={() => onOpenThread(rootId)}
              className="inline-flex h-7 items-center gap-1.5 rounded-[4px] px-2 text-xs font-medium text-ink-2 transition-colors duration-150 hover:bg-paper-2 hover:text-ink"
            >
              <IconReply />
              {m.parent_id ? "Open thread" : "Reply"}
            </button>
          )}
          <CopyLink m={m} />
        </div>
      )}
      {picker.anchor && (
        <EmojiPicker
          anchor={picker.anchor}
          label="Add a reaction"
          onPick={(e) => {
            const anchor = picker.anchor;
            picker.close();
            anchor?.focus({ preventScroll: true });
            void reactions.toggle(e);
          }}
          onClose={(restore) => {
            const anchor = picker.anchor;
            picker.close();
            if (restore) anchor?.focus({ preventScroll: true });
          }}
        />
      )}
    </article>
  );
}
