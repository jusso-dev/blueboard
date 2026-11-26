import { Fragment, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode, type RefObject, type UIEvent } from "react";
import { useLocation } from "react-router";
import { api, refreshAll, useLiveQuery, type Message } from "../lib/api";
import { isNearBottom, shouldFollow } from "../lib/scroll";
import { dayLabel, feedRows, replySummary, threadView } from "../lib/chat";
import { iocPayload, IOC_KINDS, IOC_VERDICTS, type IocDraft } from "../lib/ioc";
import { MessageRow } from "./message";
import { useAutocomplete, useMentionSource } from "./mentions";
import { EmojiPicker, useEmojiSource, usePicker } from "./emoji";
import { TypingLine, useTyping, useTypingPing } from "./typing";
import { completeShortcode, insertAtCaret, replaceShortcodes } from "../lib/emoji";
import { useMe } from "./shell";
import { useListNav } from "./shortcuts";
import { cx, Empty, ErrorLine, Input, Select, Spinner, useMediaQuery, useStoredState } from "./ui";
import { IconArrowDown, IconAt, IconBack, IconClose, IconSend, IconSmilePlus } from "./icons";

const POST_TYPES = ["chat", "question", "finding", "ioc", "verdict", "status"] as const;
const NEW_IOC: IocDraft = { kind: "ip", value: "", verdict: "suspicious" };

/** The composer grows with its text up to this share of the viewport, then scrolls. */
const GROW_MAX = 0.4;

export function Composer({
  channel,
  parentId,
  incident,
  placeholder,
  onSent,
  textareaRef,
}: {
  channel: string;
  parentId?: string;
  incident?: string | null;
  placeholder: string;
  /** Called after a successful post (the feed scrolls to the newest message). */
  onSent?: () => void;
  textareaRef?: RefObject<HTMLTextAreaElement | null>;
}) {
  const draftKey = `bb_draft:${parentId ? `t:${parentId}` : incident ? `i:${incident}` : `c:${channel}`}`;
  const [body, setBody] = useStoredState<string>(draftKey, "", "session");
  const [type, setType] = useState<(typeof POST_TYPES)[number]>("chat");
  const [ioc, setIoc] = useState<IocDraft>(NEW_IOC);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const own = useRef<HTMLTextAreaElement>(null);
  const ta = textareaRef ?? own;
  const isIoc = type === "ioc";
  const mentionSource = useMentionSource();
  const emojiSource = useEmojiSource();
  const sources = useMemo(() => [mentionSource, emojiSource], [mentionSource, emojiSource]);
  const mention = useAutocomplete({ value: body, setValue: setBody, textarea: ta, sources });
  const picker = usePicker();
  const scope = { channel, incident, thread: parentId };
  const typing = useTyping(scope);
  const ping = useTypingPing(scope);
  const id = `composer-${parentId ?? channel}`;
  const canSend = isIoc ? !!ioc.value.trim() : !!body.trim();

  // Auto-grow: one line at rest, up to 40% of the viewport, then the textarea scrolls.
  useLayoutEffect(() => {
    const el = ta.current;
    if (!el) return;
    el.style.height = "auto";
    const max = Math.round(window.innerHeight * GROW_MAX);
    el.style.height = `${Math.min(el.scrollHeight, max)}px`;
    el.style.overflowY = el.scrollHeight > max ? "auto" : "hidden";
  }, [body, ta]);

  const submit = async () => {
    const payload = isIoc ? iocPayload(ioc) : undefined;
    if (typeof payload === "string") return setErr(payload);
    // An IOC needs no prose: the body defaults to a one-line description of the indicator.
    const text = replaceShortcodes(body.trim()) || (isIoc ? `Indicator: ${ioc.kind} ${ioc.value.trim()} (${ioc.verdict})` : "");
    if (!text || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await api("/messages", {
        method: "POST",
        body: JSON.stringify({ channel, type, body: text, payload, parent_id: parentId, incident: incident ?? undefined }),
      });
      setBody("");
      ping.reset();
      setType("chat");
      setIoc(NEW_IOC);
      onSent?.();
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      aria-label={placeholder.replace(/…$/, "")}
      className="shrink-0 px-6 pb-2 pt-2 max-sm:px-4"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <div className="relative" data-mention-anchor>
        {mention.popup}
        <div
          className={cx(
            "rounded-lg border bg-paper-2 transition-colors duration-150 has-[.composer-input:focus-visible]:border-focus has-[.composer-input:focus-visible]:outline has-[.composer-input:focus-visible]:outline-1 has-[.composer-input:focus-visible]:outline-focus",
            err ? "border-critical" : "border-control",
          )}
        >
          {isIoc && (
            <fieldset className="flex flex-wrap items-center gap-2 border-b border-rule px-2 py-2">
              <legend className="sr-only">Indicator</legend>
              <Select aria-label="Indicator kind" value={ioc.kind} onChange={(e) => setIoc({ ...ioc, kind: e.target.value as IocDraft["kind"] })} className="text-ui">
                {IOC_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </Select>
              <Input
                aria-label="Indicator value"
                value={ioc.value}
                onChange={(e) => setIoc({ ...ioc, value: e.target.value })}
                placeholder="203.0.113.50, bad.example, a hash"
                maxLength={2048}
                className="min-w-0 flex-1 basis-40 font-mono text-ui"
              />
              <Select aria-label="Indicator verdict" value={ioc.verdict} onChange={(e) => setIoc({ ...ioc, verdict: e.target.value as IocDraft["verdict"] })} className="text-ui">
                {IOC_VERDICTS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </Select>
            </fieldset>
          )}
          <label className="sr-only" htmlFor={id}>
            {isIoc ? "Note about the indicator (optional)" : placeholder}
          </label>
          <textarea
            id={id}
            ref={ta}
            value={body}
            {...mention.inputProps}
            onChange={(e) => {
              const el = e.target;
              // Typing the closing ":" of a known shortcode converts it on the spot, as Slack does.
              const done = el.selectionStart === el.selectionEnd ? completeShortcode(el.value, el.selectionStart) : null;
              if (done) mention.setValueAt(done.text, done.caret);
              else setBody(el.value);
              ping.onDraft(el.value);
            }}
            onKeyDown={(e) => {
              if (mention.onKeyDown(e)) return;
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing && e.keyCode !== 229) {
                e.preventDefault();
                void submit();
              }
            }}
            rows={1}
            maxLength={20000}
            placeholder={isIoc ? "Why it matters (optional)" : placeholder}
            className="composer-input block min-h-10 w-full resize-none bg-transparent px-3 py-2.5 text-message text-ink placeholder:text-faint focus:outline-none"
          />
          <div className="flex items-center gap-1 px-1.5 pb-1.5">
            <Select
              aria-label="Message type"
              value={type}
              onChange={(e) => setType(e.target.value as never)}
              className="h-9 border-transparent bg-transparent pl-1.5 text-ui text-muted hover:border-control hover:text-ink"
            >
              {POST_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
            <span aria-hidden className="mx-0.5 h-4 w-px bg-rule" />
            <button
              type="button"
              aria-label="Mention someone"
              title="Mention someone"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => mention.insertTrigger("@")}
              className="inline-flex size-9 items-center justify-center rounded-[4px] text-muted transition-colors duration-150 hover:bg-paper-3 hover:text-ink [@media(pointer:coarse)]:size-11"
            >
              <IconAt />
            </button>
            <button
              type="button"
              aria-label="Emoji"
              title="Emoji"
              aria-haspopup="dialog"
              aria-expanded={!!picker.anchor}
              onMouseDown={(e) => e.preventDefault()}
              onClick={(e) => picker.toggle(e.currentTarget)}
              className={cx(
                "inline-flex size-9 items-center justify-center rounded-[4px] transition-colors duration-150 hover:bg-paper-3 hover:text-ink [@media(pointer:coarse)]:size-11",
                picker.anchor ? "bg-paper-3 text-ink" : "text-muted",
              )}
            >
              <IconSmilePlus />
            </button>
            <button
              type="submit"
              aria-label="Send"
              title="Send"
              disabled={!canSend || busy}
              className={cx(
                "ml-auto inline-flex size-9 items-center justify-center rounded-[4px] transition-colors duration-150 [@media(pointer:coarse)]:size-11",
                canSend ? "bg-accent text-accent-ink hover:bg-focus" : "text-faint",
                "disabled:cursor-not-allowed",
              )}
            >
              {busy ? <Spinner /> : <IconSend />}
            </button>
          </div>
        </div>
      </div>
      {picker.anchor && (
        <EmojiPicker
          anchor={picker.anchor}
          label="Insert emoji"
          onPick={(char) => {
            const el = ta.current;
            const start = el?.selectionStart ?? body.length;
            const end = el?.selectionEnd ?? start;
            const next = insertAtCaret(body, start, end, char);
            picker.close();
            el?.focus();
            mention.setValueAt(next.text, next.caret);
          }}
          onClose={(restore) => {
            picker.close();
            if (restore) ta.current?.focus();
          }}
        />
      )}
      <div className="flex min-h-5 items-start gap-2 pt-0.5">
        <div className="min-w-0 flex-1">{err ? <ErrorLine>{err}</ErrorLine> : <TypingLine list={typing} />}</div>
        {/* Only while drafting, so an empty composer gives the typing line the full width. */}
        {body && (
          <p aria-hidden className="shrink-0 text-meta leading-5 text-muted max-sm:hidden">
            <span className="font-semibold text-ink-2">Shift + Return</span> to add a new line
          </p>
        )}
      </div>
      {mention.status}
    </form>
  );
}

// ── thread panel ─────────────────────────────────────────────────────────────────────────────

const PANEL_KEY = "bb_thread_width";
const PANEL_DEFAULT = 420;
const PANEL_MIN = 320;
/** The channel column keeps at least this much room beside the panel. */
const CHANNEL_MIN = 480;
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function clampWidth(w: number, room: number) {
  const max = Math.max(PANEL_MIN, Math.min(window.innerWidth * 0.5, room - CHANNEL_MIN));
  return Math.round(Math.max(PANEL_MIN, Math.min(max, w)));
}

/**
 * The thread beside the channel (≥ 1024 px, resizable, not modal), an overlay sheet below that, and full screen
 * below 640 px. Focus moves to the root message on open (or the reply box with `focusComposer`) and returns to the
 * control that opened it on close.
 */
export function ThreadPanel({
  rootId,
  onClose,
  focusComposer,
  onComposerFocused,
}: {
  rootId: string;
  onClose: () => void;
  focusComposer?: boolean;
  onComposerFocused?: () => void;
}) {
  const { data, error } = useLiveQuery<{ root: Message; replies: Message[] }>(`/threads/${rootId}`);
  const wide = useMediaQuery("(min-width: 1024px)");
  const phone = useMediaQuery("(max-width: 639px)");
  const [stored, setStored] = useStoredState<string>(PANEL_KEY, String(PANEL_DEFAULT));
  const [width, setWidth] = useState(() => Number(stored) || PANEL_DEFAULT);
  const [room, setRoom] = useState(() => (typeof window === "undefined" ? 1600 : window.innerWidth));
  const ref = useRef<HTMLElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const rootEl = useRef<HTMLElement>(null);
  const composer = useRef<HTMLTextAreaElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const focusedRoot = useRef<string | null>(null);

  // Remember who opened the panel; give focus back on close.
  useEffect(() => {
    opener.current = document.activeElement as HTMLElement | null;
    return () => {
      const back = opener.current;
      if (back?.isConnected) back.focus({ preventScroll: true });
    };
  }, []);

  // The channel column beside a docked panel keeps CHANNEL_MIN; with less room the panel becomes an overlay sheet.
  useLayoutEffect(() => {
    const parent = ref.current?.parentElement;
    if (!parent) return;
    setRoom(parent.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setRoom(parent.clientWidth));
    ro.observe(parent);
    return () => ro.disconnect();
  }, []);
  const docked = wide && room >= CHANNEL_MIN + PANEL_MIN;
  const shown = clampWidth(width, room);

  const loaded = !!data;
  useEffect(() => {
    if (!loaded) return;
    if (focusComposer) {
      composer.current?.focus();
      focusedRoot.current = rootId;
      onComposerFocused?.();
      return;
    }
    if (focusedRoot.current !== rootId) {
      focusedRoot.current = rootId;
      rootEl.current?.focus({ preventScroll: true });
    }
  }, [loaded, rootId, focusComposer, onComposerFocused]);

  // Follow new replies when the reader is at the end; start at the end of a long thread.
  const count = data?.replies.length ?? 0;
  const near = useRef(false);
  const seen = useRef<{ root: string; count: number } | null>(null);
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el || !loaded) return;
    const prev = seen.current;
    if (!prev || prev.root !== rootId) el.scrollTop = 0;
    else if (count > prev.count && near.current) el.scrollTop = el.scrollHeight;
    seen.current = { root: rootId, count };
  }, [loaded, count, rootId]);

  const onKeyDown = (e: ReactKeyboardEvent<HTMLElement>) => {
    if (e.key === "Escape" && !e.defaultPrevented) {
      e.preventDefault();
      onClose();
      return;
    }
    // As an overlay sheet the panel is modal: Tab stays inside.
    if (e.key === "Tab" && !docked) {
      const els = [...(ref.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])].filter((x) => x.offsetParent !== null);
      if (!els.length) return;
      const first = els[0]!;
      const last = els[els.length - 1]!;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  const drag = (e: ReactPointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    const startX = e.clientX;
    const start = shown;
    const target = e.currentTarget;
    target.setPointerCapture(e.pointerId);
    let last = start;
    const move = (ev: PointerEvent) => {
      last = clampWidth(start + (startX - ev.clientX), room);
      setWidth(last);
    };
    const up = () => {
      target.removeEventListener("pointermove", move);
      target.removeEventListener("pointerup", up);
      target.removeEventListener("pointercancel", up);
      setStored(String(last));
    };
    target.addEventListener("pointermove", move);
    target.addEventListener("pointerup", up);
    target.addEventListener("pointercancel", up);
  };

  const resizeKeys = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    const step = e.shiftKey ? 64 : 16;
    let next: number | null = null;
    if (e.key === "ArrowLeft") next = shown + step;
    else if (e.key === "ArrowRight") next = shown - step;
    else if (e.key === "Home") next = PANEL_MIN;
    else if (e.key === "End") next = Number.MAX_SAFE_INTEGER;
    if (next === null) return;
    e.preventDefault();
    e.stopPropagation();
    const w = clampWidth(next, room);
    setWidth(w);
    setStored(String(w));
  };

  const channel = data?.root.channel;
  const replyRows = useMemo(() => feedRows(data?.replies ?? []), [data?.replies]);
  const label = channel ? `Thread in #${channel}` : "Thread";

  const panel = (
    <aside
      ref={ref}
      aria-label={label}
      role={docked ? undefined : "dialog"}
      aria-modal={docked ? undefined : true}
      onKeyDown={onKeyDown}
      style={docked ? { width: shown } : undefined}
      className={cx(
        "flex min-h-0 flex-col bg-paper",
        docked ? "relative shrink-0 border-l border-rule" : phone ? "fixed inset-0 z-40" : "fixed inset-y-0 right-0 z-40 w-[min(420px,100vw)] border-l border-rule-strong",
      )}
    >
      {docked && (
        <div
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize thread panel"
          aria-valuemin={PANEL_MIN}
          aria-valuemax={clampWidth(Number.MAX_SAFE_INTEGER, room)}
          aria-valuenow={shown}
          tabIndex={0}
          onPointerDown={drag}
          onKeyDown={resizeKeys}
          onDoubleClick={() => {
            setWidth(PANEL_DEFAULT);
            setStored(String(PANEL_DEFAULT));
          }}
          title="Drag to resize · double-click to reset"
          className="absolute inset-y-0 -left-[3px] z-10 w-[6px] cursor-col-resize touch-none transition-colors duration-150 hover:bg-accent/40 focus-visible:bg-accent/60 focus-visible:outline-none"
        />
      )}
      <header className="flex min-h-14 shrink-0 items-center gap-2 border-b border-rule pl-6 pr-3 max-sm:pl-1">
        {phone && (
          <button type="button" onClick={onClose} aria-label="Back to the channel" className="inline-flex size-11 items-center justify-center rounded-[var(--radius-control)] text-muted hover:bg-paper-3 hover:text-ink">
            <IconBack />
          </button>
        )}
        <h2 className="flex min-w-0 flex-1 items-baseline gap-2">
          <span className="text-title font-semibold tracking-tight text-ink">Thread</span>
          {channel && <span className="truncate text-ui text-muted">#{channel}</span>}
        </h2>
        {!phone && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close thread"
            title="Close (Esc)"
            className="inline-flex size-8 items-center justify-center rounded-[var(--radius-control)] text-muted transition-colors duration-150 hover:bg-paper-3 hover:text-ink [@media(pointer:coarse)]:size-11"
          >
            <IconClose />
          </button>
        )}
      </header>
      <div ref={scroller} onScroll={(e) => (near.current = isNearBottom(e.currentTarget))} className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden pb-2 [overflow-anchor:auto]">
        {error && <Empty title="Couldn't load this thread">{error.message}</Empty>}
        {!data && !error && (
          <div className="flex justify-center py-10 text-muted">
            <Spinner />
          </div>
        )}
        {data && (
          <>
            <div className="pt-5">
              <MessageRow m={data.root} showChannel={false} time="relative" actions="copy" rootRef={rootEl} clamp={false} />
            </div>
            <div className="flex items-center gap-3 px-6 pb-2 pt-3 max-sm:px-4" role="separator" aria-label={`${count} ${count === 1 ? "reply" : "replies"}`}>
              <span className="shrink-0 text-ui text-muted">{count === 0 ? "No replies yet" : `${count} ${count === 1 ? "reply" : "replies"}`}</span>
              <span aria-hidden className="h-px flex-1 bg-rule" />
            </div>
            <div role="list" aria-label="Replies">
              {replyRows.map((r) => (
                <div role="listitem" key={r.m.id}>
                  <MessageRow m={r.m} showIncident={false} grouped={r.grouped} time="relative" actions="copy" />
                </div>
              ))}
            </div>
          </>
        )}
      </div>
      {data && (
        <div className="shrink-0 pt-1">
          <Composer channel={data.root.channel} parentId={data.root.id} placeholder="Reply…" textareaRef={composer} onSent={() => (near.current = true)} />
        </div>
      )}
    </aside>
  );

  if (docked) return panel;
  return (
    <>
      <div aria-hidden className="fixed inset-0 z-30 bg-paper/70" onMouseDown={onClose} />
      {panel}
    </>
  );
}

// ── feed ─────────────────────────────────────────────────────────────────────────────────────

/** A day's messages: a hairline with a pill label that sticks under the header while the day scrolls. */
function DaySection({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section aria-label={label} className="relative">
      <div aria-hidden className="absolute inset-x-0 top-[1.375rem] h-px bg-rule" />
      <div role="separator" aria-label={label} className="pointer-events-none sticky top-0 z-[5] flex justify-center py-2">
        <span className="pointer-events-auto inline-flex h-7 items-center rounded-full border border-rule-strong bg-paper px-4 text-ui font-semibold text-ink-2">{label}</span>
      </div>
      {children}
    </section>
  );
}

/**
 * Feed + optional thread panel. Used for channel and incident views. Roots only: replies live in the thread panel
 * (a reply whose root isn't on the page shows with a "replied to a thread" link). Keyboard: j/k select a message,
 * Enter opens its thread, r opens it and focuses the reply box, Esc closes the panel. Pass `thread`/`onThread` to
 * open a thread from outside (the incident summary does).
 */
export function Feed({
  query,
  composer,
  emptyTitle,
  showChannel,
  thread: controlled,
  onThread,
  label,
}: {
  query: string;
  composer: { channel: string; incident?: string | null; placeholder: string };
  emptyTitle: string;
  showChannel?: boolean;
  thread?: string | null;
  onThread?: (id: string | null) => void;
  /** Accessible name of the message list, e.g. "#triage". */
  label?: string;
}) {
  const { data, error } = useLiveQuery<{ messages: Message[] }>(`/messages?${query}&limit=100`);
  const me = useMe();
  const [own, setOwn] = useState<string | null>(null);
  const thread = controlled !== undefined ? controlled : own;
  const setThread = onThread ?? setOwn;
  const [replyFor, setReplyFor] = useState<string | null>(null);
  const list = useRef<HTMLDivElement | null>(null);

  const view = useMemo(() => threadView(data?.messages ?? []), [data]);
  const rows = useMemo(() => feedRows(view.visible, view.orphans), [view]);
  const visible = view.visible;
  const newest = visible[visible.length - 1]?.id;
  const count = visible.length;

  // #m-<id> in the URL (a permalink, or after requesting an action): scroll to that message and open its thread.
  const { hash } = useLocation();
  const target = hash.startsWith("#m-") ? hash.slice(3) : null;
  const shownTarget = useRef<string | null>(null);

  // Follow new messages only for a reader already at the bottom: the 4 s poll hands back a new object every tick.
  const nearBottom = useRef(true);
  const lastSeen = useRef<string | undefined>(undefined);
  const [far, setFar] = useState(false);
  const [unseen, setUnseen] = useState(0);
  const [announce, setAnnounce] = useState("");

  const rootOf = (m: Message) => m.parent_id ?? m.id;
  const nav = useListNav(visible, (m) => m.id, {
    onOpen: (m) => setThread(rootOf(m)),
    onReply: (m) => {
      setReplyFor(rootOf(m));
      setThread(rootOf(m));
    },
    onEscape: () => {
      if (!thread) return false;
      setThread(null);
      return true;
    },
  });
  const setList = useCallback(
    (el: HTMLDivElement | null) => {
      list.current = el;
      (nav.container as RefObject<HTMLElement | null>).current = el;
    },
    [nav.container],
  );

  const toBottom = useCallback(() => {
    const el = list.current;
    if (el) el.scrollTop = el.scrollHeight;
    nearBottom.current = true;
    setUnseen(0);
    setFar(false);
  }, []);

  useLayoutEffect(() => {
    const all = data?.messages;
    if (target && all) {
      const hit = all.find((m) => m.id === target);
      if (hit) {
        if (shownTarget.current !== target) {
          shownTarget.current = target;
          setThread(rootOf(hit));
          document.getElementById(`m-${rootOf(hit)}`)?.scrollIntoView({ block: "center" });
        }
        lastSeen.current = newest;
        return;
      }
    }
    const prev = lastSeen.current;
    const follow = shouldFollow(prev, newest, nearBottom.current);
    lastSeen.current = newest;
    if (prev !== undefined && newest !== undefined && newest !== prev) {
      const at = visible.findIndex((m) => m.id === prev);
      const fresh = (at >= 0 ? visible.slice(at + 1) : []).filter((m) => m.author.handle !== me?.handle);
      if (fresh.length) setAnnounce(fresh.length === 1 ? `New message from ${fresh[0]!.author.display_name}` : `${fresh.length} new messages`);
      if (!follow) setUnseen((n) => n + fresh.length);
    }
    if (follow) toBottom();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [count, query, target, data, newest]);

  // Rows that grow after they render (an approval card or reactions loading, "Show more") keep a reader who is at
  // the bottom pinned there.
  const content = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = content.current;
    const box = list.current;
    if (!el || !box || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => {
      if (nearBottom.current) box.scrollTop = box.scrollHeight;
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [!!data]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    setThread(null);
    lastSeen.current = undefined; // a new channel or incident starts at its newest message
    nearBottom.current = true;
    setUnseen(0);
    setFar(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  const onScroll = (e: UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    nearBottom.current = isNearBottom(el);
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    const isFar = distance > el.clientHeight;
    if (isFar !== far) setFar(isFar);
    if (nearBottom.current && unseen) setUnseen(0);
  };

  const now = new Date();
  const days: { key: string; label: string; rows: typeof rows }[] = [];
  for (const r of rows) {
    if (r.newDay || !days.length) days.push({ key: r.day, label: dayLabel(r.m.created_at, now), rows: [] });
    days[days.length - 1]!.rows.push(r);
  }

  const showJump = far || unseen > 0;

  return (
    <div className="flex min-h-0 min-w-0 flex-1">
      <section aria-label={label ?? composer.placeholder.replace(/^Message /, "")} className="relative flex min-h-0 min-w-0 flex-1 flex-col">
        <div className="relative min-h-0 flex-1">
          <div
            ref={setList}
            onScroll={onScroll}
            role="feed"
            aria-label="Messages"
            aria-busy={!data && !error}
            className="absolute inset-0 overflow-y-auto overflow-x-hidden pb-3 [overflow-anchor:auto]"
          >
            {error && <Empty title="Couldn't load messages">{error.message}</Empty>}
            {!data && !error && (
              <div className="flex justify-center py-16 text-muted">
                <Spinner />
              </div>
            )}
            {data && visible.length === 0 && <Empty title={emptyTitle}>Start the conversation below. Type @ to mention a person or an agent.</Empty>}
            <div ref={content}>
            {days.map((d) => (
              <DaySection key={d.key} label={d.label}>
                {d.rows.map((r) => (
                  <Fragment key={r.m.id}>
                    <MessageRow
                      m={r.m}
                      grouped={r.grouped}
                      orphan={r.orphan}
                      time="clock"
                      replies={r.m.parent_id ? null : replySummary(r.m, view.derived.get(r.m.id))}
                      onOpenThread={setThread}
                      showChannel={showChannel}
                      selected={thread === rootOf(r.m) || nav.selected === r.m.id}
                      navProps={nav.rowProps(r.m)}
                    />
                  </Fragment>
                ))}
              </DaySection>
            ))}
            </div>
          </div>
          {showJump && (
            <div className="pointer-events-none absolute inset-x-0 bottom-2 z-10 flex justify-center">
              <button
                type="button"
                onClick={toBottom}
                className="pointer-events-auto inline-flex h-7 items-center gap-1.5 rounded-full border border-rule-strong bg-paper-3 px-3 text-xs font-medium text-ink shadow-[var(--shadow-pop)] transition-colors duration-150 hover:border-accent hover:text-accent"
              >
                {unseen > 0 ? `${unseen} new ${unseen === 1 ? "message" : "messages"}` : "Jump to recent"}
                <IconArrowDown size={14} />
              </button>
            </div>
          )}
        </div>
        <Composer {...composer} onSent={toBottom} />
        <p role="status" aria-live="polite" className="sr-only">
          {announce}
        </p>
      </section>
      {thread && (
        <ThreadPanel
          key="thread"
          rootId={thread}
          onClose={() => setThread(null)}
          focusComposer={replyFor === thread}
          onComposerFocused={() => setReplyFor(null)}
        />
      )}
    </div>
  );
}
