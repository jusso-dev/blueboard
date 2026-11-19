import { useEffect, useRef, useState, type RefObject } from "react";
import { useLocation } from "react-router";
import { api, refreshAll, useLiveQuery, type Message } from "../lib/api";
import { iocPayload, IOC_KINDS, IOC_VERDICTS, type IocDraft } from "../lib/ioc";
import { MessageRow } from "./message";
import { useListNav } from "./shortcuts";
import { Button, cx, Empty, ErrorLine, Input, Select } from "./ui";

const POST_TYPES = ["chat", "question", "finding", "ioc", "verdict", "status"] as const;
const NEW_IOC: IocDraft = { kind: "ip", value: "", verdict: "suspicious" };

export function Composer({
  channel,
  parentId,
  incident,
  placeholder,
}: {
  channel: string;
  parentId?: string;
  incident?: string | null;
  placeholder: string;
}) {
  const [body, setBody] = useState("");
  const [type, setType] = useState<(typeof POST_TYPES)[number]>("chat");
  const [ioc, setIoc] = useState<IocDraft>(NEW_IOC);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const isIoc = type === "ioc";

  const submit = async () => {
    const payload = isIoc ? iocPayload(ioc) : undefined;
    if (typeof payload === "string") return setErr(payload);
    // An IOC needs no prose: the body defaults to a one-line description of the indicator.
    const text = body.trim() || (isIoc ? `Indicator: ${ioc.kind} ${ioc.value.trim()} (${ioc.verdict})` : "");
    if (!text || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await api("/messages", {
        method: "POST",
        body: JSON.stringify({ channel, type, body: text, payload, parent_id: parentId, incident: incident ?? undefined }),
      });
      setBody("");
      setType("chat");
      setIoc(NEW_IOC);
      refreshAll();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="shrink-0 border-t border-rule p-3"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <div
        className={cx(
          "rounded-[var(--radius-card)] border bg-paper-2 transition-colors duration-150 focus-within:border-accent",
          err ? "border-critical" : "border-control",
        )}
      >
        {isIoc && (
          <fieldset className="flex flex-wrap items-center gap-2 border-b border-rule px-2 py-2">
            <legend className="sr-only">Indicator</legend>
            <Select aria-label="Indicator kind" value={ioc.kind} onChange={(e) => setIoc({ ...ioc, kind: e.target.value as IocDraft["kind"] })} className="h-7 text-xs">
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
              className="h-7 min-w-40 flex-1 font-mono text-xs"
            />
            <Select aria-label="Indicator verdict" value={ioc.verdict} onChange={(e) => setIoc({ ...ioc, verdict: e.target.value as IocDraft["verdict"] })} className="h-7 text-xs">
              {IOC_VERDICTS.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </Select>
          </fieldset>
        )}
        <label className="sr-only" htmlFor={`composer-${parentId ?? channel}`}>
          {isIoc ? "Note about the indicator (optional)" : placeholder}
        </label>
        <textarea
          id={`composer-${parentId ?? channel}`}
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault();
              void submit();
            }
          }}
          rows={2}
          placeholder={isIoc ? "Why it matters (optional)" : placeholder}
          className="block w-full resize-none bg-transparent px-3 pt-2.5 text-sm text-ink placeholder:text-faint focus:outline-none"
        />
        <div className="flex items-center gap-2 px-2 pb-2">
          <Select aria-label="Message type" value={type} onChange={(e) => setType(e.target.value as never)} className="h-7 text-xs">
            {POST_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </Select>
          <span className="label ml-auto truncate max-sm:hidden" title="Enter to send · Shift+Enter for a new line">
            {parentId ? "Enter to send" : "Enter to send · Shift+Enter for a new line"}
          </span>
          <Button type="submit" size="sm" variant="primary" loading={busy} disabled={isIoc ? !ioc.value.trim() : !body.trim()}>
            Send
          </Button>
        </div>
      </div>
      {err && (
        <div className="mt-1.5">
          <ErrorLine>{err}</ErrorLine>
        </div>
      )}
    </form>
  );
}

export function ThreadPanel({ rootId, onClose, focusReply }: { rootId: string; onClose: () => void; focusReply?: number }) {
  const { data, error } = useLiveQuery<{ root: Message; replies: Message[] }>(`/threads/${rootId}`);
  const end = useRef<HTMLDivElement>(null);
  const count = data?.replies.length ?? 0;
  useEffect(() => {
    end.current?.scrollIntoView({ block: "end" });
  }, [count]);

  return (
    <aside aria-label="Thread" className="flex min-h-0 flex-col border-l border-rule bg-paper max-lg:fixed max-lg:inset-y-0 max-lg:right-0 max-lg:z-20 max-lg:w-[min(440px,100vw)]">
      <div className="flex h-12 shrink-0 items-center border-b border-rule pl-5 pr-2">
        <h2 className="flex-1 text-sm font-semibold">Thread</h2>
        <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close thread">
          Close
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <Empty title="Couldn't load this thread">{error.message}</Empty>}
        {data && (
          <>
            <MessageRow m={data.root} showChannel />
            {data.replies.map((r) => (
              <MessageRow key={r.id} m={r} showIncident={false} />
            ))}
            <div ref={end} />
          </>
        )}
      </div>
      {data && <ReplyFocus rootId={data.root.id} signal={focusReply} />}
      {data && <Composer channel={data.root.channel} parentId={data.root.id} placeholder="Reply in thread" />}
    </aside>
  );
}

/** Moves focus to the thread's reply box when `signal` changes (the `r` shortcut). */
function ReplyFocus({ rootId, signal }: { rootId: string; signal?: number }) {
  useEffect(() => {
    if (signal) document.getElementById(`composer-${rootId}`)?.focus();
  }, [signal, rootId]);
  return null;
}

/**
 * Feed + optional thread panel. Used for channel and incident views. Keyboard: j/k select a message, Enter opens
 * its thread, r opens it and focuses the reply box, Esc closes the panel. Pass `thread`/`onThread` to open a thread
 * from outside (the incident summary does).
 */
export function Feed({
  query,
  composer,
  emptyTitle,
  showChannel,
  thread: controlled,
  onThread,
}: {
  query: string;
  composer: { channel: string; incident?: string | null; placeholder: string };
  emptyTitle: string;
  showChannel?: boolean;
  thread?: string | null;
  onThread?: (id: string | null) => void;
}) {
  const { data, error } = useLiveQuery<{ messages: Message[] }>(`/messages?${query}&limit=100`);
  const [own, setOwn] = useState<string | null>(null);
  const thread = controlled !== undefined ? controlled : own;
  const setThread = onThread ?? setOwn;
  const [replySignal, setReplySignal] = useState(0);
  const end = useRef<HTMLDivElement>(null);
  const count = data?.messages.length ?? 0;
  // #m-<id> in the URL (after requesting an action): scroll to that message and open its thread, where status replies land.
  const { hash } = useLocation();
  const target = hash.startsWith("#m-") ? hash.slice(3) : null;
  const shown = useRef<string | null>(null);
  const rootOf = (m: Message) => m.parent_id ?? m.id;
  const nav = useListNav(data?.messages, (m) => m.id, {
    onOpen: (m) => setThread(rootOf(m)),
    onReply: (m) => {
      setThread(rootOf(m));
      setReplySignal((n) => n + 1);
    },
    onEscape: () => {
      if (!thread) return false;
      setThread(null);
      return true;
    },
  });
  useEffect(() => {
    if (target && data?.messages.some((m) => m.id === target)) {
      if (shown.current !== target) {
        shown.current = target;
        setThread(target);
        document.getElementById(`m-${target}`)?.scrollIntoView({ block: "center" });
      }
      return;
    }
    end.current?.scrollIntoView({ block: "end" });
  }, [count, query, target, data]);
  useEffect(() => setThread(null), [query]);

  return (
    <div className={cx("grid min-h-0 flex-1", thread ? "grid-cols-[minmax(0,1fr)_minmax(340px,440px)] max-lg:grid-cols-1" : "grid-cols-1")}>
      <section className="flex min-h-0 min-w-0 flex-col">
        <div ref={nav.container as RefObject<HTMLDivElement>} className="min-h-0 flex-1 overflow-y-auto" aria-live="polite" aria-busy={!data && !error}>
          {error && <Empty title="Couldn't load messages">{error.message}</Empty>}
          {data && data.messages.length === 0 && <Empty title={emptyTitle} />}
          {data?.messages.map((m) => (
            <MessageRow
              key={m.id}
              m={m}
              onOpenThread={(x) => setThread(x.id)}
              showChannel={showChannel}
              selected={thread === m.id || nav.selected === m.id}
              navProps={nav.rowProps(m)}
            />
          ))}
          <div ref={end} />
        </div>
        <Composer {...composer} />
      </section>
      {thread && <ThreadPanel rootId={thread} onClose={() => setThread(null)} focusReply={replySignal} />}
    </div>
  );
}
