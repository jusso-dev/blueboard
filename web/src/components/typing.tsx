/**
 * "Enrichment Agent is typing…": the composer pings POST /typing while the person types (at most once every 3 s, never
 * for an empty draft) and polls GET /typing for its scope every 2 s, faster than the shared 4 s board poll because a
 * typing line that lags reads as broken. Scope is one of thread (root id), incident (id) or channel (name).
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { createTypingThrottle, typingScope, typingText, type Typist } from "../lib/emoji";

const POLL_MS = 2000;
/** After an error (an older API without /typing, or an outage) poll far less often. */
const BACKOFF_MS = 20000;

type Scope = { channel?: string; incident?: string | null; thread?: string | null };

function useScope(s: Scope) {
  const scope = typingScope(s);
  const qs = new URLSearchParams(scope).toString();
  return useMemo(() => ({ scope, qs }), [qs]); // eslint-disable-line react-hooks/exhaustive-deps
}

/** Who else is typing in this scope (the API leaves out the caller). */
export function useTyping(s: Scope): Typist[] {
  const { qs } = useScope(s);
  const [list, setList] = useState<Typist[]>([]);
  useEffect(() => {
    if (!qs) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      let wait = POLL_MS;
      if (document.visibilityState === "visible") {
        try {
          const r = await api<Typist[]>(`/typing?${qs}`);
          if (!stop) setList((prev) => (same(prev, r ?? []) ? prev : (r ?? [])));
        } catch {
          if (!stop) setList([]);
          wait = BACKOFF_MS;
        }
      }
      if (!stop) timer = setTimeout(tick, wait);
    };
    setList([]);
    void tick();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [qs]);
  return list;
}

function same(a: Typist[], b: Typist[]) {
  return a.length === b.length && a.every((x, i) => x.handle === b[i]!.handle && x.display_name === b[i]!.display_name);
}

/** Returns `onDraft(text)`: call it on every edit; it pings POST /typing when the throttle allows. `reset()` after sending. */
export function useTypingPing(s: Scope) {
  const { scope, qs } = useScope(s);
  const throttle = useRef(createTypingThrottle());
  const failed = useRef(false);
  useEffect(() => {
    throttle.current.reset();
    failed.current = false;
  }, [qs]);
  return useMemo(
    () => ({
      onDraft(text: string) {
        if (!qs || failed.current || !throttle.current.shouldSend(text)) return;
        api("/typing", { method: "POST", body: JSON.stringify(scope) }).catch((e: { status?: number }) => {
          // An API without the endpoint: stop trying for this scope. Other errors just wait for the next window.
          if (e?.status === 404 || e?.status === 405) failed.current = true;
        });
      },
      reset() {
        throttle.current.reset();
      },
    }),
    [scope, qs],
  );
}

/** A muted 12 px line with three dots. Its height is always reserved by the caller so the layout never jumps. */
export function TypingLine({ list }: { list: Typist[] }) {
  const text = typingText(list);
  return (
    <p aria-live="polite" aria-atomic="true" className="flex h-5 min-w-0 items-center gap-1.5 text-xs text-muted">
      {text && (
        <>
          <span aria-hidden className="typing-dots inline-flex shrink-0 items-center gap-[3px]">
            <span />
            <span />
            <span />
          </span>
          <span className="min-w-0 truncate">{text}</span>
        </>
      )}
    </p>
  );
}
