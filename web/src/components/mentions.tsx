/**
 * Inline autocomplete for a textarea (APG editable combobox with list autocomplete): @mentions and :emoji: share one
 * set of mechanics. DOM focus stays in the textarea; the popup is a listbox driven by aria-activedescendant. Logic that
 * needs no DOM lives in lib/mentions.ts and lib/emoji.ts.
 */
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode, type RefObject } from "react";
import { useLiveQuery } from "../lib/api";
import { atInsertion, detectTrigger, insertMention, isActive, rankParticipants, type Participant } from "../lib/mentions";
import { Avatar, cx, KindBadge } from "./ui";

const MAX_ROWS = 50;
const POPUP_W = 448;

export function useParticipants() {
  return useLiveQuery<Participant[]>("/participants").data;
}

/** handle → display name, from the participants list (falls back to the handle). */
export function useDisplayNames(): (handle: string) => string {
  const people = useParticipants();
  const map = useMemo(() => new Map((people ?? []).map((p) => [p.handle, p.display_name])), [people]);
  return useCallback((h: string) => map.get(h) ?? h, [map]);
}

/** The caret's x offset inside a textarea, measured with a mirror element that copies its text metrics. */
function caretX(ta: HTMLTextAreaElement, index: number): number {
  const cs = getComputedStyle(ta);
  const div = document.createElement("div");
  const props = ["boxSizing", "width", "paddingLeft", "paddingRight", "borderLeftWidth", "borderRightWidth", "fontFamily", "fontSize", "fontWeight", "fontStyle", "letterSpacing", "lineHeight", "textTransform", "wordSpacing", "tabSize"] as const;
  for (const p of props) div.style[p] = cs[p];
  div.style.position = "absolute";
  div.style.visibility = "hidden";
  div.style.whiteSpace = "pre-wrap";
  div.style.overflowWrap = "break-word";
  div.style.top = "0";
  div.style.left = "-9999px";
  div.textContent = ta.value.slice(0, index);
  const mark = document.createElement("span");
  mark.textContent = "​";
  div.appendChild(mark);
  document.body.appendChild(div);
  const x = mark.offsetLeft - ta.scrollLeft;
  div.remove();
  return x;
}

type Trigger = { start: number; query: string };

/** One kind of token the composer completes ("@handle", ":emoji:"). */
export type AutocompleteSource<T> = {
  id: string;
  detect: (text: string, caret: number) => Trigger | null;
  /** null while the data is still loading (the popup stays closed). */
  items: (query: string) => T[] | null;
  key: (t: T) => string;
  insert: (text: string, trigger: Trigger, caret: number, t: T) => { text: string; caret: number };
  render: (t: T, selected: boolean) => ReactNode;
  heading: string;
  listLabel: string;
  empty: (query: string) => string;
  /** Called after an item is inserted. */
  onPick?: (t: T) => void;
};

export type AutocompleteState = ReturnType<typeof useAutocomplete>;

/**
 * Wire a controlled textarea to one or more autocomplete sources. Call `onKeyDown` first in the textarea's own key
 * handler: it returns true when it consumed the key. Spread `inputProps` on the textarea and render `popup` in a
 * relatively positioned wrapper (`data-mention-anchor`) around the composer.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function useAutocomplete({ value, setValue, textarea, sources }: { value: string; setValue: (v: string) => void; textarea: RefObject<HTMLTextAreaElement | null>; sources: AutocompleteSource<any>[] }) {
  const listId = useId();
  const [caret, setCaret] = useState<number | null>(null);
  const [active, setActive] = useState(0);
  // Esc closes the popup for this token only; a new token (or moving to another one) opens it again.
  const [dismissedAt, setDismissedAt] = useState<number | null>(null);
  const [left, setLeft] = useState(0);
  const pendingCaret = useRef<number | null>(null);

  const hit = useMemo(() => {
    if (caret === null) return null;
    for (const s of sources) {
      const t = s.detect(value, caret);
      if (t) return { source: s, trigger: t };
    }
    return null;
  }, [value, caret, sources]);
  const trigger = hit?.trigger ?? null;
  const source = hit?.source ?? null;
  const all = useMemo(() => (hit ? hit.source.items(hit.trigger.query) : null), [hit]);
  const open = !!hit && hit.trigger.start !== dismissedAt && !!all;
  const results = useMemo(() => (open && all ? all.slice(0, MAX_ROWS) : []), [open, all]);

  useEffect(() => setActive(0), [trigger?.query, trigger?.start, source?.id]);
  useEffect(() => {
    if (dismissedAt !== null && trigger?.start !== dismissedAt) setDismissedAt(null);
  }, [trigger?.start, dismissedAt]);

  // Keep the selected option in view; never move DOM focus to it.
  useEffect(() => {
    if (open) document.getElementById(`${listId}-o${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active, open, listId]);

  // Place the popup near the trigger character, clamped inside the composer.
  useLayoutEffect(() => {
    const ta = textarea.current;
    if (!open || !ta || !trigger) return;
    const box = ta.closest<HTMLElement>("[data-mention-anchor]") ?? ta.parentElement!;
    const width = Math.min(POPUP_W, box.clientWidth);
    const x = ta.getBoundingClientRect().left - box.getBoundingClientRect().left + caretX(ta, trigger.start) - 12;
    setLeft(Math.max(0, Math.min(x, box.clientWidth - width)));
  }, [open, trigger, textarea]);

  // After inserting, put the caret where the insert said.
  useLayoutEffect(() => {
    const ta = textarea.current;
    if (pendingCaret.current === null || !ta) return;
    ta.setSelectionRange(pendingCaret.current, pendingCaret.current);
    setCaret(pendingCaret.current);
    pendingCaret.current = null;
  }, [value, textarea]);

  /** Replace the text and put the caret at `at` after React commits it (also used by the emoji picker). */
  const setValueAt = useCallback(
    (text: string, at: number) => {
      pendingCaret.current = at;
      setValue(text);
    },
    [setValue],
  );

  const choose = useCallback(
    (item: unknown) => {
      if (item === undefined || !trigger || !source || caret === null) return;
      const next = source.insert(value, trigger, caret, item);
      setValueAt(next.text, next.caret);
      source.onPick?.(item);
      textarea.current?.focus();
    },
    [trigger, source, caret, value, setValueAt, textarea],
  );

  const sync = useCallback(() => {
    const ta = textarea.current;
    if (ta && document.activeElement === ta) setCaret(ta.selectionStart === ta.selectionEnd ? ta.selectionStart : null);
  }, [textarea]);

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>): boolean => {
    if (!open || e.nativeEvent.isComposing) return false;
    const n = results.length;
    switch (e.key) {
      case "ArrowDown":
        if (!n) return false;
        e.preventDefault();
        setActive((a) => (a + 1) % n);
        return true;
      case "ArrowUp":
        if (!n) return false;
        e.preventDefault();
        setActive((a) => (a - 1 + n) % n);
        return true;
      case "Enter":
      case "Tab":
        if (!n || e.shiftKey) return false;
        e.preventDefault();
        choose(results[active]);
        return true;
      case "Escape":
        e.preventDefault();
        e.stopPropagation();
        setDismissedAt(trigger!.start);
        return true;
      default:
        return false;
    }
  };

  const optionId = (i: number) => `${listId}-o${i}`;
  const inputProps = {
    role: "combobox" as const,
    "aria-autocomplete": "list" as const,
    "aria-expanded": open,
    "aria-controls": open ? listId : undefined,
    "aria-activedescendant": open && results.length ? optionId(active) : undefined,
    onSelect: sync,
    onInput: sync,
    onKeyUp: sync,
    onClick: sync,
    onBlur: () => setCaret(null),
    onFocus: sync,
  };

  /** Insert a trigger character at the caret (with a leading space after a word) and open its popup: the "@" button. */
  const insertTrigger = (ch: string) => {
    const ta = textarea.current;
    if (!ta) return;
    const at = ta.selectionStart ?? value.length;
    const end = ta.selectionEnd ?? at;
    const lead = atInsertion(value, at).replace("@", ch);
    setDismissedAt(null);
    setValueAt(value.slice(0, at) + lead + value.slice(end), at + lead.length);
    ta.focus();
  };

  const query = trigger?.query ?? "";
  const popup =
    open && source ? (
      <div
        className="@container absolute bottom-full z-30 mb-1.5 w-[min(28rem,100%)] overflow-hidden rounded-lg border border-rule-strong bg-paper-3 shadow-[var(--shadow-pop)]"
        style={{ left }}
      >
        <p className="label border-b border-rule px-3 py-1.5">{source.heading}</p>
        {results.length > 0 ? (
          <ul id={listId} role="listbox" aria-label={source.listLabel} className="max-h-64 overflow-y-auto py-1">
            {results.map((item, i) => (
              <li
                key={source.key(item)}
                id={optionId(i)}
                role="option"
                aria-selected={i === active}
                onMouseMove={i === active ? undefined : () => setActive(i)}
                onMouseDown={(e) => {
                  e.preventDefault(); // keep focus (and the caret) in the textarea
                  choose(item);
                }}
                className={cx(
                  "mx-1 flex h-8 cursor-pointer items-center gap-2 rounded-[4px] px-2 text-[13px] [@media(pointer:coarse)]:h-11",
                  i === active ? "bg-accent-soft text-ink" : "text-ink-2",
                )}
              >
                {source.render(item, i === active)}
              </li>
            ))}
          </ul>
        ) : (
          <p id={listId} className="px-3 py-3 text-[13px] text-muted">
            {source.empty(query)}
          </p>
        )}
        <p className="flex h-8 items-center gap-1 border-t border-rule bg-paper-2 px-3 text-[11px] text-muted max-sm:hidden">
          <span className="font-semibold text-ink-2">↑↓</span> to navigate · <span className="font-semibold text-ink-2">↵</span> to select · <span className="font-semibold text-ink-2">esc</span> to dismiss
        </p>
      </div>
    ) : null;

  const status = (
    <span role="status" aria-live="polite" className="sr-only">
      {open && source ? (results.length ? `${results.length} ${results.length === 1 ? "suggestion" : "suggestions"}` : source.empty(query)) : ""}
    </span>
  );

  return { open, inputProps, onKeyDown, popup, status, insertTrigger, setValueAt };
}

/** The @mention source: people and agents from /participants. */
export function useMentionSource(): AutocompleteSource<Participant> {
  const people = useParticipants();
  return useMemo(
    () => ({
      id: "mention",
      detect: detectTrigger,
      items: (q) => (people ? rankParticipants(people, q) : null),
      key: (p) => p.handle,
      insert: (text, t, caret, p) => insertMention(text, t, caret, p.handle),
      render: (p) => <MentionOption p={p} />,
      heading: "People and agents",
      listLabel: "Mention suggestions",
      empty: (q) => `No one matches “${q}”`,
    }),
    [people],
  );
}

function MentionOption({ p }: { p: Participant }) {
  const active = isActive(p, Date.now());
  return (
    <>
      <Avatar handle={p.handle} name={p.display_name} kind={p.kind} size={20} />
      <span className="flex min-w-0 shrink-[0.5] items-baseline gap-1.5">
        <span className="min-w-[3rem] shrink-[0.3] truncate font-semibold text-ink">{p.display_name}</span>
        <span className="min-w-0 shrink truncate text-muted">@{p.handle}</span>
      </span>
      {p.kind === "agent" && <KindBadge kind="agent" />}
      {active && (
        <span className="flex shrink-0 items-center gap-1 text-[11px] text-good">
          <span aria-hidden className="size-1.5 rounded-full bg-good" />
          active
        </span>
      )}
      {p.description && (
        <span title={p.description} className="ml-auto hidden min-w-0 shrink-[4] basis-40 truncate pl-2 text-right text-xs text-faint @[24rem]:block">
          {p.description}
        </span>
      )}
    </>
  );
}
