/**
 * Emoji picker: a non-modal dialog holding a search combobox whose popup is a grid (APG "combobox with grid popup").
 * DOM focus stays in the search box; arrow keys move the active cell (aria-activedescendant), Enter picks, Esc closes.
 * Category buttons form a toolbar (one tab stop, arrow keys inside). The `:shortcode:` autocomplete for the composer
 * is a source for the shared combobox in mentions.tsx.
 */
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { CATEGORIES, detectEmojiTrigger, emojiInfo, frequentEmoji, insertEmoji, recordEmojiUse, searchEmoji, type Emoji } from "../lib/emoji";
import type { AutocompleteSource } from "./mentions";
import { cx } from "./ui";
import { IconBall, IconBulb, IconClock, IconFlag, IconFood, IconLeaf, IconPlane, IconSearch, IconSmile, IconSymbols } from "./icons";

const COLS = 9;
const CELL = 36;
const WIDTH = COLS * CELL + 26; // grid + padding + border
const HEIGHT = 420;
const GAP = 6;
const EDGE = 8;

const CATEGORY_ICON: Record<string, (p: { size?: number }) => ReactNode> = {
  frequent: IconClock,
  people: IconSmile,
  nature: IconLeaf,
  food: IconFood,
  activity: IconBall,
  travel: IconPlane,
  objects: IconBulb,
  symbols: IconSymbols,
  flags: IconFlag,
};

type Section = { id: string; label: string; emoji: Emoji[] };

/** A frequent emoji that isn't in the table (an agent reacted with something rare) still gets a cell. */
function asEmoji(char: string): Emoji {
  return emojiInfo(char) ?? { char, name: char, aliases: [], keywords: [], category: "frequent" };
}

/** Where the popover goes: below the anchor if it fits (or fits better), else above; clamped inside the viewport. */
export function placePopover(anchor: DOMRect, size: { w: number; h: number }, view: { w: number; h: number }): { top: number; left: number; above: boolean } {
  const below = view.h - anchor.bottom - GAP - EDGE;
  const above = anchor.top - GAP - EDGE;
  const goAbove = below < size.h && above > below;
  const room = goAbove ? above : below;
  const h = Math.min(size.h, Math.max(room, 120));
  const top = goAbove ? Math.max(EDGE, anchor.top - GAP - h) : Math.min(view.h - EDGE - h, anchor.bottom + GAP);
  const left = Math.max(EDGE, Math.min(anchor.left, view.w - EDGE - size.w));
  return { top, left, above: goAbove };
}

export function EmojiPicker({
  anchor,
  onPick,
  onClose,
  label = "Emoji picker",
}: {
  /** The control that opened the picker: positions it, is ignored by click-outside, and gets focus back on close. */
  anchor: HTMLElement;
  onPick: (char: string) => void;
  /** `restore` is false when focus is already moving somewhere sensible (a click elsewhere). */
  onClose: (restore: boolean) => void;
  label?: string;
}) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const measure = useCallback(() => {
    const w = Math.min(WIDTH, window.innerWidth - 2 * EDGE);
    const p = placePopover(anchor.getBoundingClientRect(), { w, h: HEIGHT }, { w: window.innerWidth, h: window.innerHeight });
    return { top: p.top, left: p.left, w, h: Math.min(HEIGHT, window.innerHeight - 2 * EDGE) };
  }, [anchor]);
  // Measured at mount (not in an effect) so the dialog is visible, and focusable, on its first paint.
  const [pos, setPos] = useState(measure);
  const columns = Math.max(1, Math.min(COLS, Math.floor((pos.w - 26) / CELL)));
  const [inView, setInView] = useState("frequent");
  const frequent = useMemo(() => frequentEmoji(COLS * 2), []);

  const sections: Section[] = useMemo(() => {
    if (query.trim()) return [{ id: "results", label: "Search results", emoji: searchEmoji(query, 200, frequent) }];
    return [{ id: "frequent", label: "Frequently used", emoji: frequent.map(asEmoji) }, ...CATEGORIES];
  }, [query, frequent]);

  // Flat cells and visual rows (rows never span sections), for arrow-key movement.
  const { cells, rows, rowOf } = useMemo(() => {
    const cells: Emoji[] = [];
    const rows: number[][] = [];
    const rowOf: number[] = [];
    for (const s of sections)
      for (let i = 0; i < s.emoji.length; i += columns) {
        const row: number[] = [];
        for (const e of s.emoji.slice(i, i + columns)) {
          rowOf.push(rows.length);
          row.push(cells.length);
          cells.push(e);
        }
        rows.push(row);
      }
    return { cells, rows, rowOf };
  }, [sections, columns]);

  useEffect(() => setActive(0), [query]);
  const current = cells[active];
  const cellId = (i: number) => `${id}-c${i}`;

  // Position against the anchor; follow scrolling and resizing.
  useLayoutEffect(() => {
    const place = () => setPos(measure());
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [measure]);

  useLayoutEffect(() => {
    search.current?.focus({ preventScroll: true });
  }, []);

  // Click outside closes (the anchor toggles itself).
  useEffect(() => {
    const down = (e: MouseEvent) => {
      const t = e.target as Node;
      if (ref.current?.contains(t) || anchor.contains(t)) return;
      onClose(false);
    };
    document.addEventListener("mousedown", down);
    return () => document.removeEventListener("mousedown", down);
  }, [anchor, onClose]);

  // Keep the active cell in view without moving focus.
  useEffect(() => {
    document.getElementById(cellId(active))?.scrollIntoView({ block: "nearest" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  const pick = (e: Emoji | undefined) => {
    if (!e) return;
    recordEmojiUse(e.char);
    onPick(e.char);
  };

  const move = (key: string, caretAtEnd: boolean): boolean => {
    if (!cells.length) return false;
    const r = rowOf[active] ?? 0;
    const c = rows[r]!.indexOf(active);
    const toRow = (nr: number) => {
      const row = rows[Math.max(0, Math.min(rows.length - 1, nr))]!;
      setActive(row[Math.min(c, row.length - 1)]!);
    };
    switch (key) {
      case "ArrowDown":
        toRow(r + 1);
        return true;
      case "ArrowUp":
        toRow(r - 1);
        return true;
      case "ArrowRight":
        if (!caretAtEnd) return false;
        setActive(Math.min(cells.length - 1, active + 1));
        return true;
      case "ArrowLeft":
        if (!caretAtEnd) return false;
        setActive(Math.max(0, active - 1));
        return true;
      case "PageDown":
        toRow(r + 5);
        return true;
      case "PageUp":
        toRow(r - 5);
        return true;
      default:
        return false;
    }
  };

  const onSearchKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.nativeEvent.isComposing) return;
    const el = e.currentTarget;
    const caretAtEnd = el.selectionStart === el.value.length && el.selectionEnd === el.value.length;
    if (move(e.key, caretAtEnd)) {
      e.preventDefault();
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      pick(current);
    }
  };

  const onDialogKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      onClose(true);
    } else if (e.key === "Tab") {
      // Two stops: the category toolbar and the search box. Tab cycles between them; focus never falls out behind.
      const stops = [ref.current?.querySelector<HTMLElement>('[role=toolbar] button[tabindex="0"]'), search.current].filter(Boolean) as HTMLElement[];
      const i = stops.indexOf(document.activeElement as HTMLElement);
      e.preventDefault();
      stops[(i + (e.shiftKey ? stops.length - 1 : 1)) % stops.length]?.focus();
    }
    // Arrow keys and Enter never reach the message list, the toolbar or the thread panel behind the portal.
    e.stopPropagation();
  };

  const jump = (sid: string) => {
    setQuery("");
    requestAnimationFrame(() => {
      const el = document.getElementById(`${id}-s-${sid}`);
      const box = scroller.current;
      if (el && box) box.scrollTop = el.offsetTop - box.offsetTop;
      const first = document.querySelector<HTMLElement>(`#${CSS.escape(`${id}-s-${sid}`)} [role=gridcell]`);
      if (first?.dataset.index) setActive(Number(first.dataset.index));
      setInView(sid);
      search.current?.focus({ preventScroll: true });
    });
  };

  const onScroll = () => {
    const box = scroller.current;
    if (!box || query) return;
    let sid = "frequent";
    for (const s of sections) {
      const el = document.getElementById(`${id}-s-${s.id}`);
      if (el && el.offsetTop - box.offsetTop <= box.scrollTop + 8) sid = s.id;
    }
    if (sid !== inView) setInView(sid);
  };

  let index = 0;
  const tabs = [{ id: "frequent", label: "Frequently used" }, ...CATEGORIES.map((c) => ({ id: c.id, label: c.label }))];

  return createPortal(
    <div
      ref={ref}
      role="dialog"
      aria-label={label}
      onKeyDown={onDialogKey}
      onBlur={(e) => {
        if (e.relatedTarget && !ref.current?.contains(e.relatedTarget as Node) && !anchor.contains(e.relatedTarget as Node)) onClose(false);
      }}
      style={{ top: pos.top, left: pos.left, width: pos.w, height: pos.h }}
      className="fixed z-50 flex flex-col overflow-hidden rounded-lg border border-rule-strong bg-paper-3 text-ink shadow-[var(--shadow-pop)]"
    >
      <CategoryBar tabs={tabs} current={query ? "" : inView} onJump={jump} />
      <div className="px-3 pb-2 pt-2.5">
        <div className="flex h-8 items-center gap-2 rounded-[var(--radius-control)] border border-control bg-paper-2 px-2 transition-colors duration-150 focus-within:border-focus focus-within:outline focus-within:outline-1 focus-within:outline-focus">
          <IconSearch className="shrink-0 text-muted" />
          <input
            ref={search}
            type="text"
            role="combobox"
            aria-label="Search emoji"
            aria-expanded="true"
            aria-haspopup="grid"
            aria-controls={`${id}-grid`}
            aria-activedescendant={current ? cellId(active) : undefined}
            aria-autocomplete="list"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onSearchKey}
            placeholder="Search all emoji"
            autoComplete="off"
            spellCheck={false}
            className="bare-input min-w-0 flex-1 bg-transparent text-ui text-ink placeholder:text-faint"
          />
        </div>
      </div>
      <div ref={scroller} onScroll={onScroll} className="relative min-h-0 flex-1 overflow-y-auto px-3 pb-2">
        {cells.length === 0 ? (
          <p id={`${id}-grid`} className="px-1 py-8 text-center text-ui text-muted">
            No emoji match “{query}”
          </p>
        ) : (
          <div id={`${id}-grid`} role="grid" aria-label={query ? "Search results" : "Emoji"} aria-colcount={columns}>
            {sections.map((s) =>
              s.emoji.length === 0 ? null : (
                <div key={s.id} id={`${id}-s-${s.id}`} role="rowgroup" aria-label={s.label}>
                  <p aria-hidden className="sticky top-0 z-[1] bg-paper-3 px-1 pb-1 pt-2 text-xs font-semibold text-ink-2">
                    {s.label}
                  </p>
                  {chunk(s.emoji, columns).map((row, r) => (
                    <div key={r} role="row" className="grid" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
                      {row.map((e) => {
                        const i = index++;
                        return (
                          <div
                            key={i}
                            id={cellId(i)}
                            role="gridcell"
                            data-index={i}
                            aria-selected={i === active}
                            aria-label={`${e.char} ${e.name.replace(/_/g, " ")}`}
                            onMouseMove={i === active ? undefined : () => setActive(i)}
                            onMouseDown={(ev) => ev.preventDefault() /* focus stays in the search box */}
                            onClick={() => pick(e)}
                            className={cx(
                              "flex h-9 min-w-0 cursor-pointer select-none items-center justify-center rounded-[var(--radius-control)] text-[22px] leading-none transition-colors duration-150",
                              i === active ? "bg-accent-soft" : "hover:bg-paper-2",
                            )}
                          >
                            <span aria-hidden>{e.char}</span>
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              ),
            )}
          </div>
        )}
      </div>
      <div aria-hidden className="flex h-12 shrink-0 items-center gap-2.5 border-t border-rule bg-paper-2 px-3">
        {current ? (
          <>
            <span className="text-[28px] leading-none">{current.char}</span>
            <span className="min-w-0">
              <span className="block truncate font-mono text-xs font-semibold text-ink">:{current.name}:</span>
              {current.aliases.length > 0 && <span className="block truncate font-mono text-meta text-muted">{current.aliases.map((a) => `:${a}:`).join(" ")}</span>}
            </span>
          </>
        ) : (
          <span className="text-xs text-muted">Pick an emoji</span>
        )}
      </div>
      <span role="status" aria-live="polite" className="sr-only">
        {query ? (cells.length ? `${cells.length} emoji` : "No emoji match") : ""}
      </span>
    </div>,
    document.body,
  );
}

function chunk<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

/** Category jump buttons: an APG toolbar (one tab stop, ←/→ inside). */
function CategoryBar({ tabs, current, onJump }: { tabs: { id: string; label: string }[]; current: string; onJump: (id: string) => void }) {
  const [focus, setFocus] = useState(0);
  const keys = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    const n = tabs.length;
    const next = e.key === "Home" ? 0 : e.key === "End" ? n - 1 : (focus + (e.key === "ArrowRight" ? 1 : n - 1)) % n;
    setFocus(next);
    e.currentTarget.querySelectorAll<HTMLButtonElement>("button")[next]?.focus();
  };
  return (
    <div role="toolbar" aria-label="Emoji categories" onKeyDown={keys} className="flex shrink-0 items-center justify-between border-b border-rule px-2">
      {tabs.map((t, i) => {
        const Icon = CATEGORY_ICON[t.id]!;
        const on = current === t.id;
        return (
          <button
            key={t.id}
            type="button"
            tabIndex={i === focus ? 0 : -1}
            aria-label={t.label}
            aria-current={on || undefined}
            title={t.label}
            onClick={() => {
              setFocus(i);
              onJump(t.id);
            }}
            className={cx(
              "relative inline-flex h-9 w-8 items-center justify-center text-muted transition-colors duration-150 hover:text-ink",
              on && "text-accent after:absolute after:inset-x-1 after:bottom-0 after:h-0.5 after:rounded-full after:bg-accent",
            )}
          >
            <Icon size={16} />
          </button>
        );
      })}
    </div>
  );
}

/** Toggle state for a picker opened from a button: `open(el)` / `close()`, and the anchor element while open. */
export function usePicker() {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const close = useCallback(() => setAnchor(null), []);
  const toggle = useCallback((el: HTMLElement) => setAnchor((a) => (a === el ? null : el)), []);
  return { anchor, toggle, close };
}

/** The composer's ":shortcode" autocomplete, for useAutocomplete. */
export function useEmojiSource(): AutocompleteSource<Emoji> {
  return useMemo(
    () => ({
      id: "emoji",
      detect: detectEmojiTrigger,
      items: (q) => searchEmoji(q, 50, frequentEmoji(24)),
      key: (e) => e.name,
      insert: (text, t, caret, e) => insertEmoji(text, t, caret, e.char),
      render: (e) => (
        <>
          <span aria-hidden className="w-5 shrink-0 text-center text-[17px] leading-none">
            {e.char}
          </span>
          <span className="min-w-0 truncate font-mono text-code text-ink">:{e.name}:</span>
          {e.aliases.length > 0 && <span className="min-w-0 shrink-[2] truncate font-mono text-meta text-muted">{e.aliases.map((a) => `:${a}:`).join(" ")}</span>}
        </>
      ),
      heading: "Emoji",
      listLabel: "Emoji suggestions",
      empty: (q) => `No emoji match “:${q}”`,
      onPick: (e) => recordEmojiUse(e.char),
    }),
    [],
  );
}
