import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { useNavigate } from "react-router";
import { useLiveQuery, type Channel, type Incident, type Me } from "../lib/api";
import { createKeyReader, matches, SHORTCUTS, type Intent } from "../lib/keys";
import { Button, cx, Kbd } from "./ui";

/**
 * Every keyboard shortcut lives here. The provider owns one keydown listener; pages register what j/k/Enter/r/Esc
 * mean for them (useListNav) and extra palette commands (usePaletteCommands). Shortcuts are off while typing, and
 * none of them approves or denies an action.
 */

/** Props useListNav puts on each row. */
export type NavRowProps = { "data-nav-key": string; "data-selected"?: true; tabIndex: number; onFocus: () => void };

type ListHandlers = { next?: () => void; prev?: () => void; open?: () => void; reply?: () => void; escape?: () => boolean };
export type PaletteCommand = { id: string; label: string; hint?: string; run: () => void };

type Ctx = {
  searchRef: RefObject<HTMLInputElement | null>;
  pushHandlers: (h: RefObject<ListHandlers>) => () => void;
  setCommands: (owner: string, cmds: PaletteCommand[] | null) => void;
  openPalette: () => void;
  openHelp: () => void;
};

const ShortcutsContext = createContext<Ctx | null>(null);
const useShortcuts = () => useContext(ShortcutsContext);

const SINGLE_KEYS = "bb_single_keys";

export function ShortcutsProvider({ me, children }: { me: Me | null; children: ReactNode }) {
  const navigate = useNavigate();
  const searchRef = useRef<HTMLInputElement | null>(null);
  const stack = useRef<RefObject<ListHandlers>[]>([]);
  const [commands, setCommandMap] = useState<Record<string, PaletteCommand[]>>({});
  const [dialog, setDialog] = useState<"palette" | "help" | null>(null);
  const [singleKeys, setSingleKeys] = useState(() => localStorage.getItem(SINGLE_KEYS) !== "off");
  const isAdmin = !!me?.roles.includes("admin");

  const state = useRef({ dialog, singleKeys, isAdmin });
  state.current = { dialog, singleKeys, isAdmin };

  useEffect(() => {
    const read = createKeyReader();
    const onKey = (e: KeyboardEvent) => {
      const s = state.current;
      // While a dialog is open it handles its own keys; only Cmd/Ctrl+K (toggle the palette) gets through.
      if (s.dialog) {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
          e.preventDefault();
          setDialog((d) => (d === "palette" ? null : "palette"));
        }
        return;
      }
      const intent = read(e, s.singleKeys);
      if (!intent) return;
      const top = stack.current.at(-1)?.current;
      if (run(intent, top, s.isAdmin)) e.preventDefault();
    };
    const run = (intent: Intent, h: ListHandlers | undefined, admin: boolean): boolean => {
      switch (intent.type) {
        case "palette":
          setDialog("palette");
          return true;
        case "help":
          setDialog("help");
          return true;
        case "search": {
          const el = searchRef.current;
          if (el && el.offsetParent !== null) el.focus();
          else navigate("/search");
          return true;
        }
        case "go":
          if (intent.to === "/reports" && !admin) return false;
          navigate(intent.to);
          return true;
        case "escape":
          return h?.escape?.() ?? false;
        default: {
          const fn = h?.[intent.type];
          if (!fn) return false;
          fn();
          return true;
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  const ctx = useMemo<Ctx>(
    () => ({
      searchRef,
      pushHandlers: (h) => {
        stack.current.push(h);
        return () => {
          stack.current = stack.current.filter((x) => x !== h);
        };
      },
      setCommands: (owner, cmds) =>
        setCommandMap((m) => {
          const next = { ...m };
          if (cmds) next[owner] = cmds;
          else delete next[owner];
          return next;
        }),
      openPalette: () => setDialog("palette"),
      openHelp: () => setDialog("help"),
    }),
    [],
  );

  const close = useCallback(() => setDialog(null), []);
  return (
    <ShortcutsContext.Provider value={ctx}>
      {children}
      {dialog === "palette" && <Palette onClose={close} isAdmin={isAdmin} pageCommands={Object.values(commands).flat()} onHelp={() => setDialog("help")} />}
      {dialog === "help" && (
        <HelpDialog
          onClose={close}
          singleKeys={singleKeys}
          setSingleKeys={(on) => {
            localStorage.setItem(SINGLE_KEYS, on ? "on" : "off");
            setSingleKeys(on);
          }}
        />
      )}
    </ShortcutsContext.Provider>
  );
}

/** The rail's search input registers here so `/` can focus it. */
export function useSearchShortcut() {
  return useShortcuts()?.searchRef;
}

/** Buttons that open the palette or the shortcut list (for people who don't know the keys yet). */
export function useShortcutDialogs() {
  const c = useShortcuts();
  return { openPalette: c?.openPalette ?? (() => {}), openHelp: c?.openHelp ?? (() => {}) };
}

/** Page-specific palette commands, e.g. "Copy summary" on an incident. Pass null to remove them. */
export function usePaletteCommands(owner: string, cmds: PaletteCommand[] | null) {
  const c = useShortcuts();
  const setCommands = c?.setCommands;
  useEffect(() => {
    if (!setCommands) return;
    setCommands(owner, cmds);
    return () => setCommands(owner, null);
  }, [setCommands, owner, cmds]);
}

/**
 * j/k (and arrows) move a roving selection through a list of rows, Enter opens, r replies, Esc runs `escape`.
 * Rows get `data-nav-key`; the selected row is the only one in the tab order and receives focus, so screen
 * readers announce it. The page decides what "open" and "reply" mean.
 */
export function useListNav<T>(
  items: T[] | undefined,
  key: (t: T) => string,
  opts: { onOpen?: (t: T) => void; onReply?: (t: T) => void; onEscape?: () => boolean } = {},
) {
  const c = useShortcuts();
  const [selected, setSelected] = useState<string | null>(null);
  const container = useRef<HTMLElement | null>(null);
  const latest = useRef({ items, key, opts, selected });
  latest.current = { items, key, opts, selected };

  const focusKey = useCallback((k: string) => {
    setSelected(k);
    const el = container.current?.querySelector<HTMLElement>(`[data-nav-key="${CSS.escape(k)}"]`);
    el?.focus({ preventScroll: true });
    el?.scrollIntoView({ block: "nearest" });
  }, []);

  const handlers = useRef<ListHandlers>({});
  handlers.current = {
    next: () => move(1),
    prev: () => move(-1),
    open: () => withSelected((t) => latest.current.opts.onOpen?.(t)),
    reply: latest.current.opts.onReply ? () => withSelected((t) => latest.current.opts.onReply?.(t)) : undefined,
    escape: () => latest.current.opts.onEscape?.() ?? false,
  };
  function withSelected(fn: (t: T) => void) {
    const { items: list, key: k, selected: sel } = latest.current;
    const t = list?.find((x) => k(x) === sel);
    if (t) fn(t);
  }
  function move(delta: number) {
    const { items: list, key: k, selected: sel } = latest.current;
    if (!list?.length) return;
    const i = list.findIndex((x) => k(x) === sel);
    const next = i < 0 ? (delta > 0 ? 0 : list.length - 1) : Math.min(list.length - 1, Math.max(0, i + delta));
    focusKey(k(list[next]!));
  }

  const pushHandlers = c?.pushHandlers;
  useEffect(() => pushHandlers?.(handlers), [pushHandlers]);

  const rowProps = (t: T): NavRowProps => {
    const k = key(t);
    const first = items && items.length > 0 && key(items[0]!) === k;
    const isSel = selected === k || (!selected && first);
    return {
      "data-nav-key": k,
      "data-selected": selected === k || undefined,
      tabIndex: isSel ? 0 : -1,
      onFocus: () => setSelected(k),
    };
  };
  return { selected, select: focusKey, container, rowProps };
}

// ── dialogs ─────────────────────────────────────────────────────────────────────────────────

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Modal dialog: focus moves in and is trapped, Esc closes, focus returns to where it was. No motion. */
function Dialog({ label, onClose, children, initialFocus, className }: { label: string; onClose: () => void; children: ReactNode; initialFocus?: RefObject<HTMLElement | null>; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    (initialFocus?.current ?? ref.current?.querySelector<HTMLElement>(FOCUSABLE))?.focus();
    return () => before?.focus?.();
  }, [initialFocus]);
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-paper/80 px-4 pt-[12vh]" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className={cx("w-full max-w-lg overflow-hidden rounded-[var(--radius-card)] border border-rule-strong bg-paper-2", className)}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            e.stopPropagation();
            onClose();
          } else if (e.key === "Tab") {
            const els = [...(ref.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])];
            if (els.length === 0) return;
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
        }}
      >
        <h2 id={titleId} className="sr-only">
          {label}
        </h2>
        {children}
      </div>
    </div>
  );
}

type Item = { id: string; group: string; label: string; hint?: string; run: () => void };

function Palette({ onClose, isAdmin, pageCommands, onHelp }: { onClose: () => void; isAdmin: boolean; pageCommands: PaletteCommand[]; onHelp: () => void }) {
  const navigate = useNavigate();
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const { data: incidents } = useLiveQuery<Incident[]>("/incidents");
  const { data: channels } = useLiveQuery<Channel[]>("/channels");

  const items = useMemo<Item[]>(() => {
    const go = (to: string) => () => navigate(to);
    const pages: Item[] = [
      { id: "p-queue", group: "Pages", label: "Queue", hint: "g q", run: go("/") },
      { id: "p-approvals", group: "Pages", label: "Approvals", hint: "g a", run: go("/approvals") },
      { id: "p-search", group: "Pages", label: "Search", hint: "g s", run: go("/search") },
      ...(isAdmin ? [{ id: "p-reports", group: "Pages", label: "Reports", hint: "g r", run: go("/reports") }] : []),
      { id: "p-help", group: "Pages", label: "Keyboard shortcuts", hint: "?", run: onHelp },
    ];
    const text = q.trim();
    const incidentItems = (incidents ?? []).map((i) => ({ id: `i-${i.id}`, group: "Incidents", label: `INC ${i.graph_id} · ${i.display_name}`, hint: i.severity, run: go(`/incidents/${i.id}`) }));
    const all: Item[] = [
      ...pageCommands.map((c) => ({ id: `c-${c.id}`, group: "This page", label: c.label, hint: c.hint, run: c.run })),
      ...pages,
      ...(text ? incidentItems : incidentItems.slice(0, 8)), // with no query, only the most recent few
      ...(channels ?? []).map((c) => ({ id: `ch-${c.name}`, group: "Channels", label: `#${c.name}`, run: go(`/channels/${encodeURIComponent(c.name)}`) })),
    ];
    if (!text) return all;
    const hits = all.filter((i) => matches(i.label, text)).slice(0, 50);
    hits.push({ id: "search", group: "Search", label: `Search for "${text}"`, run: go(`/search?q=${encodeURIComponent(text)}`) });
    return hits;
  }, [q, incidents, channels, pageCommands, isAdmin, navigate, onHelp]);

  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active, listId]);

  const choose = (i: Item | undefined) => {
    if (!i) return;
    onClose();
    i.run();
  };

  let lastGroup = "";
  return (
    <Dialog label="Command palette" onClose={onClose} initialFocus={input}>
      <div className="border-b border-rule p-2">
        <input
          ref={input}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((a) => Math.min(items.length - 1, a + 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((a) => Math.max(0, a - 1));
            } else if (e.key === "Enter" && !e.nativeEvent.isComposing) {
              e.preventDefault();
              choose(items[active]);
            }
          }}
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={items[active] ? `${listId}-${active}` : undefined}
          aria-autocomplete="list"
          aria-label="Go to an incident, channel or page, or search"
          placeholder="Go to an incident, channel or page, or search"
          className="h-9 w-full rounded-[var(--radius-control)] bg-transparent px-2 text-sm text-ink placeholder:text-faint focus-visible:outline-none"
        />
      </div>
      <ul id={listId} role="listbox" aria-label="Results" className="max-h-[50vh] overflow-y-auto py-1">
        {items.length === 0 && <li className="px-4 py-3 text-[13px] text-muted">Nothing matches.</li>}
        {items.map((it, n) => {
          const header = it.group !== lastGroup ? it.group : null;
          lastGroup = it.group;
          return (
            <li key={it.id} role="presentation">
              {header && (
                <p role="presentation" className="label px-4 pb-1 pt-2">
                  {header}
                </p>
              )}
              <div
                id={`${listId}-${n}`}
                role="option"
                aria-selected={n === active}
                onMouseMove={() => setActive(n)}
                onClick={() => choose(it)}
                className={cx("mx-1 flex cursor-pointer items-center gap-2 rounded-[var(--radius-control)] px-3 py-1.5 text-[13px]", n === active ? "bg-paper-3 text-ink" : "text-ink-2")}
              >
                <span className="min-w-0 flex-1 truncate">{it.label}</span>
                {it.hint && <span className="label shrink-0">{it.hint}</span>}
              </div>
            </li>
          );
        })}
      </ul>
      <p className="label border-t border-rule px-4 py-2">↑ ↓ to move · Enter to open · Esc to close</p>
    </Dialog>
  );
}

function HelpDialog({ onClose, singleKeys, setSingleKeys }: { onClose: () => void; singleKeys: boolean; setSingleKeys: (on: boolean) => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  return (
    <Dialog label="Keyboard shortcuts" onClose={onClose} initialFocus={closeRef}>
      <div className="flex items-center border-b border-rule py-2 pl-4 pr-2">
        <p aria-hidden className="flex-1 text-sm font-semibold">
          Keyboard shortcuts
        </p>
        <Button ref={closeRef} variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      </div>
      <table className="w-full text-[13px]">
        <caption className="sr-only">Keyboard shortcuts</caption>
        <thead className="sr-only">
          <tr>
            <th scope="col">Keys</th>
            <th scope="col">Action</th>
          </tr>
        </thead>
        <tbody>
          {SHORTCUTS.map((s) => (
            <tr key={s.label} className="border-b border-rule last:border-b-0">
              <td className="w-32 whitespace-nowrap py-1.5 pl-4 pr-3">
                {s.keys.map((k, i) => (
                  <span key={k}>
                    {i > 0 && <span className="px-1 text-faint">or</span>}
                    <Kbd>{k}</Kbd>
                  </span>
                ))}
              </td>
              <td className="py-1.5 pr-4 text-ink-2">{s.label}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="space-y-2 border-t border-rule px-4 py-3">
        <label className="flex items-center gap-2 text-[13px] text-ink-2">
          <input type="checkbox" checked={singleKeys} onChange={(e) => setSingleKeys(e.target.checked)} className="size-4 accent-[var(--color-accent)]" />
          Single-key shortcuts (turn off if you use speech input)
        </label>
        <p className="text-xs text-muted">Shortcuts are off while you type. No shortcut approves or denies an action: that is always a click on Approvals.</p>
      </div>
    </Dialog>
  );
}
