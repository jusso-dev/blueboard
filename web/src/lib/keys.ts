/**
 * Keyboard shortcuts, as pure logic: turn a key press into an intent. The React side (components/shortcuts.tsx)
 * decides what each intent does on the current page. No intent approves or denies anything: approval stays a
 * deliberate click on the Approvals page.
 */

export type Go = "/" | "/approvals" | "/search" | "/reports";
export type Intent =
  | { type: "palette" }
  | { type: "help" }
  | { type: "search" }
  | { type: "go"; to: Go }
  | { type: "next" }
  | { type: "prev" }
  | { type: "open" }
  | { type: "reply" }
  | { type: "escape" };

export type KeyInput = {
  key: string;
  metaKey?: boolean;
  ctrlKey?: boolean;
  altKey?: boolean;
  isComposing?: boolean;
  defaultPrevented?: boolean;
  target: unknown;
};

type ElementLike = { tagName?: string; isContentEditable?: boolean; getAttribute?: (n: string) => string | null; type?: string };

const TEXT_INPUTS = new Set(["text", "search", "email", "url", "tel", "password", "number", "date", "datetime-local", "month", "time", "week"]);

/** True while the user is typing: text inputs, textareas, selects and contenteditable regions. */
export function isTyping(target: unknown): boolean {
  const t = target as ElementLike | null;
  if (!t || typeof t !== "object") return false;
  if (t.isContentEditable) return true;
  const role = t.getAttribute?.("role");
  if (role === "textbox" || role === "combobox" || role === "searchbox") return true;
  const tag = t.tagName?.toUpperCase();
  if (tag === "TEXTAREA" || tag === "SELECT") return true;
  return tag === "INPUT" && TEXT_INPUTS.has((t.type ?? "text").toLowerCase());
}

/** Links, buttons and other controls handle Enter themselves. */
export function isInteractive(target: unknown): boolean {
  const t = target as ElementLike | null;
  const tag = t?.tagName?.toUpperCase();
  if (tag === "A" || tag === "BUTTON" || tag === "SUMMARY" || tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return true;
  const role = t?.getAttribute?.("role");
  return role === "button" || role === "link" || role === "option" || role === "menuitem" || role === "radio" || role === "checkbox";
}

export const SEQUENCE_MS = 1500;
const GO: Record<string, Go> = { q: "/", a: "/approvals", s: "/search", r: "/reports" };

/**
 * A stateful reader (it remembers a pending `g`). `singleKeys` off leaves only Cmd/Ctrl+K, so people using speech
 * input or a screen reader can switch character-key shortcuts off (WCAG 2.1.4).
 */
export function createKeyReader(now: () => number = () => Date.now()) {
  let gAt = -Infinity;
  return function read(e: KeyInput, singleKeys = true): Intent | null {
    if (e.defaultPrevented || e.isComposing) return null;
    if (isTyping(e.target)) {
      gAt = -Infinity;
      return null;
    }
    const k = e.key;
    if ((e.metaKey || e.ctrlKey) && !e.altKey && k.toLowerCase() === "k") return { type: "palette" };
    if (e.metaKey || e.ctrlKey || e.altKey) return null;
    if (k === "Escape") return { type: "escape" };
    if (!singleKeys) return null;

    if (now() - gAt < SEQUENCE_MS) {
      gAt = -Infinity;
      const to = GO[k.toLowerCase()];
      return to ? { type: "go", to } : null;
    }
    switch (k) {
      case "g":
        gAt = now();
        return null;
      case "?":
        return { type: "help" };
      case "/":
        return { type: "search" };
      case "j":
      case "ArrowDown":
        return { type: "next" };
      case "k":
      case "ArrowUp":
        return { type: "prev" };
      case "Enter":
        return isInteractive(e.target) ? null : { type: "open" };
      case "r":
        return { type: "reply" };
      default:
        return null;
    }
  };
}

/** What the `?` overlay lists. Keep in step with createKeyReader. */
export const SHORTCUTS: { keys: string[]; label: string }[] = [
  { keys: ["⌘ K", "Ctrl K"], label: "Command palette: incidents, channels, pages, search" },
  { keys: ["g q"], label: "Go to the queue" },
  { keys: ["g a"], label: "Go to approvals" },
  { keys: ["g s"], label: "Go to search" },
  { keys: ["g r"], label: "Go to reports (admins)" },
  { keys: ["/"], label: "Search" },
  { keys: ["j", "↓"], label: "Next row or message" },
  { keys: ["k", "↑"], label: "Previous row or message" },
  { keys: ["Enter"], label: "Open the selected incident or thread" },
  { keys: ["r"], label: "Reply to the selected message" },
  { keys: ["Esc"], label: "Close the thread panel or dialog" },
  { keys: ["?"], label: "Show this list" },
];

/** Case-insensitive match on every word of the query, for the palette. */
export function matches(text: string, query: string): boolean {
  const t = text.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => t.includes(w));
}
