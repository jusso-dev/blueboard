import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { api } from "../lib/api";
import {
  CURATED_GIFS,
  gifProviderOf,
  isAllowedGifUrl,
  searchLocalGifs,
  toGifPayload,
  type GifItem,
  type GifPayload,
  type GifSearchResponse,
} from "../lib/gifs";
import { placePopover } from "./emoji";
import { Button, cx, ErrorLine, Input, Spinner, Tag } from "./ui";
import { IconClose, IconSearch, IconShuffle } from "./icons";

const WIDTH = 376;
const HEIGHT = 430;
const EDGE = 8;

const QUICK_CHIPS = ["this is fine", "lgtm", "party", "coffee", "suspicious", "ship it", "hackerman"];

export function GifPicker({
  anchor,
  onPick,
  onClose,
}: {
  anchor: HTMLElement;
  onPick: (gif: GifPayload) => void;
  onClose: (restore: boolean) => void;
}) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<GifItem[]>(CURATED_GIFS);
  const [provider, setProvider] = useState("curated");
  const [enabled, setEnabled] = useState(true);
  const [loading, setLoading] = useState(false);
  const [showPaste, setShowPaste] = useState(false);
  const [pasteUrl, setPasteUrl] = useState("");
  const [pasteTitle, setPasteTitle] = useState("");
  const [pasteErr, setPasteErr] = useState<string | null>(null);

  const measure = useCallback(() => {
    const w = Math.min(WIDTH, window.innerWidth - 2 * EDGE);
    const p = placePopover(anchor.getBoundingClientRect(), { w, h: HEIGHT }, { w: window.innerWidth, h: window.innerHeight });
    return { top: p.top, left: p.left, w, h: Math.min(HEIGHT, window.innerHeight - 2 * EDGE) };
  }, [anchor]);
  const [pos, setPos] = useState(measure);

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
    searchRef.current?.focus({ preventScroll: true });
  }, []);

  useEffect(() => {
    const down = (e: MouseEvent) => {
      const t = e.target as Node;
      if (ref.current?.contains(t) || anchor.contains(t)) return;
      onClose(false);
    };
    document.addEventListener("mousedown", down);
    return () => document.removeEventListener("mousedown", down);
  }, [anchor, onClose]);

  useEffect(() => {
    let cancelled = false;
    const trimmed = query.trim();
    const timer = setTimeout(() => {
      setLoading(true);
      void api<GifSearchResponse>(`/gifs/search?q=${encodeURIComponent(trimmed)}&limit=16`)
        .then((res) => {
          if (cancelled) return;
          setEnabled(res.enabled);
          setProvider(res.provider);
          setItems(res.items.filter((g) => isAllowedGifUrl(g.url)));
        })
        .catch(() => {
          if (cancelled) return;
          setProvider("curated");
          setItems(searchLocalGifs(trimmed, 16));
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, trimmed ? 220 : 0);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query]);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      onClose(true);
    }
    e.stopPropagation();
  };

  const submitUrl = () => {
    const u = pasteUrl.trim();
    if (!isAllowedGifUrl(u)) {
      setPasteErr("Use an https:// URL from media.giphy.com, i.giphy.com, or media.tenor.com.");
      return;
    }
    setPasteErr(null);
    onPick({
      url: u,
      preview_url: u,
      title: pasteTitle.trim().slice(0, 200) || "GIF",
      provider: gifProviderOf(u),
    });
  };

  return createPortal(
    <div
      ref={ref}
      id={id}
      role="dialog"
      aria-label="GIF picker"
      onKeyDown={onKeyDown}
      style={{ top: pos.top, left: pos.left, width: pos.w, height: pos.h }}
      className="fixed z-50 flex flex-col overflow-hidden rounded-lg border border-rule-strong bg-paper-2 shadow-[var(--shadow-pop)]"
    >
      <div className="flex items-center gap-2 border-b border-rule px-2.5 py-2">
        <div className="relative flex-1">
          <IconSearch size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
          <input
            ref={searchRef}
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search GIFs or try /giphy…"
            aria-label="Search GIFs"
            className="h-8 w-full rounded-[var(--radius-control)] border border-control bg-paper pl-8 pr-2 text-ui text-ink placeholder:text-faint focus:border-accent focus:outline-none"
          />
        </div>
        <button
          type="button"
          onClick={() => setShowPaste((v) => !v)}
          className={cx(
            "h-8 shrink-0 rounded-[var(--radius-control)] border px-2 text-xs transition-colors",
            showPaste ? "border-accent bg-accent-soft text-accent" : "border-control text-muted hover:text-ink",
          )}
        >
          URL
        </button>
      </div>

      {showPaste ? (
        <div className="flex flex-1 flex-col gap-2 p-3">
          <p className="text-xs text-muted">Paste an HTTPS GIF URL from GIPHY or Tenor (other hosts are blocked by CSP).</p>
          <Input
            aria-label="GIF URL"
            value={pasteUrl}
            onChange={(e) => {
              setPasteUrl(e.target.value);
              setPasteErr(null);
            }}
            placeholder="https://media.giphy.com/media/.../giphy.gif"
            className="font-mono text-xs"
          />
          <Input
            aria-label="GIF caption (optional)"
            value={pasteTitle}
            onChange={(e) => setPasteTitle(e.target.value)}
            placeholder="Caption (optional)"
            maxLength={200}
          />
          {pasteErr && <ErrorLine>{pasteErr}</ErrorLine>}
          <div className="mt-1 flex justify-end gap-2">
            <Button type="button" variant="ghost" size="sm" onClick={() => setShowPaste(false)}>
              Back
            </Button>
            <Button type="button" variant="primary" size="sm" disabled={!pasteUrl.trim()} onClick={submitUrl}>
              Send GIF
            </Button>
          </div>
        </div>
      ) : !enabled ? (
        <div className="flex flex-1 items-center justify-center px-6 text-center text-ui text-muted">
          GIFs are turned off for this board (GIFS_ENABLED=false).
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-1 border-b border-rule px-2.5 py-1.5">
            {QUICK_CHIPS.map((chip) => (
              <button
                key={chip}
                type="button"
                onClick={() => setQuery(chip)}
                className={cx(
                  "rounded-full border px-2 py-0.5 text-meta transition-colors",
                  query.toLowerCase() === chip ? "border-accent bg-accent-soft text-accent" : "border-rule text-muted hover:border-rule-strong hover:text-ink",
                )}
              >
                {chip}
              </button>
            ))}
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {loading && items.length === 0 ? (
              <div className="flex h-full items-center justify-center text-muted">
                <Spinner />
              </div>
            ) : items.length === 0 ? (
              <p className="py-10 text-center text-ui text-muted">No GIFs matched "{query}".</p>
            ) : (
              <div className="grid grid-cols-2 gap-1.5">
                {items.map((g) => (
                  <button
                    key={g.id}
                    type="button"
                    title={g.title}
                    onClick={() => onPick(toGifPayload(g))}
                    className="group/gif relative overflow-hidden rounded-[6px] border border-rule bg-paper text-left transition-colors hover:border-accent focus-visible:border-accent focus-visible:outline-none"
                  >
                    <img
                      src={g.preview_url || g.url}
                      alt={g.title}
                      loading="lazy"
                      referrerPolicy="no-referrer"
                      className="h-24 w-full object-cover"
                    />
                    <span className="absolute inset-x-0 bottom-0 truncate bg-paper/85 px-1.5 py-0.5 text-[11px] text-ink-2 opacity-0 transition-opacity group-hover/gif:opacity-100 group-focus-visible/gif:opacity-100">
                      {g.title}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <footer className="flex items-center justify-between border-t border-rule px-2.5 py-1.5 text-meta text-faint">
            <span>
              {provider === "giphy"
                ? "Powered by GIPHY"
                : provider === "tenor"
                  ? "Powered by Tenor"
                  : "Curated reaction GIFs · /giphy <search>"}
            </span>
            {loading && <Spinner />}
          </footer>
        </>
      )}
    </div>,
    document.body,
  );
}

/** Slack-style ephemeral `/giphy <query>` shuffle preview card shown above the composer before sending. */
export function GifShuffleBar({
  query,
  items,
  index,
  loading,
  busy,
  onShuffle,
  onSend,
  onCancel,
}: {
  query: string;
  items: GifItem[];
  index: number;
  loading: boolean;
  busy: boolean;
  onShuffle: () => void;
  onSend: (gif: GifPayload) => void;
  onCancel: () => void;
}) {
  const current = items[index % Math.max(1, items.length)];
  return (
    <div
      role="region"
      aria-label="GIF preview"
      className="mb-2 rounded-lg border border-rule-strong bg-paper-2 p-3 shadow-[var(--shadow-pop)]"
    >
      <div className="flex flex-wrap items-center gap-2 pb-2">
        <span className="font-mono text-xs font-medium text-accent">/giphy{query ? ` ${query}` : ""}</span>
        <Tag tone="neutral">Only visible to you</Tag>
        {items.length > 0 && (
          <span className="label tnum">
            {(index % items.length) + 1} / {items.length}
          </span>
        )}
        <button
          type="button"
          onClick={onCancel}
          aria-label="Cancel GIF"
          className="ml-auto inline-flex size-6 items-center justify-center rounded-[4px] text-muted hover:bg-paper-3 hover:text-ink"
        >
          <IconClose size={14} />
        </button>
      </div>
      {loading ? (
        <div className="flex h-36 items-center justify-center text-muted">
          <Spinner />
        </div>
      ) : current ? (
        <div className="flex flex-col gap-2.5 sm:flex-row sm:items-end">
          <div className="overflow-hidden rounded-[6px] border border-rule bg-paper">
            <img
              src={current.url}
              alt={current.title}
              referrerPolicy="no-referrer"
              className="max-h-48 w-auto max-w-full object-contain"
            />
          </div>
          <div className="flex flex-col gap-2">
            <p className="text-xs text-ink-2">{current.title}</p>
            <div className="flex flex-wrap items-center gap-1.5">
              <Button type="button" variant="primary" size="sm" loading={busy} onClick={() => onSend(toGifPayload(current))}>
                Send
              </Button>
              <Button type="button" variant="secondary" size="sm" disabled={items.length <= 1 || busy} onClick={onShuffle}>
                <IconShuffle size={14} />
                Shuffle
              </Button>
              <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={onCancel}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <p className="text-ui text-muted">No GIFs found for "{query}".</p>
      )}
    </div>
  );
}

/** Inline animated GIF attachment rendered beneath a message body, with a Slack-like collapse toggle. */
export function GifAttachment({ gif }: { gif: GifPayload }) {
  const [collapsed, setCollapsed] = useState(false);
  if (!isAllowedGifUrl(gif.url)) return null;
  const caption = gif.title || "GIF";
  const via = gif.provider === "tenor" ? "Tenor" : "GIPHY";
  return (
    <figure className="mt-1.5 max-w-[360px]">
      <div className="mb-1 flex items-center gap-2 text-meta text-muted">
        <span className="truncate font-medium text-ink-2">{caption}</span>
        <span aria-hidden>·</span>
        <span className="shrink-0">via {via}</span>
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          aria-expanded={!collapsed}
          className="ml-auto shrink-0 text-meta text-muted hover:text-ink hover:underline"
        >
          {collapsed ? "Show GIF" : "Hide"}
        </button>
      </div>
      {!collapsed && (
        <div className="inline-block overflow-hidden rounded-lg border border-rule bg-paper-2">
          <img
            src={gif.url}
            alt={caption}
            loading="lazy"
            referrerPolicy="no-referrer"
            className="block max-h-64 w-auto max-w-full object-contain"
          />
        </div>
      )}
    </figure>
  );
}
