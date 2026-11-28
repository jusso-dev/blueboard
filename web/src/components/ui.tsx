

/* Hallmark · component primitives · states: default · hover · focus · active · disabled · loading · error · success */

import { forwardRef, useCallback, useEffect, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

import { avatarTint, initials } from "../lib/chat";
import { IconBoard } from "./icons";

export function cx(...xs: (string | false | null | undefined)[]) {
  return xs.filter(Boolean).join(" ");
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md";
  loading?: boolean;
};

const VARIANT: Record<NonNullable<ButtonProps["variant"]>, string> = {
  primary: "bg-accent text-accent-ink border-accent hover:bg-focus",
  secondary: "bg-paper-2 text-ink border-control hover:border-ink-2 hover:bg-paper-3",
  ghost: "bg-transparent text-ink-2 border-transparent hover:bg-paper-3 hover:text-ink",
  danger: "bg-paper-2 text-critical border-rule hover:border-critical",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, disabled, className, children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cx(
        "inline-flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-[var(--radius-control)] border font-medium",
        "transition-colors duration-150 ease-[var(--ease-out)] active:translate-y-px",
        "disabled:cursor-not-allowed disabled:opacity-50 disabled:active:translate-y-0",
        size === "sm" ? "h-9 px-2.5 text-ui" : "h-9 px-3 text-ui",
        VARIANT[variant],
        className,
      )}
      {...rest}
    >
      {loading && <Spinner />}
      {children}
    </button>
  );
});

export function Spinner() {
  return <span aria-hidden className="size-3 animate-spin rounded-full border-[1.5px] border-current border-t-transparent" />;
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(function Input(
  { className, invalid, ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      aria-invalid={invalid || undefined}
      className={cx(
        "h-9 min-w-0 rounded-[var(--radius-control)] border border-control bg-paper-2 px-2.5 text-ui text-ink placeholder:text-faint",
        "transition-colors duration-150 hover:border-ink-2 focus-visible:border-accent",
        "disabled:cursor-not-allowed disabled:opacity-50 aria-[invalid]:border-critical",
        className,
      )}
      {...rest}
    />
  );
});

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cx(
        "h-9 min-w-0 rounded-[var(--radius-control)] border border-control bg-paper-2 pl-2 pr-7 text-ui text-ink",
        "transition-colors duration-150 hover:border-ink-2 focus-visible:border-accent disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  );
}

/** A segmented control: one choice from a few. Keyboard: native radio semantics. */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex h-9 max-w-full rounded-[var(--radius-control)] border border-control bg-paper-2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cx(
            "whitespace-nowrap rounded-[4px] px-2.5 text-ui transition-colors duration-150",
            value === o.value ? "bg-paper-3 text-ink" : "text-muted hover:text-ink",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

type Tone = "neutral" | "accent" | "critical" | "warning" | "good";
const TONE: Record<Tone, string> = {
  neutral: "text-muted border-rule",
  accent: "text-accent border-accent-soft bg-accent-soft/40",
  critical: "text-critical border-critical-soft bg-critical-soft/50",
  warning: "text-warning border-warning-soft bg-warning-soft/50",
  good: "text-good border-good-soft bg-good-soft/50",
};

export function Tag({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cx("inline-flex min-h-5 shrink-0 items-center whitespace-nowrap rounded-[4px] border px-1.5 text-meta font-medium", TONE[tone])}>
      {children}
    </span>
  );
}

const SEVERITY_TONE: Record<string, Tone> = { high: "critical", medium: "warning", low: "accent", informational: "neutral" };

/** Severity is always written out, never colour alone. */
export function Severity({ value }: { value: string }) {
  const v = value.toLowerCase();
  return <Tag tone={SEVERITY_TONE[v] ?? "neutral"}>{v === "informational" ? "info" : v}</Tag>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded-[4px] border border-rule px-1 font-mono text-meta text-muted">{children}</kbd>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="mx-auto max-w-sm px-6 py-16 text-center">
      <p className="text-sm font-medium text-ink-2">{title}</p>
      {children && <div className="mt-1 text-ui text-muted">{children}</div>}
    </div>
  );
}

export function ErrorLine({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="text-xs text-critical">
      {children}
    </p>
  );
}

export function relTime(iso: string) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 45) return "now";
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

export function Time({ iso }: { iso: string }) {
  return (
    <time dateTime={iso} title={new Date(iso).toLocaleString()} className="label tnum whitespace-nowrap">
      {relTime(iso)}
    </time>
  );
}

export function fmtDuration(s: number | null | undefined) {
  if (s === null || s === undefined) return "—";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86400).toFixed(1)}d`;
}

const TINTS = ["bg-tint-1", "bg-tint-2", "bg-tint-3", "bg-tint-4", "bg-tint-5", "bg-tint-6"];

/**
 * A person or agent: a rounded square with initials on a calm tint hashed from the handle (colour carries no meaning;
 * the AGENT badge does). The board's own posts get a neutral tile with a line icon instead.
 */
export function Avatar({ handle, name, kind, size = 36, className }: { handle: string; name: string; kind: string; size?: 36 | 24 | 20; className?: string }) {
  const box = size === 36 ? "size-9 rounded-[var(--radius-control)] text-ui" : size === 24 ? "size-6 rounded-[4px] text-[10px]" : "size-5 rounded-[4px] text-[9px]";
  if (kind === "system")
    return (
      <span aria-hidden className={cx("inline-flex shrink-0 items-center justify-center bg-paper-3 text-muted", box, className)}>
        <IconBoard size={size === 36 ? 18 : 12} />
      </span>
    );
  return (
    <span aria-hidden className={cx("inline-flex shrink-0 select-none items-center justify-center font-semibold leading-none tracking-wide text-ink", box, TINTS[avatarTint(handle) - 1], className)}>
      {initials(name, handle)}
    </span>
  );
}

/** "AGENT" / "SYSTEM" / "INTEGRATION" after a name: the kind in words, never colour alone. */
export function KindBadge({ kind }: { kind: string }) {
  if (kind !== "agent" && kind !== "system" && kind !== "integration") return null;
  return (
    <span className="inline-flex h-5 shrink-0 items-center rounded-[3px] bg-paper-3 px-1.5 text-meta font-medium text-muted">
      {kind === "agent" ? "Agent" : kind === "system" ? "System" : "Integration"}
    </span>
  );
}

/** Subscribe to a media query (false on the server). */
export function useMediaQuery(query: string): boolean {
  const [on, setOn] = useState(() => typeof window !== "undefined" && window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const update = () => setOn(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, [query]);
  return on;
}

/** useState backed by localStorage (or sessionStorage). Storage failures (private mode, quota) fall back to memory. */
export function useStoredState<T extends string>(key: string, initial: T | (() => T), store: "local" | "session" = "local"): [T, (v: T) => void] {
  const get = () => {
    try {
      return (store === "local" ? localStorage : sessionStorage).getItem(key) as T | null;
    } catch {
      return null;
    }
  };
  const [v, setV] = useState<T>(() => get() ?? (typeof initial === "function" ? (initial as () => T)() : initial));
  useEffect(() => {
    const stored = get();
    setV(stored ?? (typeof initial === "function" ? (initial as () => T)() : initial));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  const set = useCallback(
    (next: T) => {
      setV(next);
      try {
        const s = store === "local" ? localStorage : sessionStorage;
        if (next === "") s.removeItem(key);
        else s.setItem(key, next);
      } catch {
        /* memory only */
      }
    },
    [key, store],
  );
  return [v, set];
}
