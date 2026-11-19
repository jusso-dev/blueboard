

/* Hallmark · component primitives · states: default · hover · focus · active · disabled · loading · error · success */

import { forwardRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

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
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-[13px]",
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
        "h-8 rounded-[var(--radius-control)] border border-control bg-paper-2 px-2.5 text-[13px] text-ink placeholder:text-faint",
        "transition-colors duration-150 hover:border-ink-2 focus-visible:border-accent focus-visible:outline-none",
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
        "h-8 rounded-[var(--radius-control)] border border-control bg-paper-2 pl-2 pr-7 text-[13px] text-ink",
        "transition-colors duration-150 hover:border-ink-2 focus-visible:border-accent focus-visible:outline-none disabled:opacity-50",
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
    <div role="radiogroup" aria-label={label} className="inline-flex h-8 rounded-[var(--radius-control)] border border-control bg-paper-2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cx(
            "rounded-[4px] px-2.5 text-xs transition-colors duration-150",
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
    <span title={title} className={cx("inline-flex h-[18px] items-center rounded-[4px] border px-1.5 font-mono text-[10.5px] leading-none tracking-wide", TONE[tone])}>
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
  return <kbd className="rounded-[4px] border border-rule px-1 font-mono text-[10px] text-faint">{children}</kbd>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="mx-auto max-w-sm px-6 py-16 text-center">
      <p className="text-sm font-medium text-ink-2">{title}</p>
      {children && <div className="mt-1 text-[13px] text-muted">{children}</div>}
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
