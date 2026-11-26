import { Fragment, type ReactNode } from "react";
import { CveRef } from "./cve";
import { isJumbo, replaceShortcodesInProse } from "../lib/emoji";

const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;

/**
 * Tiny, safe markdown subset (no HTML passthrough): paragraphs, lists, quotes, code, bold, links, @mentions, CVE ids
 * (linked to /intel) and :shortcode: emoji. Shortcodes convert only in plain text runs: never in code, link targets or
 * bare URLs (replaceShortcodesInProse skips those itself).
 */
function inline(text: string, key: string, highlight = false, me?: string): ReactNode[] {
  const out: ReactNode[] = [];
  const clean = text.replace(BIDI_CONTROLS, "");
  const re = highlight
    ? /(<<[^<>]{1,200}>>|`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\((https?:\/\/[^)\s]+)\)|\b[Cc][Vv][Ee]-\d{4}-\d{4,}\b|@[a-z0-9][a-z0-9-]{0,40})/g
    : /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\((https?:\/\/[^)\s]+)\)|\b[Cc][Vv][Ee]-\d{4}-\d{4,}\b|@[a-z0-9][a-z0-9-]{0,40})/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(clean))) {
    const tok = m[0];
    // An @ preceded by a word character is part of an email address, not a mention: leave it as text.
    if (tok.startsWith("@") && m.index > 0 && /[\w.]/.test(clean[m.index - 1]!)) continue;
    if (m.index > last) out.push(replaceShortcodesInProse(clean.slice(last, m.index)));
    const k = `${key}-${i++}`;
    if (/^cve-/i.test(tok)) out.push(<CveRef key={k} id={tok} />);
    else if (highlight && tok.startsWith("<<")) out.push(<mark key={k}>{tok.slice(2, -2)}</mark>);
    else if (tok.startsWith("`")) out.push(<code key={k}>{tok.slice(1, -1)}</code>);
    else if (tok.startsWith("**")) out.push(<strong key={k}>{inline(tok.slice(2, -2), k, highlight, me)}</strong>);
    else if (tok.startsWith("[")) {
      const label = tok.slice(1, tok.indexOf("]"));
      out.push(
        <a key={k} href={m[2]} target="_blank" rel="noreferrer noopener">
          {label}
        </a>,
      );
    } else out.push(<Mention key={k} tok={tok} self={!!me && tok.slice(1) === me} />);
    last = m.index + tok.length;
  }
  if (last < clean.length) out.push(replaceShortcodesInProse(clean.slice(last)));
  return out;
}

/** An @handle chip. The viewer's own handle is the stronger form (and says so to screen readers). */
function Mention({ tok, self }: { tok: string; self: boolean }) {
  return self ? (
    <span className="mention rounded-[3px] bg-accent px-0.5 font-medium text-accent-ink">
      {tok}
      <span className="sr-only"> (you)</span>
    </span>
  ) : (
    <span className="mention rounded-[3px] bg-accent-soft px-0.5 text-accent">{tok}</span>
  );
}

/** `me` is the viewer's handle: mentions of it render as the "you" chip. */
export function Markdown({ text, highlight = false, me }: { text: string; highlight?: boolean; me?: string }) {
  const blocks: ReactNode[] = [];
  const lines = text.replace(BIDI_CONTROLS, "").split("\n");
  let i = 0;
  let b = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.startsWith("```")) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i]!.startsWith("```")) body.push(lines[i++]!);
      i++;
      blocks.push(<pre key={b++}>{body.join("\n")}</pre>);
    } else if (/^\s*[-*] /.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*] /.test(lines[i]!)) items.push(lines[i++]!.replace(/^\s*[-*] /, ""));
      blocks.push(
        <ul key={b++}>
          {items.map((it, j) => (
            <li key={j}>{inline(it, `${b}-${j}`, highlight, me)}</li>
          ))}
        </ul>,
      );
    } else if (line.startsWith(">")) {
      const q: string[] = [];
      while (i < lines.length && lines[i]!.startsWith(">")) q.push(lines[i++]!.replace(/^>\s?/, ""));
      blocks.push(<blockquote key={b++}>{inline(q.join(" "), `q${b}`, highlight, me)}</blockquote>);
    } else if (line.trim() === "") {
      i++;
    } else {
      const p: string[] = [];
      while (i < lines.length && lines[i]!.trim() !== "" && !/^(\s*[-*] |>|```)/.test(lines[i]!)) p.push(lines[i++]!);
      blocks.push(
        <p key={b++}>
          {p.map((l, j) => (
            <Fragment key={j}>
              {j > 0 && <br />}
              {inline(l, `p${b}-${j}`, highlight, me)}
            </Fragment>
          ))}
        </p>,
      );
    }
  }
  // Only 1 to 3 emoji (Slack's "jumbomoji"): shown at about 32 px.
  return <div className={isJumbo(text) && !highlight ? "md jumbo" : "md"}>{blocks}</div>;
}
