import { Fragment, type ReactNode } from "react";

/** Tiny, safe markdown subset (no HTML passthrough): paragraphs, lists, quotes, code, bold, links, @mentions. */
function inline(text: string, key: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\((https?:\/\/[^)\s]+)\)|@[a-z0-9][a-z0-9-]{1,40})/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    const tok = m[0];
    // An @ preceded by a word character is part of an email address, not a mention: leave it as text.
    if (tok.startsWith("@") && m.index > 0 && /[\w.]/.test(text[m.index - 1]!)) continue;
    if (m.index > last) out.push(text.slice(last, m.index));
    const k = `${key}-${i++}`;
    if (tok.startsWith("`")) out.push(<code key={k}>{tok.slice(1, -1)}</code>);
    else if (tok.startsWith("**")) out.push(<strong key={k}>{tok.slice(2, -2)}</strong>);
    else if (tok.startsWith("[")) {
      const label = tok.slice(1, tok.indexOf("]"));
      out.push(
        <a key={k} href={m[2]} target="_blank" rel="noreferrer noopener">
          {label}
        </a>,
      );
    } else out.push(<span key={k} className="text-sky-300 font-medium">{tok}</span>);
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Markdown({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  const lines = text.split("\n");
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
            <li key={j}>{inline(it, `${b}-${j}`)}</li>
          ))}
        </ul>,
      );
    } else if (line.startsWith(">")) {
      const q: string[] = [];
      while (i < lines.length && lines[i]!.startsWith(">")) q.push(lines[i++]!.replace(/^>\s?/, ""));
      blocks.push(<blockquote key={b++}>{inline(q.join(" "), `q${b}`)}</blockquote>);
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
              {inline(l, `p${b}-${j}`)}
            </Fragment>
          ))}
        </p>,
      );
    }
  }
  return <div className="md text-sm leading-relaxed break-words">{blocks}</div>;
}
