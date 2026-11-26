import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { Markdown } from "../components/markdown";

const html = (text: string, highlight = false) => renderToStaticMarkup(createElement(Markdown, { text, highlight }));

describe("Markdown", () => {
  it("keeps email addresses intact and highlights real mentions incl. single-char handles", () => {
    const out = html("1 user(s): j.doe@contoso.com · ask @analyst and @x");
    expect(out).toContain("1 user(s): j.doe@contoso.com · ask ");
    expect(out.match(/text-accent/g)).toHaveLength(2);
    expect(out).toContain(">@analyst</span>");
    expect(out).toContain(">@x</span>");
  });
  it("renders search highlights only when highlight is true", () => {
    expect(html("check <<this>>")).not.toContain("<mark>");
    expect(html("check <<this>>", true)).toContain("<mark>this</mark>");
  });
  it("strips Unicode BiDi override characters", () => {
    expect(html("file_\u202Etxt.exe")).not.toContain("\u202E");
  });
  it("escapes HTML", () => {
    expect(html("<img src=x onerror=alert(1)>")).not.toContain("<img");
  });
  it("links CVE ids to the intel page", () => {
    const out = html("patch cve-2021-44228 now, not CVE-21-1");
    expect(out).toContain('href="/intel/CVE-2021-44228"');
    expect(out.match(/\/intel\//g)).toHaveLength(1);
    expect(html("**Intel: CVE-2024-3400**")).toContain('href="/intel/CVE-2024-3400"');
  });
  it("only links http(s) URLs", () => {
    expect(html("[x](javascript:alert(1))")).not.toContain("href");
    expect(html("[x](https://security.microsoft.com)")).toContain('href="https://security.microsoft.com"');
  });
  it("renders allowlisted GIF images as <img> and downgrades untrusted image URLs to links", () => {
    const ok = html("![This is fine](https://media.giphy.com/media/QMHoU66sBXqqLqYvGO/giphy.gif)");
    expect(ok).toContain("<img");
    expect(ok).toContain('referrerPolicy="no-referrer"');
    const bad = html("![Tracker](https://evil.example/pixel.png)");
    expect(bad).not.toContain("<img");
    expect(bad).toContain('href="https://evil.example/pixel.png"');
  });
});

describe("Markdown mentions", () => {
  const md = (text: string, me?: string) => renderToStaticMarkup(createElement(Markdown, { text, me }));
  it("renders others as soft chips and the viewer as the strong chip", () => {
    const out = md("cc @enrichment-agent and @analyst", "analyst");
    expect(out).toContain('bg-accent-soft px-0.5 text-accent">@enrichment-agent</span>');
    expect(out).toMatch(/bg-accent px-0\.5 font-medium text-accent-ink">@analyst<span class="sr-only"> \(you\)<\/span>/);
  });
  it("leaves emails alone even when they contain the viewer's handle", () => {
    expect(md("mail analyst@contoso.com", "contoso")).not.toContain("mention");
  });
  it("renders :shortcode: emoji in prose but never in code, links or URLs", () => {
    expect(html("nice :tada: work")).toContain("nice 🎉 work");
    expect(html("run `echo :tada:` now")).toContain("<code>echo :tada:</code>");
    expect(html("```\n:fire:\n```")).toContain("<pre>:fire:</pre>");
    expect(html("see https://x.test/:fire:/y")).toContain("https://x.test/:fire:/y");
    expect(html("[docs](https://x.test/:fire:)")).toContain('href="https://x.test/:fire:"');
    expect(html("at 12:30:45")).toContain("12:30:45");
    expect(html("**:rotating_light: high**")).toContain("<strong>🚨 high</strong>");
  });
  it("renders a message of only 1 to 3 emoji as jumbomoji", () => {
    expect(html("🎉")).toContain('class="md jumbo"');
    expect(html(":eyes: :fire:")).toContain('class="md jumbo"');
    expect(html("🎉🎉🎉🎉")).toContain('class="md"');
    expect(html("done 🎉")).toContain('class="md"');
  });
});
