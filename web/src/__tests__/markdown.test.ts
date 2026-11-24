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
});
