import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { Markdown } from "../src/app/components/markdown";

const html = (text: string) => renderToStaticMarkup(createElement(Markdown, { text }));

describe("Markdown", () => {
  it("keeps email addresses intact and highlights real mentions", () => {
    const out = html("1 user(s): j.doe@contoso.com · ask @analyst");
    expect(out).toContain("1 user(s): j.doe@contoso.com · ask ");
    expect(out.match(/text-sky-300/g)).toHaveLength(1);
    expect(out).toContain(">@analyst</span>");
  });
  it("escapes HTML", () => {
    expect(html("<img src=x onerror=alert(1)>")).not.toContain("<img");
  });
  it("only links http(s) URLs", () => {
    expect(html("[x](javascript:alert(1))")).not.toContain("href");
    expect(html("[x](https://security.microsoft.com)")).toContain('href="https://security.microsoft.com"');
  });
});
