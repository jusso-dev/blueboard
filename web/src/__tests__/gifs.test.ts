import { describe, expect, it } from "vitest";
import { CURATED_GIFS, extractGif, isAllowedGifUrl, parseGifCommand, safeHref, searchLocalGifs } from "../lib/gifs";

describe("GIF helpers and URL guards", () => {
  it("allows only exact HTTPS GIPHY/Tenor CDN URLs", () => {
    expect(isAllowedGifUrl("https://media.giphy.com/media/QMHoU66sBXqqLqYvGO/giphy.gif")).toBe(true);
    expect(isAllowedGifUrl("https://media3.giphy.com/media/abc/200w.gif")).toBe(true);
    expect(isAllowedGifUrl("https://media.tenor.com/abc/tenor.gif")).toBe(true);

    expect(isAllowedGifUrl("http://media.giphy.com/media/abc/giphy.gif")).toBe(false);
    expect(isAllowedGifUrl("https://tracker.evil.example/pixel.gif")).toBe(false);
    expect(isAllowedGifUrl("https://media.giphy.com.evil.example/giphy.gif")).toBe(false);
    expect(isAllowedGifUrl("https://user@media.giphy.com/media/abc/giphy.gif")).toBe(false);
    expect(isAllowedGifUrl("https://media.giphy.com:8443/media/abc/giphy.gif")).toBe(false);
    expect(isAllowedGifUrl("https://media.giphy.com/media/abc/giphy.gif#hash")).toBe(false);
    expect(isAllowedGifUrl("javascript:alert(1)")).toBe(false);
  });

  it("validates external links via safeHref", () => {
    expect(safeHref("https://security.microsoft.com/incidents/1")).toBe("https://security.microsoft.com/incidents/1");
    expect(safeHref("http://localhost:8080/test")).toBe("http://localhost:8080/test");
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(safeHref(null)).toBeNull();
  });

  it("parses /giphy and /gif slash commands", () => {
    expect(parseGifCommand("/giphy this is fine")).toEqual({ command: "giphy", query: "this is fine" });
    expect(parseGifCommand("/GIF party")).toEqual({ command: "gif", query: "party" });
    expect(parseGifCommand("/giphy")).toEqual({ command: "giphy", query: "" });
    expect(parseGifCommand("hello /giphy world")).toBeNull();
  });

  it("extracts only allowlisted payload.gif entries", () => {
    const valid = extractGif({ gif: { url: "https://media.giphy.com/media/abc/giphy.gif", title: "Fine" } });
    expect(valid?.provider).toBe("giphy");
    expect(valid?.title).toBe("Fine");
    expect(extractGif({ gif: { url: "https://evil.example/pixel.gif", title: "Bad" } })).toBeNull();
  });

  it("searches curated reaction GIFs and keeps every curated URL allowlisted", () => {
    for (const g of CURATED_GIFS) {
      expect(isAllowedGifUrl(g.url)).toBe(true);
      expect(isAllowedGifUrl(g.preview_url)).toBe(true);
    }
    const res = searchLocalGifs("this is fine");
    expect(res[0]?.title).toBe("This is fine");
  });
});
