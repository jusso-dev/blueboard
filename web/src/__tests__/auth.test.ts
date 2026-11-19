import { describe, expect, it } from "vitest";
import { devApiConfirms } from "../lib/auth";

describe("dev sign-in is honoured only when the API has DEV_AUTH", () => {
  it("accepts when the API takes a dev identity", async () => {
    const f = (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    expect(await devApiConfirms("http://localhost:7370/api", f)).toBe(true);
  });

  it("refuses when the API wants a real token (a deployed board)", async () => {
    const f = (async () => new Response('{"error":"authentication required"}', { status: 401 })) as unknown as typeof fetch;
    expect(await devApiConfirms("https://blueboard-api.example/api", f)).toBe(false);
  });

  it("refuses when the API is unreachable", async () => {
    const f = (async () => {
      throw new TypeError("network");
    }) as unknown as typeof fetch;
    expect(await devApiConfirms("http://nowhere/api", f)).toBe(false);
  });
});
