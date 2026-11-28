import type { AccountInfo, SilentRequest } from "@azure/msal-browser";
import { describe, expect, it, vi } from "vitest";
import { acquireEntraHeaders, devApiConfirms, resolveAccount } from "../lib/auth";

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

const sampleAccount = {
  homeAccountId: "uid.tid",
  environment: "login.microsoftonline.com",
  tenantId: "tid",
  username: "analyst@example.com",
  localAccountId: "uid",
} as AccountInfo;

describe("Entra account resolution and token acquisition", () => {
  it("adopts a cached account when active account is unset (e.g. another tab signed in)", () => {
    let active: AccountInfo | null = null;
    const setActiveAccount = vi.fn((a: AccountInfo | null) => {
      active = a;
    });
    const pca = {
      getActiveAccount: () => active,
      getAllAccounts: () => [sampleAccount],
      setActiveAccount,
    };
    expect(resolveAccount(pca)).toBe(sampleAccount);
    expect(setActiveAccount).toHaveBeenCalledWith(sampleAccount);
  });

  it("acquires a bearer token and forwards forceRefresh when retrying a 401", async () => {
    const acquireTokenSilent = vi.fn(async (_req: SilentRequest) => ({ accessToken: "tok-123" }) as never);
    const pca = {
      getActiveAccount: () => null,
      getAllAccounts: () => [sampleAccount],
      setActiveAccount: vi.fn(),
      acquireTokenSilent,
    };

    expect(await acquireEntraHeaders(pca, "api://board/Board.Access")).toEqual({ authorization: "Bearer tok-123" });
    expect(acquireTokenSilent).toHaveBeenLastCalledWith({ scopes: ["api://board/Board.Access"], account: sampleAccount });

    expect(await acquireEntraHeaders(pca, "api://board/Board.Access", true)).toEqual({ authorization: "Bearer tok-123" });
    expect(acquireTokenSilent).toHaveBeenLastCalledWith({ scopes: ["api://board/Board.Access"], account: sampleAccount, forceRefresh: true });
  });

  it("returns null when no account is cached or interaction is required", async () => {
    const emptyPca = {
      getActiveAccount: () => null,
      getAllAccounts: () => [],
      setActiveAccount: vi.fn(),
      acquireTokenSilent: vi.fn(),
    };
    expect(await acquireEntraHeaders(emptyPca, "api://board/Board.Access")).toBeNull();

    const interactionErr = Object.assign(new Error("login required"), { name: "InteractionRequiredAuthError" });
    const expiredPca = {
      getActiveAccount: () => sampleAccount,
      getAllAccounts: () => [sampleAccount],
      setActiveAccount: vi.fn(),
      acquireTokenSilent: vi.fn(async () => {
        throw interactionErr;
      }),
    };
    expect(await acquireEntraHeaders(expiredPca, "api://board/Board.Access")).toBeNull();

    const noAccountErr = Object.assign(new Error("no account"), { name: "BrowserAuthError", errorCode: "no_account_error" });
    const signedOutElsewherePca = {
      ...expiredPca,
      acquireTokenSilent: vi.fn(async () => {
        throw noAccountErr;
      }),
    };
    expect(await acquireEntraHeaders(signedOutElsewherePca, "api://board/Board.Access")).toBeNull();
  });

  it("rethrows transient network errors instead of treating the user as signed out", async () => {
    const networkErr = Object.assign(new Error("offline"), { name: "BrowserAuthError", errorCode: "network_error" });
    const pca = {
      getActiveAccount: () => sampleAccount,
      getAllAccounts: () => [sampleAccount],
      setActiveAccount: vi.fn(),
      acquireTokenSilent: vi.fn(async () => {
        throw networkErr;
      }),
    };
    await expect(acquireEntraHeaders(pca, "api://board/Board.Access")).rejects.toThrow("offline");
  });
});
