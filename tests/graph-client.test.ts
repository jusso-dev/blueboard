import { describe, expect, it, vi } from "vitest";

vi.mock("@azure/identity", () => ({
  DefaultAzureCredential: class {
    async getToken() {
      return { token: "t", expiresOnTimestamp: Date.now() + 60_000 };
    }
  },
}));

const { msFetch, GRAPH } = await import("../src/lib/graph/client");

describe("msFetch token guard", () => {
  it("refuses a look-alike origin", async () => {
    await expect(msFetch(GRAPH, "https://graph.microsoft.com.evil.example/v1.0/me")).rejects.toThrow(/refusing to send token/);
  });
  it("refuses dot-segments", async () => {
    await expect(msFetch(GRAPH, "/v1.0/security/incidents/../../me")).rejects.toThrow(/dot-segments/);
    await expect(msFetch(GRAPH, "/v1.0/users/%2E%2E/x")).rejects.toThrow(/dot-segments/);
  });
});
