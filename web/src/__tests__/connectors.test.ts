import { describe, expect, it } from "vitest";
import { connectorsSummary, healthTag, oktaStatusTone, type ConnectorView } from "../lib/connectors";

const c = (connector: ConnectorView["connector"], configured: boolean, health: ConnectorView["health"]): ConnectorView => ({
  connector,
  configured,
  health,
  host: configured ? `${connector}.example` : null,
  auth: null,
  inbound_enabled: null,
  last_ok_at: null,
  last_error_at: null,
  last_error: null,
  last_sync_at: null,
  links: 0,
});

describe("connectors", () => {
  it("health is words and tone, never colour alone", () => {
    expect(healthTag(c("okta", false, "off"))).toEqual({ word: "Off", tone: "neutral" });
    expect(healthTag(c("okta", true, "failing"))).toEqual({ word: "Failing", tone: "critical" });
    expect(healthTag(c("jira", true, "unknown"))).toEqual({ word: "Not used yet", tone: "warning" });
    expect(healthTag(c("servicenow", true, "ok"))).toEqual({ word: "Healthy", tone: "good" });
  });

  it("admin centre summary counts configured and failing connectors", () => {
    expect(connectorsSummary(undefined)).toBeUndefined();
    expect(connectorsSummary([c("okta", false, "off"), c("jira", false, "off")])).toEqual({ status: "None configured", tone: "neutral" });
    expect(connectorsSummary([c("okta", true, "ok"), c("servicenow", true, "failing"), c("jira", false, "off")])).toEqual({ status: "1 failing", tone: "critical" });
    expect(connectorsSummary([c("okta", true, "ok"), c("servicenow", true, "unknown")])).toEqual({ status: "2 configured", tone: "good" });
  });

  it("Okta statuses that block sign-in are critical", () => {
    expect(oktaStatusTone("ACTIVE")).toBe("good");
    expect(oktaStatusTone("SUSPENDED")).toBe("critical");
    expect(oktaStatusTone("LOCKED_OUT")).toBe("critical");
    expect(oktaStatusTone("PASSWORD_EXPIRED")).toBe("warning");
    expect(oktaStatusTone(null)).toBe("neutral");
  });
});
