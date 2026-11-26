import { describe, expect, it } from "vitest";
import {
  clearOverride,
  describeValue,
  diffPatch,
  fieldState,
  isEmptyPatch,
  isOverridden,
  mergeSettings,
  normalizeMine,
  SINK_KEYS,
  SINK_LABELS,
  setOverride,
  timeZones,
  type DeepPartial,
  type NotificationSettings,
  type SettingsResponse,
} from "../lib/notifications";

const defaults: NotificationSettings = {
  enabled: true,
  events: { approvals: true, mention: true, question: true, reply: false, verdict: false, finding: false, incident: true, action_result: true },
  verdict_classifications: ["truePositive"],
  min_incident_severity: "medium",
  mentions_from_people: true,
  include_summary: false,
  quiet_hours: { enabled: false, start: "22:00", end: "07:00", time_zone: "UTC", except_high_severity: true },
  sinks: { webhook: true, teams: true, mail: false, ntfy: true },
};

describe("merge and inherited state", () => {
  it("returns the defaults when there are no overrides", () => {
    expect(mergeSettings(defaults, null)).toEqual(defaults);
    expect(mergeSettings(defaults, {})).toEqual(defaults);
  });

  it("lays nested overrides over the defaults without touching siblings", () => {
    const mine: DeepPartial<NotificationSettings> = { events: { reply: true }, quiet_hours: { enabled: true, time_zone: "Australia/Melbourne" } };
    const eff = mergeSettings(defaults, mine);
    expect(eff.events).toEqual({ ...defaults.events, reply: true });
    expect(eff.quiet_hours).toEqual({ ...defaults.quiet_hours, enabled: true, time_zone: "Australia/Melbourne" });
    expect(eff.sinks).toEqual(defaults.sinks);
    expect(defaults.events.reply).toBe(false); // not mutated
  });

  it("treats arrays as whole values, including an empty override", () => {
    expect(mergeSettings(defaults, { verdict_classifications: ["falsePositive", "unknown"] }).verdict_classifications).toEqual(["falsePositive", "unknown"]);
    expect(mergeSettings(defaults, { verdict_classifications: [] }).verdict_classifications).toEqual([]);
  });

  it("treats null in mine as inherited (the server may echo resets)", () => {
    const mine = { enabled: null, events: { mention: null } } as unknown as DeepPartial<NotificationSettings>;
    expect(mergeSettings(defaults, mine)).toEqual(defaults);
    expect(isOverridden(mine, "enabled")).toBe(false);
    expect(normalizeMine(mine)).toEqual({});
  });

  it("matches the server's effective settings", () => {
    const mine: DeepPartial<NotificationSettings> = { enabled: false, sinks: { mail: true }, min_incident_severity: "high" };
    const effective = { ...defaults, enabled: false, min_incident_severity: "high" as const, sinks: { ...defaults.sinks, mail: true } };
    expect(mergeSettings(defaults, mine)).toEqual(effective);
  });

  it("reports inherited vs overridden per field, with the board default for the hint", () => {
    const mine: DeepPartial<NotificationSettings> = { events: { approvals: false }, quiet_hours: { start: "21:30" } };
    expect(fieldState(defaults, mine, "events.approvals")).toEqual({ value: false, overridden: true, defaultValue: true });
    expect(fieldState(defaults, mine, "events.mention")).toEqual({ value: true, overridden: false, defaultValue: true });
    expect(fieldState(defaults, mine, "quiet_hours.start")).toEqual({ value: "21:30", overridden: true, defaultValue: "22:00" });
    // An override equal to the default is still the person's own choice: it survives a later change of the default.
    expect(fieldState(defaults, { include_summary: false }, "include_summary").overridden).toBe(true);
  });

  it("describes defaults in words", () => {
    expect(describeValue("enabled", true)).toBe("On");
    expect(describeValue("events.reply", false)).toBe("Off");
    expect(describeValue("min_incident_severity", "medium")).toBe("Medium");
    expect(describeValue("verdict_classifications", ["truePositive", "unknown"])).toBe("True positive, Undetermined");
    expect(describeValue("verdict_classifications", [])).toBe("none");
    expect(describeValue("quiet_hours.start", "22:00")).toBe("22:00");
  });
});

describe("setOverride / clearOverride", () => {
  it("sets a nested key, creating parents, without mutating", () => {
    const mine: DeepPartial<NotificationSettings> = { events: { reply: true } };
    const next = setOverride(mine, "quiet_hours.end", "06:00");
    expect(next).toEqual({ events: { reply: true }, quiet_hours: { end: "06:00" } });
    expect(mine).toEqual({ events: { reply: true } });
  });

  it("clears a key and prunes parents that become empty", () => {
    const mine: DeepPartial<NotificationSettings> = { events: { reply: true }, quiet_hours: { end: "06:00", enabled: true } };
    expect(clearOverride(mine, "events.reply")).toEqual({ quiet_hours: { end: "06:00", enabled: true } });
    expect(clearOverride(mine, "quiet_hours.end")).toEqual({ events: { reply: true }, quiet_hours: { enabled: true } });
    expect(clearOverride(mine, "sinks.mail")).toEqual(mine);
  });
});

describe("diffPatch (PUT bodies)", () => {
  it("sends only what changed", () => {
    const base = { enabled: true, events: { reply: true, mention: false } };
    const next = { enabled: true, events: { reply: true, mention: true } };
    expect(diffPatch(base, next)).toEqual({ events: { mention: true } });
  });

  it("is empty when nothing changed", () => {
    const same = { events: { reply: true }, verdict_classifications: ["truePositive"] };
    expect(isEmptyPatch(diffPatch(same, structuredClone(same)))).toBe(true);
  });

  it("adds new overrides as a deep partial", () => {
    expect(diffPatch({}, { quiet_hours: { enabled: true, time_zone: "Australia/Melbourne" } })).toEqual({ quiet_hours: { enabled: true, time_zone: "Australia/Melbourne" } });
  });

  it("sends arrays whole when they change", () => {
    expect(diffPatch({ verdict_classifications: ["truePositive"] }, { verdict_classifications: ["truePositive", "unknown"] })).toEqual({
      verdict_classifications: ["truePositive", "unknown"],
    });
    expect(diffPatch({ verdict_classifications: ["truePositive"] }, { verdict_classifications: [] })).toEqual({ verdict_classifications: [] });
  });

  it("turns reset to default into null on that key only", () => {
    const mine: DeepPartial<NotificationSettings> = { enabled: false, events: { reply: true, mention: false } };
    const patch = diffPatch(mine, clearOverride(mine, "events.reply"));
    expect(patch).toEqual({ events: { reply: null } });
  });

  it("nulls every key under a parent that was reset entirely", () => {
    const mine: DeepPartial<NotificationSettings> = { quiet_hours: { start: "21:00" }, enabled: false };
    expect(diffPatch(mine, clearOverride(mine, "quiet_hours.start"))).toEqual({ quiet_hours: { start: null } });
    expect(diffPatch(mine, clearOverride(mine, "enabled"))).toEqual({ enabled: null });
  });

  it("resetting an array override sends null, not []", () => {
    const mine: DeepPartial<NotificationSettings> = { verdict_classifications: [] };
    expect(diffPatch(mine, clearOverride(mine, "verdict_classifications"))).toEqual({ verdict_classifications: null });
  });

  it("set then reset in one debounce window sends nothing", () => {
    const mine: DeepPartial<NotificationSettings> = {};
    const next = clearOverride(setOverride(mine, "events.reply", true), "events.reply");
    expect(isEmptyPatch(diffPatch(mine, next))).toBe(true);
  });

  it("round-trips: applying the patch to the base gives the next state", () => {
    const base: DeepPartial<NotificationSettings> = { enabled: false, events: { reply: true }, sinks: { mail: true } };
    const next: DeepPartial<NotificationSettings> = { events: { reply: true, verdict: true }, quiet_hours: { enabled: true } };
    const patch = diffPatch(base, next);
    expect(patch).toEqual({ enabled: null, events: { verdict: true }, sinks: { mail: null }, quiet_hours: { enabled: true } });
    // Merge-patch semantics: null removes the key.
    const apply = (o: Record<string, unknown>, p: Record<string, unknown>): Record<string, unknown> => {
      const out = { ...o };
      for (const [k, v] of Object.entries(p)) {
        if (v === null) delete out[k];
        else if (typeof v === "object" && !Array.isArray(v)) {
          const inner = apply((out[k] as Record<string, unknown>) ?? {}, v as Record<string, unknown>);
          if (Object.keys(inner).length) out[k] = inner;
          else delete out[k];
        } else out[k] = v;
      }
      return out;
    };
    expect(apply(base as Record<string, unknown>, patch as Record<string, unknown>)).toEqual(next);
  });
});

describe("timeZones", () => {
  it("always offers UTC and keeps an unlisted current value", () => {
    const zones = timeZones("Mars/Olympus_Mons");
    expect(zones).toContain("UTC");
    expect(zones).toContain("Mars/Olympus_Mons");
    expect(new Set(zones).size).toBe(zones.length);
  });
});

describe("ntfy sink", () => {
  it("is listed with its label in delivery order", () => {
    expect(SINK_KEYS).toEqual(["webhook", "teams", "mail", "ntfy"]);
    expect(SINK_LABELS.ntfy).toBe("ntfy (phone push)");
    expect(SINK_KEYS.every((k) => SINK_LABELS[k])).toBe(true);
  });

  it("reads a settings response whose sinks include ntfy", () => {
    const resp: SettingsResponse = {
      defaults,
      mine: { sinks: { ntfy: false } },
      effective: { ...defaults, sinks: { ...defaults.sinks, ntfy: false } },
      sinks: [
        { sink: "webhook", configured: true, ready: true, problem: null },
        { sink: "ntfy", configured: true, ready: false, problem: "NOTIFY_NTFY_URL must be an https URL" },
      ],
      can_edit_defaults: false,
    };
    expect(resp.sinks.find((s) => s.sink === "ntfy")?.ready).toBe(false);
    expect(mergeSettings(resp.defaults, resp.mine)).toEqual(resp.effective);
    expect(fieldState(resp.defaults, resp.mine, "sinks.ntfy")).toEqual({ value: false, overridden: true, defaultValue: true });
    expect(diffPatch(resp.mine, clearOverride(resp.mine, "sinks.ntfy"))).toEqual({ sinks: { ntfy: null } });
  });

  it("fills ntfy from the defaults for a person whose stored sinks predate it", () => {
    const mine = { sinks: { webhook: false, teams: true, mail: true } } as DeepPartial<NotificationSettings>;
    expect(mergeSettings(defaults, mine).sinks).toEqual({ webhook: false, teams: true, mail: true, ntfy: true });
  });
});
