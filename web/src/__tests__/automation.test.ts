import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { allowedModes, defaultRule, revertWords, ruleProblems, splitList, targetLabel, type Ceiling, type KindView } from "../lib/automation";
import { AutoExecutedTag } from "../components/request-action";

const ceiling: Ceiling = {
  conditional_auto_allowed: ["isolate_device"],
  irreversible_auto_allowed: [],
  min_confidence_floor: 0.85,
  max_per_hour: 5,
  max_per_incident: 1,
  max_revert_after_minutes: 240,
  change_expiry_hours: 24,
};

const kind = (over: Partial<KindView> = {}): KindView => ({
  kind: "isolate_device",
  title: "Isolate device",
  destructive: true,
  reversible: true,
  reverse_kind: "release_device",
  ceiling_allows_rule: true,
  file: { mode: "approval", confirm_target: false, rule: null },
  override: null,
  override_version: null,
  effective: { mode: "approval", confirm_target: false, rule: null },
  rule_id: null,
  mode: "approval",
  ...over,
});

describe("automation helpers", () => {
  it("never offers a mode looser than policy.json, nor auto for destructive kinds", () => {
    expect(allowedModes(kind())).toEqual(["approval", "two_approvers", "disabled"]);
    expect(allowedModes(kind({ destructive: false, file: { mode: "auto", confirm_target: false, rule: null } }))).toEqual(["auto", "on_instruction", "approval", "two_approvers", "disabled"]);
    expect(allowedModes(kind({ file: { mode: "two_approvers", confirm_target: false, rule: null } }))).toEqual(["two_approvers", "disabled"]);
  });

  it("default rule fits the ceiling", () => {
    const r = defaultRule(kind(), ceiling);
    expect(ruleProblems(kind(), r, ceiling)).toEqual([]);
    expect(r.revert_after_minutes).toBe(60);
  });

  it("flags rules beyond the ceiling", () => {
    const r = { ...defaultRule(kind(), ceiling), min_confidence: 0.5, max_per_hour: 50, severities: [] as string[] };
    const p = ruleProblems(kind(), r, ceiling);
    expect(p.some((x) => x.includes("confidence"))).toBe(true);
    expect(p.some((x) => x.includes("max per hour"))).toBe(true);
    expect(p.some((x) => x.includes("severity"))).toBe(true);
    expect(ruleProblems(kind({ ceiling_allows_rule: false }), defaultRule(kind(), ceiling), ceiling)[0]).toContain("does not allow");
    expect(ruleProblems(kind(), { ...defaultRule(kind(), ceiling), revert_after_minutes: null }, ceiling).some((x) => x.includes("revert after"))).toBe(true);
  });

  it("parses lists and labels", () => {
    expect(splitList(" a, b ,, c ")).toEqual(["a", "b", "c"]);
    expect(splitList("  ")).toBeNull();
    expect(targetLabel("kind:isolate_device")).toBe("isolate_device");
    expect(targetLabel("trigger:file-phishing")).toBe("trigger file-phishing");
    expect(targetLabel("automation:paused")).toBe("resume automation");
    expect(revertWords("failed", null)).toContain("still in place");
    expect(revertWords(null, null)).toBeNull();
  });

  it("marks auto-executed actions distinctly", () => {
    expect(renderToStaticMarkup(createElement(AutoExecutedTag, { rule: "isolate_device@v3" }))).toContain("auto-executed under rule isolate_device@v3");
    expect(renderToStaticMarkup(createElement(AutoExecutedTag, { rule: null }))).toBe("");
  });
});
