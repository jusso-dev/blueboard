using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Blueboard.Contracts;

// Conditional automation (policy.json "automation" + the admin override store). REST-only: none of these are ever
// exposed as MCP tools, and only human Board.Admin principals may call the routes that take them.

/// <summary>
/// When a destructive kind may run without a person: every condition must hold, otherwise the request goes to the
/// normal approval path with a note naming the condition that failed. Used in policy.json (automation.rules) and as
/// the rule in an admin override. The file's automation.ceiling bounds every rule.
/// </summary>
public sealed record AutoRuleSpec(
    [Description("Lowest confidence (0-1) of a truePositive verdict on the incident, posted by someone other than the requester")]
    [Range(0, 1)] double MinConfidence = 0.9,
    [Description("Incident severities the rule applies to: informational, low, medium, high (at least one)")]
    string[]? Severities = null,
    [Description("Optional: only incidents with an alert from one of these service sources / products, e.g. microsoftDefenderForEndpoint")]
    string[]? Sources = null,
    [Description("Most auto-runs of this kind per rolling hour, tenant-wide; over the cap the request waits for approval")]
    [Range(1, 1000)] int MaxPerHour = 3,
    [Description("Most auto-runs of this kind on one incident; over the cap the request waits for approval")]
    [Range(1, 100)] int MaxPerIncident = 1,
    [Description("Optional: only requests from these handles may auto-run")]
    string[]? Requesters = null,
    [Description("Reversible kinds: undo automatically this many minutes after it ran (5-10080). Required for reversible kinds, not allowed for irreversible ones")]
    [Range(5, 10080)] int? RevertAfterMinutes = null,
    [Description("Only a person's verdict counts as corroboration (agents' verdicts are ignored)")]
    bool RequireHumanVerdict = false,
    [Description("Optional: the requester's agent risk score (0-100) must be at or below this. An unknown score (a person, or an agent not scored yet) fails the condition")]
    [Range(0, 100)] int? MaxRequesterRisk = null);

/// <summary>
/// The whole desired setting for one action kind, within the policy.json ceiling. Reset drops the override, going back
/// to what policy.json says. Tightening applies at once; loosening waits for a second, different admin.
/// </summary>
public sealed record KindOverrideInput(
    [Description("Why (5-500 characters); recorded in the audit log")][StringLength(500, MinimumLength = 5)] string Reason,
    [Description("disabled | two_approvers | approval | on_instruction | auto (auto: non-destructive kinds only). Required unless reset")]
    [AllowedValues("disabled", "two_approvers", "approval", "on_instruction", "auto")] string? Mode = null,
    [Description("Approver types the target back. Required unless reset")] bool? ConfirmTarget = null,
    [Description("Conditional auto rule for a destructive kind, or omit for none")] AutoRuleSpec? Rule = null,
    [Description("true: remove the override and use policy.json")] bool Reset = false);

/// <summary>A playbook auto-attach trigger. Adding, editing or re-enabling one is loosening; disabling or removing it is tightening.</summary>
public sealed record TriggerInput(
    [Description("Why (5-500 characters); recorded in the audit log")][StringLength(500, MinimumLength = 5)] string Reason,
    [Description("Playbook id to attach")][StringLength(41, MinimumLength = 1), RegularExpression("^[a-z0-9][a-z0-9-]{0,40}$")] string? PlaybookId = null,
    [Description("Higher wins when several triggers match (-100 to 1000)")][Range(-100, 1000)] int Priority = 0,
    [Description("Only incidents with one of these severities (filter)")] string[]? Severities = null,
    [Description("Alert service sources / products, e.g. microsoftDefenderForOffice365")] string[]? Sources = null,
    [Description("Incident or alert title contains one of these")] string[]? Titles = null,
    [Description("Alert category equals one of these")] string[]? Categories = null,
    [Description("MITRE technique, e.g. T1566 (sub-techniques match)")] string[]? Techniques = null,
    [Description("false: the trigger never attaches anything")] bool Enabled = true,
    [Description("true: delete a custom trigger (file triggers can only be disabled)")] bool Remove = false);

/// <summary>Automation kill switch. Pausing applies at once (any admin); resuming is loosening and needs a second admin.</summary>
public sealed record AutomationPauseInput(
    [Description("true pauses every automatic decision (requests wait for approval); false asks to resume")] bool Paused,
    [Description("Why (5-500 characters)")][StringLength(500, MinimumLength = 5)] string Reason);

public sealed record PolicyChangeDecisionInput(
    [Description("approve or deny")][AllowedValues("approve", "deny")] string Decision,
    [Description("Optional note (up to 2000 characters)")][StringLength(2000)] string? Note = null);

/// <summary>Keep: cancel an action's scheduled automatic revert. now: revert it immediately.</summary>
public sealed record RevertOpInput(
    [Description("keep (cancel the scheduled revert) or now (revert immediately)")][AllowedValues("keep", "now")] string Op,
    [Description("Optional note (up to 500 characters)")][StringLength(500)] string? Note = null,
    [Description("now only, when the reverse kind is in policy confirm_target: the target name typed back")][StringLength(500)] string? Confirm = null);
