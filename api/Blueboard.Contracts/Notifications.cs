using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Blueboard.Contracts;

// Notification settings: WHAT the board sends outside itself and to whom. WHERE (webhook URL, Teams URL, ntfy URL,
// mailbox, secrets) stays in app settings and never appears here.

/// <summary>Which events notify. Approvals are the approver notices (requested, reminder, second approval, expired, interrupted, failed).</summary>
public sealed record NotificationEventToggles(
    bool Approvals, bool Mention, bool Question, bool Reply, bool Verdict, bool Finding, bool Incident, bool ActionResult);

/// <summary>Quiet hours: events are held (not dropped) and sent when the window ends. HH:mm in the IANA time zone.</summary>
public sealed record QuietHours(bool Enabled, string Start, string End, string TimeZone, bool ExceptHighSeverity);

/// <summary>Delivery paths a person has on. Ntfy defaults to on, so documents stored before it existed still read.</summary>
public sealed record NotificationSinkToggles(bool Webhook, bool Teams, bool Mail, bool Ntfy = true);

/// <summary>A full settings document: the board defaults, or one person's effective settings.</summary>
public sealed record NotificationSettings(
    bool Enabled,
    NotificationEventToggles Events,
    string[] VerdictClassifications,
    string MinIncidentSeverity,
    bool MentionsFromPeople,
    bool IncludeSummary,
    QuietHours QuietHours,
    NotificationSinkToggles Sinks);

// The PUT bodies are JSON merge patches over the stored document: send only the fields to change; null resets a
// field (to the board default for "mine", to the built-in default for "defaults"). Unknown keys are refused.
// These records only document that shape (OpenAPI); the board validates the raw JSON strictly.

public sealed record NotificationEventTogglesPatch(
    bool? Approvals = null, bool? Mention = null, bool? Question = null, bool? Reply = null, bool? Verdict = null,
    bool? Finding = null, bool? Incident = null, bool? ActionResult = null);

public sealed record QuietHoursPatch(
    bool? Enabled = null,
    [Description("HH:mm")] string? Start = null,
    [Description("HH:mm")] string? End = null,
    [Description("IANA time zone, e.g. Australia/Sydney")] string? TimeZone = null,
    bool? ExceptHighSeverity = null);

public sealed record NotificationSinkTogglesPatch(bool? Webhook = null, bool? Teams = null, bool? Mail = null, bool? Ntfy = null);

public sealed record NotificationSettingsPatch(
    bool? Enabled = null,
    NotificationEventTogglesPatch? Events = null,
    [Description("Verdict classifications that notify: truePositive, falsePositive, informationalExpectedActivity, unknown")] string[]? VerdictClassifications = null,
    [Description("informational | low | medium | high")] string? MinIncidentSeverity = null,
    bool? MentionsFromPeople = null,
    [Description("Send a one-line summary of the (untrusted) message text")] bool? IncludeSummary = null,
    QuietHoursPatch? QuietHours = null,
    NotificationSinkTogglesPatch? Sinks = null);

/// <summary>A sink as the settings page sees it. Never a URL or secret.</summary>
public sealed record NotificationSinkStatus(string Sink, bool Configured, bool Ready, string? Problem);

/// <summary>GET /api/notifications/settings and the PUT responses.</summary>
public sealed record NotificationSettingsView(
    NotificationSettings Defaults,
    [property: Description("The caller's own overrides (a partial settings document), or null")] JsonElement? Mine,
    NotificationSettings Effective,
    IReadOnlyList<NotificationSinkStatus> Sinks,
    bool CanEditDefaults);

/// <summary>Who a notice is for, so a downstream router (ntfy, Pushover, n8n) can route it.</summary>
public sealed record NotificationRecipient(
    string Handle,
    string DisplayName,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Email = null);

public sealed record NotificationTestInput(
    [Description("Sample event to send (default: the generic test notice)")]
    [AllowedValues("approvals", "mention", "question", "reply", "verdict", "finding", "incident", "action_result")] string? Event = null);

public sealed record NotificationRecentQuery([Description("1-200, default 50")][Range(1, 200)] int Limit = 50);

/// <summary>One delivery row (admin: recent deliveries).</summary>
public sealed record NotificationDelivery(
    string Event, string Sink, string Status, string? Error, string? Recipient, DateTimeOffset CreatedAt, Guid? MessageId, Guid? ActionId);
