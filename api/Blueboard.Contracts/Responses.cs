using System.Text.Json;

namespace Blueboard.Contracts;

// What the board returns. Shared with the agent SDK so agents read typed results, not hand-copied shapes.

public sealed record Author(string Handle, string DisplayName, string Kind);

public sealed record Message(
    Guid Id,
    string Seq,
    string Channel,
    Author Author,
    Guid? ParentId,
    Guid? IncidentId,
    string? IncidentGraphId,
    string Type,
    string Body,
    JsonElement? Payload,
    string[] Mentions,
    string ClaimState,
    string? ClaimedBy,
    DateTimeOffset? ClaimExpiresAt,
    DateTimeOffset CreatedAt,
    int ReplyCount,
    string? Snippet = null,
    DateTimeOffset? LastReplyAt = null,
    // Up to 4 distinct repliers, most recent first (thread roots; empty for replies).
    Author[]? ReplyAuthors = null,
    // Emoji reactions, in the order each emoji was first used. Null when there are none.
    Reaction[]? Reactions = null);

/// <summary>One emoji on a message: how many reacted with it and who (up to 20 handles, earliest first).</summary>
public sealed record Reaction(string Emoji, int Count, string[] Handles);

public sealed record FeedResult(IReadOnlyList<Message> Messages, string? Cursor);
public sealed record ThreadResult(Message Root, IReadOnlyList<Message> Replies);
public sealed record ChannelInfo(string Name, string Topic, string? LastSeq);
public sealed record Participant(string Handle, string DisplayName, string Kind, string[] Roles, string? Description, DateTimeOffset? LastSeenAt);

/// <summary>The caller as the board sees it (whoami, /api/me).</summary>
public sealed record Identity(Guid Id, string Handle, string DisplayName, string Kind, string[] Roles);

public sealed record ActionRow(
    Guid Id, string Kind, JsonElement Params, Guid? IncidentId, string? IncidentGraphId, Guid? RequestMessageId,
    string RequestedBy, string Justification, string Status, bool RequiresApproval, string[] PolicyNotes,
    string? DecidedBy, DateTimeOffset? DecidedAt, string? DecisionNote, JsonElement? Result, string? Error, DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt = null, int ApprovalsRequired = 1, string[]? Approvals = null, DateTimeOffset? HeldAt = null,
    // The person's board message whose instruction counted as the approval (policy act_on_instruction).
    Guid? OnBehalfOf = null,
    // Set when the action ran without a person under a conditional automation rule (e.g. "isolate_device@v3").
    string? AutoRule = null,
    // Automatic revert: minutes after success, when it is due, its state (scheduled | kept | reverting | reverted | failed),
    // the revert action filed for it, and (on a revert action) the action it undoes.
    int? RevertAfterMinutes = null, DateTimeOffset? RevertAt = null, string? RevertState = null, Guid? RevertActionId = null, Guid? RevertOf = null)
{
    /// <summary>Set on open actions whose kind is in confirm_target: the name the approver is asked to type back.</summary>
    public string? ConfirmPrompt { get; init; }
}

/// <summary>A webhook subscription. The secret is returned once, by subscribe, and never again.</summary>
public sealed record Subscription(Guid Id, string Url, string[] Events, string? Channel, bool Enabled, int Failures, DateTimeOffset CreatedAt, string? Secret = null);

public sealed record Followup(Guid Id, Guid MessageId, DateTimeOffset DueAt);

public sealed record TiFindingIndicator(string Kind, string Value);

public sealed record TiFinding(
    Guid Id,
    string Title,
    string Summary,
    string Severity,
    string Status,
    double? Confidence,
    string[] TechStack,
    string[] MatchedWatches,
    string[] Cves,
    TiFindingIndicator[] Indicators,
    string Source,
    string? SourceUrl,
    string? Recommendation,
    Author Author,
    Guid? MessageId,
    string? DedupeKey,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record SharedMemory(
    Guid Id,
    string Key,
    string Category,
    string Title,
    string Content,
    string[] Tags,
    string[] Entities,
    double? Confidence,
    bool Verified,
    string? VerifiedBy,
    DateTimeOffset? VerifiedAt,
    bool Pinned,
    bool Archived,
    Guid? SourceIncidentId,
    string? SourceIncidentGraphId,
    Guid? SourceMessageId,
    DateTimeOffset? ExpiresAt,
    Author CreatedBy,
    Author UpdatedBy,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>What a timeline event or graph element came from: an alert (Defender id), a board message or a brokered action.</summary>
public sealed record TimelineRef(string Type, string Id, string? Label = null);

/// <summary>
/// One attack-timeline event. Kind: alert | evidence (from Defender/Sentinel data) | finding | ioc | verdict (board
/// messages) | action (brokered actions). Lane: attack (what the adversary did), detection (alerts raised) or response
/// (what the team did). Reported = a participant's claim (finding/ioc events[]), not Defender evidence; InEvidence says
/// whether its entities appear in the incident's evidence. Source is who the board says it came from: for a reported
/// event always "reported by @handle"; the source the participant claimed (say "Microsoft Defender XDR") is kept apart
/// in ClaimedSource, untrusted, so a claim can never look like Defender evidence.
/// </summary>
public sealed record TimelineEvent(
    string Id, DateTimeOffset Ts, string Kind, string Lane, string Action, string[] Entities, string Source,
    TimelineRef[] Refs, string[] ReportedBy, bool Reported, bool? InEvidence, Guid? ThreadId, string? ClaimedSource = null);

public sealed record IncidentTimelineResult(Guid IncidentId, string GraphId, IReadOnlyList<TimelineEvent> Events, int Total, bool Truncated, string Notice);

/// <summary>
/// An entity in the attack graph. Kind: user | device | ip | domain | url | file | process | mailbox | email |
/// cloud_app | service_principal | azure_resource. Verdict: malicious | suspicious | benign (strongest from Defender
/// evidence and board IOCs). Protected: on a policy protected_* list; ProtectedAs names the entry for admins only.
/// </summary>
public sealed record GraphNode(
    string Id, string Kind, string Label, string[] Keys, string[] AlertIds, bool InEvidence, string? Verdict, bool Compromised,
    bool Protected, string? ProtectedAs, string[] PendingActions, string[] ExecutedActions);

/// <summary>A relationship derived from evidence. Inferred = only co-occurrence in the same alert or a command-line mention.</summary>
public sealed record GraphEdge(string From, string To, string Relation, string[] AlertIds, bool Inferred);

public sealed record IncidentGraphResult(Guid IncidentId, string GraphId, IReadOnlyList<GraphNode> Nodes, IReadOnlyList<GraphEdge> Edges, bool Truncated, string Notice);

/// <summary>A playbook run started from a threat intel finding: its checklist steps live in a thread in #intel.</summary>
public sealed record TiPlaybookRun(Guid Id, Guid TiFindingId, string PlaybookId, string PlaybookTitle, Guid? RootMessageId, int StepsPosted, int TotalSteps, bool Existing);

/// <summary>
/// Webhook body. Ids only, never message content: the agent reads the message through MCP with its own token.
/// Signed: X-Blueboard-Signature: sha256=hex(HMAC-SHA256(secret, "{timestamp}.{body}")), X-Blueboard-Timestamp: unix seconds.
/// </summary>
public sealed record WebhookEvent(string Event, Guid MessageId, string Seq, Guid SubscriptionId, Guid DeliveryId);

public static class WebhookEvents
{
    public const string IncidentNew = "incident.new";
    public const string IncidentUpdated = "incident.updated";
    public const string Mention = "mention";
    public const string ThreadReply = "thread.reply";
    public const string ClaimExpired = "claim.expired";
    public const string ActionDecided = "action.decided";
    public static readonly string[] All = [IncidentNew, IncidentUpdated, Mention, ThreadReply, ClaimExpired, ActionDecided];

    public const string SignatureHeader = "X-Blueboard-Signature";
    public const string TimestampHeader = "X-Blueboard-Timestamp";
}

/// <summary>report_usage result: what the board recorded and how it priced it, with your budget position.</summary>
public sealed record UsageReceipt(long Id, string Model, long Tokens, double CostUsd, string CostSource, bool Duplicate, BudgetPosition? Budget);

/// <summary>Spend against an agent's budget for the current UTC day and month (null limits are not enforced).</summary>
public sealed record BudgetPosition(double DayUsd, long DayTokens, double MonthUsd, long MonthTokens,
    double? DailyUsdLimit, double? MonthlyUsdLimit, long? DailyTokenLimit, long? MonthlyTokenLimit, int SoftPct, bool Blocked);

/// <summary>Feedback on one of your messages: a person's call, or the incident's resolution compared with your verdict.</summary>
public sealed record AgentFeedbackItem(
    Guid MessageId, string MessageType, string? IncidentGraphId, string Source, string Verdict, string? Reason,
    string? YourClassification, string? CorrectedClassification, string? GivenBy, DateTimeOffset At);

public sealed record AgentFeedbackResult(string Notice, int Correct, int Incorrect, IReadOnlyList<AgentFeedbackItem> Items);
/// <summary>Hits on one UTC day of a back-test window.</summary>
public sealed record BacktestDay(string Date, long Hits);
public sealed record BacktestValue(string Value, long Hits);
/// <summary>Distinct values seen in one entity column, with the five most frequent.</summary>
public sealed record BacktestEntity(string Column, long Distinct, BacktestValue[] Top);

/// <summary>
/// backtest_detection: what the candidate query matched over the window. The board ran it and stored it; cite
/// backtest_id in create_detection_rule within bindable_until.
/// </summary>
public sealed record BacktestResult(
    Guid BacktestId, string Target, string QuerySha256, int LookbackDays, long TotalHits, long UndatedHits, bool Truncated,
    BacktestDay[] HitsPerDay, BacktestEntity[] DistinctEntities, JsonElement[] SampleRows, double EstimatedAlertsPerDay, long PeakHitsPerDay,
    DateTimeOffset CreatedAt, DateTimeOffset BindableUntil, string[] Notes);

/// <summary>One prioritised exposure: a CVE (or recommendation) on the tenant's devices, scored by what makes it urgent.</summary>
public sealed record ExposureItem(
    string Id, string Title, string? CveId, string Severity, double? Cvss, bool ExploitAvailable, bool KnownExploited, int Devices,
    int InternetFacingDevices, int CriticalDevices, int InOpenIncidents, double Score, string[] Reasons, ExposureDevice[] TopDevices,
    string? Remediation);

/// <summary>A device an exposure affects, with every id the remediation request can target.</summary>
public sealed record ExposureDevice(string? MdeDeviceId, string? Name, string? AadDeviceId, bool InternetFacing, string? AssetValue, bool InOpenIncident);

