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
