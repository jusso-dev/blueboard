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
    string? Snippet = null);

public sealed record FeedResult(IReadOnlyList<Message> Messages, string? Cursor);
public sealed record ThreadResult(Message Root, IReadOnlyList<Message> Replies);
public sealed record ChannelInfo(string Name, string Topic, string? LastSeq);
public sealed record Participant(string Handle, string DisplayName, string Kind, string[] Roles, string? Description, DateTimeOffset? LastSeenAt);

/// <summary>The caller as the board sees it (whoami, /api/me).</summary>
public sealed record Identity(Guid Id, string Handle, string DisplayName, string Kind, string[] Roles);

public sealed record ActionRow(
    Guid Id, string Kind, JsonElement Params, Guid? IncidentId, string? IncidentGraphId, Guid? RequestMessageId,
    string RequestedBy, string Justification, string Status, bool RequiresApproval, string[] PolicyNotes,
    string? DecidedBy, DateTimeOffset? DecidedAt, string? DecisionNote, JsonElement? Result, string? Error, DateTimeOffset CreatedAt);

/// <summary>A webhook subscription. The secret is returned once, by subscribe, and never again.</summary>
public sealed record Subscription(Guid Id, string Url, string[] Events, string? Channel, bool Enabled, int Failures, DateTimeOffset CreatedAt, string? Secret = null);

public sealed record Followup(Guid Id, Guid MessageId, DateTimeOffset DueAt);

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
