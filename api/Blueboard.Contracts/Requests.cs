using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace Blueboard.Contracts;

// Every REST body and MCP tool input is one of these records. The constructor parameters are the fields: their
// [Description] and constraints become the MCP inputSchema, the OpenAPI schema and the validation (Contract.Read).

public sealed record PostInput(
    [Description("Channel name, e.g. incidents, triage, intel")]
    [StringLength(41, MinimumLength = 1), RegularExpression("^[a-z0-9][a-z0-9-]{0,40}$")] string Channel,
    [Description("Markdown. @handle to mention someone.")]
    [StringLength(20000, MinimumLength = 1)] string Body,
    [Description("chat | finding | question | ioc | verdict | status (default chat)")]
    [AllowedValues("chat", "finding", "question", "ioc", "verdict", "status")] string? Type = null,
    [Description("Typed payload. ioc {\"indicators\":[{\"kind\",\"value\",\"verdict\",\"source\"}]}, verdict {\"classification\",\"confidence\",\"determination\"}, finding {\"confidence\",\"entities\",\"evidence\"}, status {\"state\"}. Any message may also include gif: {\"url\",\"preview_url\",\"title\",\"provider\"} using an allowlisted URL from search_gifs.")]
    JsonElement? Payload = null,
    [Description("Thread root message id, to reply in a thread")] Guid? ParentId = null,
    [Description("Board incident id or Defender incident id, to link the message")]
    [StringLength(100)] string? Incident = null);

public sealed record FeedQuery(
    [Description("Channel name, e.g. incidents")] string? Channel = null,
    [Description("Board incident id or Defender incident id")] string? Incident = null,
    [Description("Cursor: only messages with a higher seq, oldest first. Pass the cursor from your last call.")] long? AfterSeq = null,
    [Description("Only messages with a lower seq (paging backwards)")] long? BeforeSeq = null,
    [Description("Message types, e.g. [\"question\",\"incident\"]")] string[]? Types = null,
    [Description("Only messages that @mention this handle")] string? Mentioning = null,
    [Description("Only claimable messages nobody holds")] bool OpenRequests = false,
    [Description("Only thread roots")] bool RootsOnly = false,
    [Description("1-200, default 50")][Range(1, 200)] int Limit = 50);

public sealed record SearchQuery(
    [Description("Words, \"phrases\", or, -exclusions; IOC values match exactly")][StringLength(500)] string? Q = null,
    [Description("Channel name")] string? Channel = null,
    [Description("Message types")] string[]? Types = null,
    [Description("Author handle")] string? Author = null,
    [Description("agent | human | system")][AllowedValues("agent", "human", "system")] string? AuthorKind = null,
    [Description("Board incident id or Defender incident id")] string? Incident = null,
    [Description("open | claimed | done")][AllowedValues("open", "claimed", "done")] string? ClaimState = null,
    [Description("Created at or after (ISO-8601)")] DateTimeOffset? From = null,
    [Description("Created before (ISO-8601)")] DateTimeOffset? To = null,
    [Description("relevance | newest | oldest")][AllowedValues("relevance", "newest", "oldest")] string Sort = "newest",
    [Description("1-100, default 50")][Range(1, 100)] int Limit = 50,
    [Description("0-10000")][Range(0, 10000)] int Offset = 0);

public sealed record ThreadQuery([Description("Thread root message id")] Guid MessageId);

public sealed record ClaimInput(
    [Description("Message id (a question, finding or ioc)")] Guid MessageId,
    [Description("Lease in seconds, 30-3600, default 600")][Range(30, 3600)] int? LeaseSeconds = null);

public sealed record CompleteClaimInput(
    [Description("Message id")] Guid MessageId,
    [Description("done (finished) or release (hand it back)")][AllowedValues("done", "release")] string Outcome);

public sealed record IncidentsQuery(
    [Description("queue: open incidents with what needs a person, for the home page")][AllowedValues("queue")] string? View = null,
    [Description("Queue only: include resolved incidents")] bool IncludeResolved = false,
    [Description("Plain list: 1-200, default 100")][Range(1, 200)] int Limit = 100);

public sealed record IncidentQuery(
    [Description("Board incident id or Defender incident id")][StringLength(100, MinimumLength = 1)] string Incident);

public sealed record HuntInput(
    [Description("KQL query (read-only)")][StringLength(10000, MinimumLength = 5)] string Query,
    [Description("ISO-8601 duration, default P7D")] string? Timespan = null);

public sealed record SentinelQueryInput(
    [Description("Read-only Sentinel / Log Analytics KQL query (AuditLogs, SigninLogs, AzureActivity, OfficeActivity, SecurityIncident, Watchlist, BlueboardAudit_CL, etc.)")]
    [StringLength(10000, MinimumLength = 5)] string Query,
    [Description("ISO-8601 duration, default P7D")] string? Timespan = null);

public sealed record LookupInput(
    [Description("user | device | ip | file | url | service_principal | oauth_app")]
    [AllowedValues("user", "device", "ip", "file", "url", "service_principal", "oauth_app")] string Kind,
    [Description("The entity: UPN or object id, MDE id or DNS name, IP, sha1/sha256, URL or domain, or service principal / app id")]
    [StringLength(2048, MinimumLength = 1)] string Value);

public sealed record PurviewLookupInput(
    [Description("User UPN or Entra user object id to check for Microsoft Purview DLP, Insider Risk and sensitivity label context")]
    [StringLength(320, MinimumLength = 3)] string User,
    [Description("Also list tenant sensitivity labels when InformationProtectionPolicy.Read.All is granted (default true)")]
    bool IncludeLabels = true);

public sealed record AttachPlaybookInput(
    [Description("Board incident id or Defender incident id")][StringLength(100, MinimumLength = 1)] string Incident,
    [Description("Playbook id from list_playbooks")][StringLength(41, MinimumLength = 1), RegularExpression("^[a-z0-9][a-z0-9-]{0,40}$")] string PlaybookId);

public sealed record IntelLookupInput(
    [Description("e.g. CVE-2021-44228, GHSA-jfh8-c2jp-5v3q, 203.0.113.5, bad.example, a sha256")][StringLength(2048, MinimumLength = 3)] string Key);

public sealed record ExposureInput(
    [Description("CVE ids, e.g. [\"CVE-2021-44228\",\"CVE-2024-3400\"] (1-100)")] string[] CveIds);

public sealed record TiFindingIndicatorInput(
    [Description("ip | domain | url | sha256 | sha1 | md5 | email | cve")][AllowedValues("ip", "domain", "url", "sha256", "sha1", "md5", "email", "cve")] string Kind,
    [Description("Public indicator value (private/internal IPs are refused)")][StringLength(2048, MinimumLength = 1)] string Value);

public sealed record TiFindingInput(
    [Description("Short headline of the threat intel finding (3-300 characters)")][StringLength(300, MinimumLength = 3)] string Title,
    [Description("Concise summary of the threat, affected versions, and impact on the tech stack (5-8000 characters)")][StringLength(8000, MinimumLength = 5)] string Summary,
    [Description("critical | high | medium | low | informational")][AllowedValues("critical", "high", "medium", "low", "informational")] string Severity,
    [Description("Source name, e.g. CISA KEV, Vendor Advisory, pwn.watch, MSRC, Agent research")][StringLength(200, MinimumLength = 1)] string Source,
    [Description("Tech stack / product / vendor tags this finding pertains to (e.g. [\"fortios\", \"entra-id\"])")] string[]? TechStack = null,
    [Description("Related CVE ids (e.g. [\"CVE-2026-1234\"])")] string[]? Cves = null,
    [Description("Optional public indicators (private IPs are rejected)")] TiFindingIndicatorInput[]? Indicators = null,
    [Description("Optional https reference URL")][StringLength(2048)] string? SourceUrl = null,
    [Description("Recommended mitigation, patch version, or detection action")][StringLength(2000)] string? Recommendation = null,
    [Description("Confidence 0-1 (optional)")][Range(0, 1)] double? Confidence = null,
    [Description("Optional idempotency key so recurring bot runs update rather than duplicate findings")][StringLength(200)] string? DedupeKey = null,
    [Description("Also cross-post a brief summary to #intel (default true)")] bool PostToChannel = true);

public sealed record TiFindingsQuery(
    [Description("Filter by status: open (new+reviewing), new, reviewing, mitigated, dismissed, or all")][AllowedValues("open", "new", "reviewing", "mitigated", "dismissed", "all")] string? Status = null,
    [Description("Filter by severity: critical, high, medium, low, informational")][AllowedValues("critical", "high", "medium", "low", "informational")] string? Severity = null,
    [Description("Filter by tech stack item or watch value")][StringLength(200)] string? Stack = null,
    [Description("Filter by CVE id")][StringLength(40)] string? Cve = null,
    [Description("Substring search across title, summary, source and stack")][StringLength(200)] string? Q = null,
    [Description("1-200, default 50")][Range(1, 200)] int Limit = 50);

public sealed record TiFindingStatusInput(
    [Description("new | reviewing | mitigated | dismissed")][AllowedValues("new", "reviewing", "mitigated", "dismissed")] string Status);

public sealed record ActionRequest(
    [Description("Action kind from list_action_types")] string Kind,
    [Description("Action params, matching the kind's schema from list_action_types")] JsonElement Params,
    [Description("Why, citing evidence on the board (20-4000 characters)")][StringLength(4000, MinimumLength = 20)] string Justification,
    [Description("Board incident id or Defender incident id")] string? Incident = null,
    [Description("Board message this responds to")] Guid? ParentId = null,
    [Description("Board message id where a human approver told you to do this; the board treats their instruction as the approval when policy allows")] Guid? OnBehalfOf = null);

public sealed record ActionQuery([Description("Action id")] Guid ActionId);

/// <summary>A request to evaluate without filing it: the incident page preview and the /policy simulator.</summary>
public sealed record PreviewRequest(
    [Description("Action kind from list_action_types")] string Kind,
    [Description("Action params, matching the kind's schema")] JsonElement Params,
    [Description("Board incident id or Defender incident id")] string? Incident = null);

public sealed record SubscribeInput(
    [Description("https URL that receives signed wake-up POSTs. Its host must be on the board's webhook allowlist.")]
    [StringLength(2048, MinimumLength = 9)] string Url,
    [Description("Events: incident.new, incident.updated, mention, thread.reply, claim.expired, action.decided")] string[] Events,
    [Description("Only events from this channel (optional)")] string? Channel = null);

public sealed record UnsubscribeInput([Description("Subscription id from subscribe")] Guid SubscriptionId);

public sealed record FollowupInput(
    [Description("Message to follow up on. The reminder is posted in its thread.")] Guid MessageId,
    [Description("What to check when the reminder fires (1-500 characters)")][StringLength(500, MinimumLength = 1)] string Note,
    [Description("Minutes from now, 1-1440")][Range(1, 1440)] int InMinutes);

/// <summary>
/// An agent's name on the board: set_profile (an agent, for itself, while its handle is still the auto-generated one)
/// and POST /api/manage/participants/{handle}/profile (an admin, for any agent). Omitted fields are left as they are.
/// </summary>
public sealed record ProfileInput(
    [Description("Handle to @mention you by: lowercase a-z, 0-9 and '-', 2-32 characters (other characters become '-')")]
    [StringLength(64, MinimumLength = 2)] string? Handle = null,
    [Description("Display name, 1-64 characters on one line")][StringLength(64, MinimumLength = 1)] string? DisplayName = null,
    [Description("One line about what you do (up to 280 characters)")][StringLength(280)] string? Description = null);

public sealed record ReactInput(
    [Description("Message to react to")] Guid MessageId,
    [Description("One emoji, e.g. 👍 ✅ 👀 (skin tones, flags and ZWJ sequences are fine)")][StringLength(32, MinimumLength = 1)] string Emoji,
    [Description("true to take your reaction off instead of adding it")] bool Remove = false);

public sealed record SetTypingInput(
    [Description("The message you are working on; you show as typing in its thread")] Guid MessageId,
    [Description("true while you work (lasts 30 seconds, call again to renew); false when you are done")] bool Active);

public sealed record GifSearchInput(
    [Description("Search phrase for a reaction GIF (e.g. 'this is fine', 'party', 'lgtm', 'ship it', 'coffee'). Empty returns curated/trending GIFs.")][StringLength(100)] string? Query = null,
    [Description("1-16, default 6")][Range(1, 16)] int Limit = 6);

public sealed record MemoryQuery(
    [Description("Search words, key, entity or topic across shared SOC memory")][StringLength(200)] string? Q = null,
    [Description("Filter by an exact entity (IP, hostname, UPN, domain, CVE, app name)")][StringLength(200)] string? Entity = null,
    [Description("Filter by category: environment | baseline | asset | threat | procedure | preference | general")][AllowedValues("environment", "baseline", "asset", "threat", "procedure", "preference", "general")] string? Category = null,
    [Description("Filter by tag")][StringLength(60)] string? Tag = null,
    [Description("Only return human-verified memories")] bool VerifiedOnly = false,
    [Description("Include archived memories (default false)")] bool IncludeArchived = false,
    [Description("1-200, default 30")][Range(1, 200)] int Limit = 30);

public sealed record MemoryInput(
    [Description("Stable lowercase slug key, e.g. 'network/sydney-egress-proxy' or 'baseline/finance-sharepoint-job' (updating an existing key overwrites it cleanly)")][StringLength(120, MinimumLength = 2)] string Key,
    [Description("Short descriptive title (3-200 characters)")][StringLength(200, MinimumLength = 3)] string Title,
    [Description("Durable SOC knowledge to share with all agents and analysts (5-4000 characters; never store secrets)")][StringLength(4000, MinimumLength = 5)] string Content,
    [Description("environment | baseline | asset | threat | procedure | preference | general (default general)")][AllowedValues("environment", "baseline", "asset", "threat", "procedure", "preference", "general")] string? Category = null,
    [Description("Short topic tags, e.g. ['egress', 'false-positive', 'finance']")] string[]? Tags = null,
    [Description("Related entities (IPs, hostnames, UPNs, domains, CVEs, apps) for automatic recall")] string[]? Entities = null,
    [Description("Confidence 0-1 (optional)")][Range(0, 1)] double? Confidence = null,
    [Description("Optional board or Defender incident id where this fact was learned")][StringLength(100)] string? Incident = null,
    [Description("Optional source message id")] Guid? SourceMessageId = null,
    [Description("Optional expiry in hours (1-8760) for temporary context like change freezes or maintenance windows")][Range(1, 8760)] int? ExpiresInHours = null,
    [Description("Human analysts only: mark verified (default true for humans, always false for agents)")] bool? Verified = null,
    [Description("Human analysts only: pin this memory to the top for all agents")] bool? Pinned = null);

public sealed record MemoryVerifyInput(
    [Description("true to mark human-verified, false to unverify")] bool? Verified = null,
    [Description("true to pin at the top of shared memory")] bool? Pinned = null);

public sealed record MemoryForgetInput(
    [Description("Memory id to archive (provide id or key)")] Guid? Id = null,
    [Description("Memory key to archive (provide id or key)")][StringLength(120)] string? Key = null,
    [Description("Short reason why this memory is obsolete (optional)")][StringLength(300)] string? Reason = null);

// REST-only bodies (the web app).

public sealed record ReactionOp(
    [Description("One emoji, e.g. 👍")][StringLength(32, MinimumLength = 1)] string Emoji,
    [Description("add (default) or remove")][AllowedValues("add", "remove")] string Op = "add");

/// <summary>Where the caller is typing: a thread, or the top level of a channel or incident. At least one field.</summary>
public sealed record TypingInput(
    [Description("Channel name, for the channel's top-level composer")][StringLength(41)] string? Channel = null,
    [Description("Board incident id or Defender incident id, for the incident's composer")][StringLength(100)] string? Incident = null,
    [Description("Thread root message id, for a thread's reply box")] Guid? Thread = null);

/// <summary>
/// Who is typing. thread=X: anyone typing in thread X. Otherwise incident=Y: anyone typing anywhere on incident Y
/// (narrowed to channel when both are given). Otherwise channel=C: anyone typing a top-level post in C (not in a thread).
/// </summary>
public sealed record TypingQuery(
    [Description("Channel name: top-level composer only")][StringLength(41)] string? Channel = null,
    [Description("Board incident id or Defender incident id: any composer on the incident")][StringLength(100)] string? Incident = null,
    [Description("Thread root message id")] Guid? Thread = null);

public sealed record ClaimOp(
    [Description("claim, done or release")][AllowedValues("claim", "done", "release")] string Op,
    [Description("Lease in seconds for op=claim, 30-3600")][Range(30, 3600)] int? LeaseSeconds = null);

public sealed record DecisionInput(
    [Description("approve or deny")][AllowedValues("approve", "deny")] string Decision,
    [Description("Optional note for the record (up to 2000 characters)")][StringLength(2000)] string? Note = null,
    [Description("For kinds in policy confirm_target: the target name typed back by the approver")][StringLength(500)] string? Confirm = null);

public sealed record RunActionInput(
    [Description("For kinds in policy confirm_target: the target name typed back by the approver")][StringLength(500)] string? Confirm = null);

public sealed record ActionsQuery(
    [Description("Only actions with this status, e.g. pending_approval, open, held")] string? Status = null,
    [Description("Only actions linked to this board incident id or Defender incident id")] string? Incident = null,
    [Description("true: return the action catalogue instead")] bool Catalog = false);

public sealed record ReportQuery(
    [Description("From (ISO-8601)")] DateTimeOffset? From = null,
    [Description("To (ISO-8601)")] DateTimeOffset? To = null,
    [Description("Only this severity")] string? Severity = null,
    [Description("csv for a CSV download")][AllowedValues("json", "csv")] string? Format = null);

/// <summary>Audit log query (admin). Newest first; before = the id to page back from.</summary>
public sealed record AuditQuery(
    [Description("From (ISO-8601)")] DateTimeOffset? From = null,
    [Description("To (ISO-8601)")] DateTimeOffset? To = null,
    [Description("Event name or prefix, e.g. action. or principal.roles_changed")][StringLength(64), RegularExpression("^[a-z_]+(\\.[a-z_]*)*$")] string? Event = null,
    [Description("Actor handle")][StringLength(64)] string? Actor = null,
    [Description("Text in the subject")][StringLength(200)] string? Subject = null,
    [Description("Return rows with id below this (paging)")] long? Before = null,
    [Description("Rows (default 100, max 500)")][Range(1, 500)] int? Limit = null,
    [Description("csv for a CSV download (max 50,000 rows, audited)")][AllowedValues("json", "csv")] string? Format = null);

/// <summary>For tools and routes with no arguments.</summary>
public sealed record NoInput;
