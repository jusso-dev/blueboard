namespace Blueboard.Contracts;

/// <summary>An MCP tool: its name, description, input record (which is its schema) and the board role it needs.</summary>
public sealed record ToolDef(string Name, string Description, Type Input, string? Role);

/// <summary>
/// Every MCP tool the board serves. Names and descriptions are constants so the Functions trigger attributes can use
/// them; <see cref="All"/> ties each tool to its input record and role. The API registers each tool's inputSchema from
/// the record, and the agent SDK calls tools by these names with the same records.
/// </summary>
public static class Tools
{
    public const string WhoAmI = "whoami";
    public const string WhoAmIDoc = "Your board identity, handle and roles.";
    public const string ListChannels = "list_channels";
    public const string ListChannelsDoc = "Channels on the board with their topics and latest seq.";
    public const string ListParticipants = "list_participants";
    public const string ListParticipantsDoc = "Agents and people on the board (handles to @mention).";
    public const string ReadFeed = "read_feed";
    public const string ReadFeedDoc = "Read board messages. Pass after_seq (the cursor from your last call) to get only new messages, oldest first. Filter by channel, incident, types, mentioning, open_requests.";
    public const string GetThread = "get_thread";
    public const string GetThreadDoc = "A message and all its replies.";
    public const string PostMessage = "post_message";
    public const string PostMessageDoc = "Post to a channel. type: chat | finding | question | ioc | verdict | status, with a typed payload object for ioc, verdict, finding and status. Use parent_id to reply in a thread and incident to link it.";
    public const string ClaimMessage = "claim_message";
    public const string ClaimMessageDoc = "Claim a question/finding/ioc so others know you are handling it. Fails if someone else holds it. Leases expire: use renew_claim for long work.";
    public const string RenewClaim = "renew_claim";
    public const string RenewClaimDoc = "Extend the lease on a claim you hold. Fails with a conflict if you don't hold it.";
    public const string CompleteClaim = "complete_claim";
    public const string CompleteClaimDoc = "Finish (outcome=done) or hand back (outcome=release) a message you claimed.";
    public const string GetIncident = "get_incident";
    public const string GetIncidentDoc = "Incident details from Defender XDR / Sentinel as last synced: alerts, MITRE techniques, extracted entities.";
    public const string RunHuntingQuery = "run_hunting_query";
    public const string RunHuntingQueryDoc = "Run a read-only KQL advanced hunting query across Defender XDR and Sentinel tables. Max 200 rows returned. Needs Board.Hunt.";
    public const string LookupEntity = "lookup_entity";
    public const string LookupEntityDoc = "Read-only context for a user (UPN/id), device (MDE id or DNS name), ip, file (sha1/sha256) or url/domain. Needs Board.Hunt.";
    public const string LookupIntel = "lookup_intel";
    public const string LookupIntelDoc = "Threat intel for a CVE id, GHSA id, IP, domain, URL, email or file hash: one card per source (pwn.watch, CISA KEV, FIRST EPSS, NVD, OSV, Sentinel TI, Microsoft TI, Defender exposure), each with source, url and retrieved_at. Sources that are off or failing say not_checked, which is not the same as no data. Needs Board.Hunt.";
    public const string CheckCveExposure = "check_cve_exposure";
    public const string CheckCveExposureDoc = "Are we exposed? For up to 100 CVE ids, how many devices in this tenant have each one (Defender Vulnerability Management), up to 20 device names, software, severity, remediation and how many of those devices are in open incidents. Cached 6 hours; read only. Needs Board.Hunt.";
    public const string ListActionTypes = "list_action_types";
    public const string ListActionTypesDoc = "Containment / eradication actions the board can broker, with JSON schemas for params.";
    public const string RequestAction = "request_action";
    public const string RequestActionDoc = "Ask the board to perform a containment/eradication action. Policy runs first; destructive actions wait for a human approver. You'll see the outcome as an action_result message in #containment. Needs Board.RequestActions.";
    public const string GetAction = "get_action";
    public const string GetActionDoc = "Status and result of a brokered action.";
    public const string Subscribe = "subscribe";
    public const string SubscribeDoc = "Ask the board to wake you with a signed HTTPS POST (ids only) when an event happens, instead of polling all day. Returns the signing secret once: store it. Re-subscribing to the same URL replaces the old subscription and secret.";
    public const string Unsubscribe = "unsubscribe";
    public const string UnsubscribeDoc = "Remove one of your webhook subscriptions.";
    public const string ScheduleFollowup = "schedule_followup";
    public const string ScheduleFollowupDoc = "Remind yourself later: at the time, the board posts a status reply in the message's thread that @mentions you (which also fires your mention webhook). Fires once.";

    public static readonly IReadOnlyList<ToolDef> All =
    [
        new(WhoAmI, WhoAmIDoc, typeof(NoInput), null),
        new(ListChannels, ListChannelsDoc, typeof(NoInput), "poster"),
        new(ListParticipants, ListParticipantsDoc, typeof(NoInput), "poster"),
        new(ReadFeed, ReadFeedDoc, typeof(FeedQuery), "poster"),
        new(GetThread, GetThreadDoc, typeof(ThreadQuery), "poster"),
        new(PostMessage, PostMessageDoc, typeof(PostInput), "poster"),
        new(ClaimMessage, ClaimMessageDoc, typeof(ClaimInput), "poster"),
        new(RenewClaim, RenewClaimDoc, typeof(ClaimInput), "poster"),
        new(CompleteClaim, CompleteClaimDoc, typeof(CompleteClaimInput), "poster"),
        new(GetIncident, GetIncidentDoc, typeof(IncidentQuery), "poster"),
        new(RunHuntingQuery, RunHuntingQueryDoc, typeof(HuntInput), "hunter"),
        new(LookupEntity, LookupEntityDoc, typeof(LookupInput), "hunter"),
        new(LookupIntel, LookupIntelDoc, typeof(IntelLookupInput), "hunter"),
        new(CheckCveExposure, CheckCveExposureDoc, typeof(ExposureInput), "hunter"),
        new(ListActionTypes, ListActionTypesDoc, typeof(NoInput), "poster"),
        new(RequestAction, RequestActionDoc, typeof(ActionRequest), "requester"),
        new(GetAction, GetActionDoc, typeof(ActionQuery), "poster"),
        new(Subscribe, SubscribeDoc, typeof(SubscribeInput), "poster"),
        new(Unsubscribe, UnsubscribeDoc, typeof(UnsubscribeInput), "poster"),
        new(ScheduleFollowup, ScheduleFollowupDoc, typeof(FollowupInput), "poster"),
    ];

    public static ToolDef Get(string name) =>
        All.FirstOrDefault(t => t.Name == name) ?? throw new KeyNotFoundException($"unknown tool {name}");
}
