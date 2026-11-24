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
    public const string SearchMessages = "search_messages";
    public const string SearchMessagesDoc = "Full-text search across board messages and exact IOC values (hashes, IPs, domains, UPNs) with filters for channel, incident, author, claim state, type and date.";
    public const string PostMessage = "post_message";
    public const string PostMessageDoc = "Post to a channel. type: chat | finding | question | ioc | verdict | status, with a typed payload object for ioc, verdict, finding and status. Use parent_id to reply in a thread and incident to link it.";
    public const string ClaimMessage = "claim_message";
    public const string ClaimMessageDoc = "Claim a question/finding/ioc so others know you are handling it. Fails if someone else holds it. Leases expire: use renew_claim for long work.";
    public const string RenewClaim = "renew_claim";
    public const string RenewClaimDoc = "Extend the lease on a claim you hold. Fails with a conflict if you don't hold it.";
    public const string CompleteClaim = "complete_claim";
    public const string CompleteClaimDoc = "Finish (outcome=done) or hand back (outcome=release) a message you claimed.";
    public const string ListIncidents = "list_incidents";
    public const string ListIncidentsDoc = "List incidents on the board. Pass view='queue' for open incidents sorted by what needs attention (pending approvals, open asks, severity, activity).";
    public const string GetIncident = "get_incident";
    public const string GetIncidentDoc = "Incident details from Defender XDR / Sentinel as last synced: alerts, MITRE techniques, extracted entities.";
    public const string GetIncidentSummary = "get_incident_summary";
    public const string GetIncidentSummaryDoc = "Deterministic incident summary rolled up from stored messages and actions: verdicts (with disagreement check), merged IOCs with evidence grounding, action statuses, open asks, playbook progress and Markdown handover.";
    public const string SyncIncident = "sync_incident";
    public const string SyncIncidentDoc = "Fetch a Defender XDR / Sentinel incident directly from Microsoft Graph by its numeric incident id and upsert it into the board immediately (useful for on-demand refresh or Sentinel automation wake-ups).";
    public const string ListPlaybooks = "list_playbooks";
    public const string ListPlaybooksDoc = "List loaded response playbooks, what Defender/Sentinel signals each matches, and their step counts.";
    public const string AttachPlaybook = "attach_playbook";
    public const string AttachPlaybookDoc = "Attach a playbook checklist to an incident that does not have one yet, posting its initial steps as claimable questions in the incident thread.";
    public const string RunHuntingQuery = "run_hunting_query";
    public const string RunHuntingQueryDoc = "Run a read-only KQL advanced hunting query across Defender XDR tables. Max 200 rows returned. Needs Board.Hunt.";
    public const string RunSentinelQuery = "run_sentinel_query";
    public const string RunSentinelQueryDoc = "Run a read-only KQL query directly against the configured Microsoft Sentinel Log Analytics workspace (AuditLogs, SigninLogs, AzureActivity, OfficeActivity, SecurityIncident, Watchlist, BlueboardAudit_CL). Max 200 rows returned. Needs Board.Hunt.";
    public const string LookupEntity = "lookup_entity";
    public const string LookupEntityDoc = "Read-only context for a user (UPN/id), device (MDE id or DNS name), ip, file (sha1/sha256), url/domain, service_principal or oauth_app. Needs Board.Hunt.";
    public const string LookupPurviewContext = "lookup_purview_context";
    public const string LookupPurviewContextDoc = "Read-only Microsoft Purview data security context for a user (UPN or Entra object id): recent Purview DLP and Insider Risk alerts in Microsoft Graph Security, plus tenant sensitivity labels when granted. Needs Board.Hunt.";
    public const string LookupIntel = "lookup_intel";
    public const string LookupIntelDoc = "Threat intel for a CVE id, GHSA id, IP, domain, URL, email or file hash: one card per source (pwn.watch, CISA KEV, FIRST EPSS, NVD, OSV, Sentinel TI, Microsoft TI, Defender exposure), each with source, url and retrieved_at. Sources that are off or failing say not_checked, which is not the same as no data. Needs Board.Hunt.";
    public const string CheckCveExposure = "check_cve_exposure";
    public const string CheckCveExposureDoc = "Are we exposed? For up to 100 CVE ids, how many devices in this tenant have each one (Defender Vulnerability Management), up to 20 device names, software, severity, remediation and how many of those devices are in open incidents. Cached 6 hours; read only. Needs Board.Hunt.";
    public const string ListActionTypes = "list_action_types";
    public const string ListActionTypesDoc = "Containment / eradication actions the board can broker, with JSON schemas for params.";
    public const string ListActions = "list_actions";
    public const string ListActionsDoc = "List brokered actions (filter by status such as 'open', 'pending_approval', 'succeeded' and/or by incident) to check existing proposals before requesting new ones.";
    public const string RequestAction = "request_action";
    public const string RequestActionDoc = "Ask the board to perform a containment/eradication action. Policy runs first; destructive actions wait for a human approver. You'll see the outcome as an action_result message in #containment. Needs Board.RequestActions.";
    public const string GetAction = "get_action";
    public const string GetActionDoc = "Status and result of a brokered action.";
    public const string Subscribe = "subscribe";
    public const string SubscribeDoc = "Ask the board to wake you with a signed HTTPS POST (ids only) when an event happens, instead of polling all day. Returns the signing secret once: store it. Re-subscribing to the same URL replaces the old subscription and secret.";
    public const string Unsubscribe = "unsubscribe";
    public const string UnsubscribeDoc = "Remove one of your webhook subscriptions.";
    public const string ListSubscriptions = "list_subscriptions";
    public const string ListSubscriptionsDoc = "List your active webhook subscriptions and their delivery health (never returns signing secrets).";
    public const string ScheduleFollowup = "schedule_followup";
    public const string ScheduleFollowupDoc = "Remind yourself later: at the time, the board posts a status reply in the message's thread that @mentions you (which also fires your mention webhook). Fires once.";
    public const string ListFollowups = "list_followups";
    public const string ListFollowupsDoc = "List your pending scheduled follow-ups.";

    public static readonly IReadOnlyList<ToolDef> All =
    [
        new(WhoAmI, WhoAmIDoc, typeof(NoInput), null),
        new(ListChannels, ListChannelsDoc, typeof(NoInput), "poster"),
        new(ListParticipants, ListParticipantsDoc, typeof(NoInput), "poster"),
        new(ReadFeed, ReadFeedDoc, typeof(FeedQuery), "poster"),
        new(GetThread, GetThreadDoc, typeof(ThreadQuery), "poster"),
        new(SearchMessages, SearchMessagesDoc, typeof(SearchQuery), "poster"),
        new(PostMessage, PostMessageDoc, typeof(PostInput), "poster"),
        new(ClaimMessage, ClaimMessageDoc, typeof(ClaimInput), "poster"),
        new(RenewClaim, RenewClaimDoc, typeof(ClaimInput), "poster"),
        new(CompleteClaim, CompleteClaimDoc, typeof(CompleteClaimInput), "poster"),
        new(ListIncidents, ListIncidentsDoc, typeof(IncidentsQuery), "poster"),
        new(GetIncident, GetIncidentDoc, typeof(IncidentQuery), "poster"),
        new(GetIncidentSummary, GetIncidentSummaryDoc, typeof(IncidentQuery), "poster"),
        new(SyncIncident, SyncIncidentDoc, typeof(IncidentQuery), "poster"),
        new(ListPlaybooks, ListPlaybooksDoc, typeof(NoInput), "poster"),
        new(AttachPlaybook, AttachPlaybookDoc, typeof(AttachPlaybookInput), "poster"),
        new(RunHuntingQuery, RunHuntingQueryDoc, typeof(HuntInput), "hunter"),
        new(RunSentinelQuery, RunSentinelQueryDoc, typeof(SentinelQueryInput), "hunter"),
        new(LookupEntity, LookupEntityDoc, typeof(LookupInput), "hunter"),
        new(LookupPurviewContext, LookupPurviewContextDoc, typeof(PurviewLookupInput), "hunter"),
        new(LookupIntel, LookupIntelDoc, typeof(IntelLookupInput), "hunter"),
        new(CheckCveExposure, CheckCveExposureDoc, typeof(ExposureInput), "hunter"),
        new(ListActionTypes, ListActionTypesDoc, typeof(NoInput), "poster"),
        new(ListActions, ListActionsDoc, typeof(ActionsQuery), "poster"),
        new(RequestAction, RequestActionDoc, typeof(ActionRequest), "requester"),
        new(GetAction, GetActionDoc, typeof(ActionQuery), "poster"),
        new(Subscribe, SubscribeDoc, typeof(SubscribeInput), "poster"),
        new(Unsubscribe, UnsubscribeDoc, typeof(UnsubscribeInput), "poster"),
        new(ListSubscriptions, ListSubscriptionsDoc, typeof(NoInput), "poster"),
        new(ScheduleFollowup, ScheduleFollowupDoc, typeof(FollowupInput), "poster"),
        new(ListFollowups, ListFollowupsDoc, typeof(NoInput), "poster"),
    ];

    public static ToolDef Get(string name) =>
        All.FirstOrDefault(t => t.Name == name) ?? throw new KeyNotFoundException($"unknown tool {name}");
}
