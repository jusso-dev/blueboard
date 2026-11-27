using Blueboard.Contracts;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blueboard.Api.Ops;

/// <summary>What an approver needs to know. Every field except Title and Event is untrusted and escaped per sink.</summary>
public sealed record Notice(
    string Event, Guid? ActionId, string Title, string Target, string RequestedBy,
    string? IncidentGraphId, string? IncidentTitle, string? IncidentSeverity, int PolicyNotes, string? Url, string Status,
    IReadOnlyList<NotificationRecipient>? Recipients = null, bool Test = false);

/// <summary>The action an action_result notice reports on.</summary>
public sealed record NoticeAction(Guid Id, string Title, string Status);

/// <summary>
/// A board message someone should hear about: an agent asked, mentioned, replied or found something, a new incident,
/// or an action's result. Summary is a one-line, Markdown-stripped excerpt of untrusted text (or null when the
/// settings leave it out); every string except Event is escaped per sink.
/// </summary>
public sealed record MessageNotice(
    string Event, Guid MessageId, string Channel, Author Author, string Type, string? Summary,
    string? IncidentGraphId, string? IncidentTitle, string? IncidentSeverity,
    string? Classification, double? Confidence, NoticeAction? Action,
    IReadOnlyList<NotificationRecipient> Recipients, string? Url, bool Test = false);

/// <summary>
/// Tells people outside the board when something needs them, through Teams, email, a signed webhook and ntfy. Runs from a
/// timer. Approver notices (an action waits, a reminder, expired, interrupted, failed) and message notices (an agent
/// mentions or asks someone, replies in their thread, posts a verdict or finding; a new incident; an action's result)
/// are each claimed by inserting a row in `notifications` before sending, so each goes out once across every instance.
/// Which events go out and for whom comes from the notification settings (board defaults and each person's own);
/// where they go (URLs, mailboxes, tokens, secrets) stays in app settings. Justification text never leaves the board; message
/// notices carry at most a one-line summary, and only when include_summary allows. A failing sink is logged and
/// audited, never blocking.
/// </summary>
public sealed partial class Notifier(HttpClient http, Db db, Audit audit, MsClient ms, Settings settings, ILogger<Notifier>? log = null)
{
    private readonly ILogger _log = log ?? NullLogger<Notifier>.Instance;
    private const int MaxReminders = 8;
    private const int Batch = 50;
    public const string MessageCursorKey = "notify.message_cursor";

    [GeneratedRegex(@"^[^@\s/\\?#]+@[^@\s/\\?#]+\.[^@\s/\\?#]+$")] private static partial Regex Email();

    // ── configuration ────────────────────────────────────────────────────────────────────────────
    public sealed record SinkState(string Sink, bool Configured, string? Problem);

    /// <summary>Each sink: is it set up, and if so, what (if anything) stops it from sending. Never includes URLs or secrets.</summary>
    public IReadOnlyList<SinkState> Sinks()
    {
        var list = new List<SinkState>();
        if (settings.NotifyTeamsWebhookUrl is { } teams) list.Add(new("teams", true, UrlProblem(teams, "NOTIFY_TEAMS_WEBHOOK_URL")));
        if (settings.NotifyWebhookUrl is { } hook)
            list.Add(new("webhook", true, UrlProblem(hook, "NOTIFY_WEBHOOK_URL")
                ?? (settings.NotifyWebhookSecret is { Length: >= 32 } ? null : "NOTIFY_WEBHOOK_SECRET must be set (at least 32 characters) to sign webhook payloads")));
        if (settings.NotifyMailFrom is not null || settings.NotifyMailTo.Length > 0)
            list.Add(new("mail", true,
                settings.NotifyMailFrom is not { } from || !Email().IsMatch(from) ? "NOTIFY_MAIL_FROM must be a mailbox address"
                : settings.NotifyMailTo.Length == 0 || settings.NotifyMailTo.Any(t => !Email().IsMatch(t)) ? "NOTIFY_MAIL_TO must list approver addresses"
                : null));
        if (settings.NotifyNtfyUrl is { } ntfy)
            list.Add(new("ntfy", true, NtfyProblem(ntfy)
                ?? (settings.NotifyNtfyToken is not { } t || NtfyToken().IsMatch(t) ? null :"NOTIFY_NTFY_TOKEN must be an ntfy access token (tk_…)")));
        return list;
    }

    [GeneratedRegex(@"^tk_[A-Za-z0-9_]{5,125}$")] private static partial Regex NtfyToken();
    [GeneratedRegex(@"^[-_A-Za-z0-9]{1,64}$")] private static partial Regex NtfyTopic();

    private IEnumerable<string> ReadySinks() => Sinks().Where(s => s.Problem is null).Select(s => s.Sink);

    /// <summary>Outbound guard: https only, default port, no credentials in the URL, no IP literals, and an exact host from NOTIFY_ALLOWED_HOSTS.</summary>
    internal string? UrlProblem(string url, string name) => UrlProblem(url, name, localHttp: false);

    /// <summary>
    /// The same guard; with <paramref name="localHttp"/>, plain http and a custom port are allowed for a single-label
    /// host (no dot, such as a Docker service name) that is in NOTIFY_ALLOWED_HOSTS. Any dotted host still needs
    /// https on the default port.
    /// </summary>
    private string? UrlProblem(string url, string name, bool localHttp)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp))
            return $"{name} must be an https URL";
        var host = u.IdnHost.Trim('[', ']').TrimEnd('.');
        var ip = IPAddress.TryParse(host, out _);
        var local = localHttp && !ip && IsSingleLabel(host);
        if (u.Scheme != Uri.UriSchemeHttps && !local)
            return localHttp ? $"{name} must be an https URL (plain http only for a single-label host such as a Docker service name)" : $"{name} must be an https URL";
        if (u.UserInfo.Length > 0 || (!u.IsDefaultPort && !local)) return $"{name} must not carry credentials or a custom port";
        if (ip) return $"{name} must use a host name, not an IP address";
        if (!settings.NotifyAllowedHosts.Contains(host, StringComparer.OrdinalIgnoreCase)) return $"{host} is not in NOTIFY_ALLOWED_HOSTS";
        return null;
    }

    private static bool IsSingleLabel(string host) => host.Length > 0 && !host.Contains('.') && !host.Contains(':');

    /// <summary>
    /// NOTIFY_NTFY_URL: the URL guard with the single-label http exception, and exactly one path segment, the topic
    /// (ntfy's rule: letters, digits, - and _, at most 64). No query or fragment.
    /// </summary>
    internal string? NtfyProblem(string url)
    {
        if (UrlProblem(url, "NOTIFY_NTFY_URL", localHttp: true) is { } problem) return problem;
        var u = new Uri(url);
        if (u.Query.Length > 0 || u.Fragment.Length > 0) return "NOTIFY_NTFY_URL must not carry a query or fragment";
        if (!NtfyTopic().IsMatch(u.AbsolutePath.Trim('/'))) return "NOTIFY_NTFY_URL must be the server URL plus one topic (letters, digits, - and _, at most 64), for example https://ntfy.example.com/blueboard";
        return null;
    }

    /// <summary>
    /// The host a private (Docker network) address is accepted for: the ntfy URL's host, when it is a single-label
    /// name in NOTIFY_ALLOWED_HOSTS. Every other notification host must resolve to public addresses only.
    /// </summary>
    public static bool MayBePrivate(Settings settings, string host) =>
        settings.NotifyNtfyUrl is { } url && Uri.TryCreate(url, UriKind.Absolute, out var u)
        && IsSingleLabel(u.IdnHost) && !IPAddress.TryParse(u.IdnHost.Trim('[', ']'), out _)
        && string.Equals(u.IdnHost, host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)
        && settings.NotifyAllowedHosts.Contains(u.IdnHost, StringComparer.OrdinalIgnoreCase);

    // ── the sweep (timer) ────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// Finds events that still need a notice and sends each once per ready sink: held notices whose quiet hours are
    /// over, approver notices, then new board messages. Returns notices sent.
    /// </summary>
    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        var sinks = ReadySinks().ToArray();
        if (sinks.Length == 0) return 0;
        var defaults = await DefaultsAsync(ct);
        var people = await PeopleAsync(defaults, ct);
        var now = DateTimeOffset.UtcNow;
        var sent = await HeldAsync(sinks, defaults, people, ct);
        sent += await ApprovalsAsync(sinks, defaults, people, now, ct);
        sent += await MessagesAsync(sinks, defaults, people, now, ct);
        return sent;
    }

    private async Task<int> ApprovalsAsync(string[] sinks, NotificationSettings defaults, IReadOnlyList<Person> people, DateTimeOffset now, CancellationToken ct)
    {
        var due = new List<(Guid Id, string Event)>();
        await using (var cmd = db.Command("""
            with events as (
              select id, 'requested' as event from actions
               where status in ('pending_approval', 'approved_once') and created_at > now() - interval '1 day'
              union all
              select id, 'second_approval' as event from actions
               where status = 'approved_once' and updated_at > now() - interval '1 day'
              union all
              select id, 'reminder:' || floor(extract(epoch from now() - created_at) / 60 / @m)::int from actions
               where status in ('pending_approval', 'approved_once') and created_at > now() - interval '1 day'
                 and now() - created_at >= make_interval(mins => @m)
                 and floor(extract(epoch from now() - created_at) / 60 / @m) <= @max
              union all
              select id, case when error like 'interrupted%' then 'interrupted' else 'failed' end from actions
               where status = 'failed' and updated_at > now() - interval '1 day'
              union all
              select id, 'expired' from actions
               where status = 'expired' and updated_at > now() - interval '1 day'
            )
            select e.id, e.event from events e
            where (select count(*) from notifications n where n.action_id = e.id and n.event = e.event) < @sinks
            limit 50
            """).With("m", settings.NotifyRemindMinutes).With("max", MaxReminders).With("sinks", sinks.Length))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) due.Add((r.GetGuid(0), r.GetString(1)));

        var sent = 0;
        foreach (var (id, evt) in due)
        {
            var notice = await BuildAsync(id, evt, ct);
            if (notice is null) continue;
            foreach (var sink in sinks)
            {
                // Settings say who wants it on this sink; a sink nobody wants is claimed as skipped so it isn't re-checked.
                var (send, to, hold) = NotificationRules.Approvals(people, defaults, sink, notice.IncidentSeverity, now);
                if (await ClaimActionAsync(id, evt, sink, !send ? "skipped" : hold is null ? "sending" : "held", hold, ct) is not { } row || !send || hold is not null) continue;
                if (await DeliverAsync(row, sink, Render(notice with { Recipients = to.Select(p => p.Recipient).ToList() }), notice.Event, id.ToString(), ct)) sent++;
            }
        }
        return sent;
    }

    private async Task<long?> ClaimActionAsync(Guid actionId, string evt, string sink, string status, DateTimeOffset? holdUntil, CancellationToken ct)
    {
        await using var cmd = db.Command("insert into notifications (action_id, event, sink, status, send_after) values (@a, @e, @s, @st, @after) on conflict do nothing returning id")
            .With("a", actionId).With("e", evt).With("s", sink).With("st", status).With("after", holdUntil);
        return await cmd.ExecuteScalarAsync(ct) as long?;
    }

    private async Task<long?> ClaimMessageAsync(Guid messageId, string evt, string sink, string? recipient, DateTimeOffset? holdUntil, CancellationToken ct)
    {
        await using var cmd = db.Command("""
            insert into notifications (message_id, event, sink, recipient, status, send_after) values (@m, @e, @s, @r, @st, @after)
            on conflict do nothing returning id
            """).With("m", messageId).With("e", evt).With("s", sink).With("r", recipient)
                .With("st", holdUntil is null ? "sending" : "held").With("after", holdUntil);
        return await cmd.ExecuteScalarAsync(ct) as long?;
    }

    private async Task<Notice?> BuildAsync(Guid id, string evt, CancellationToken ct)
    {
        await using var cmd = db.Command("""
            select a.kind, a.params::text, a.status, a.policy_notes, p.handle, i.graph_id, i.display_name, i.severity
            from actions a join principals p on p.id = a.requested_by left join incidents i on i.id = a.incident_id
            where a.id = @id
            """).With("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return null;
        var def = Catalog.All.GetValueOrDefault(r.GetString(0));
        string target;
        try { target = def is null ? r.GetString(0) : def.Describe(def.Validate(JsonDocument.Parse(r.GetString(1)).RootElement)); }
        catch (BoardException) { target = "(parameters no longer valid)"; }
        var name = evt.StartsWith("reminder:", StringComparison.Ordinal) ? "action.reminder" : evt switch
        {
            "requested" => "action.pending_approval",
            "second_approval" => "action.second_approval_needed",
            "expired" => "action.expired",
            "interrupted" => "action.interrupted",
            _ => "action.failed",
        };
        return new Notice(name, id, def?.Title ?? r.GetString(0), target, r.GetString(4), r.Get<string>("graph_id"), r.Get<string>("display_name"),
            r.Get<string>("severity"), r.GetFieldValue<string[]>(3).Length, DeepLink(id), r.GetString(2));
    }

    // ── message events ───────────────────────────────────────────────────────────────────────────
    /// <summary>One board message with what the rules and the notice need. Body is untrusted and only ever summarised.</summary>
    internal sealed record MessageRow(
        MessageFacts Facts, long Seq, string Channel, string AuthorName, string Body, string? IncidentGraphId, string? IncidentTitle,
        double? Confidence, Guid? ActionId, string? ActionKind, string? ActionStatus);

    private const string MessageRowSql = """
        select m.id, m.seq, m.type, a.handle, a.kind, a.display_name, m.mentions, m.parent_id, c.name as channel, m.body,
               i.graph_id, i.display_name as incident_title, i.severity,
               case when m.type = 'verdict' then m.payload->>'classification' end as classification,
               case when m.type = 'verdict' and jsonb_typeof(m.payload->'confidence') = 'number' then (m.payload->>'confidence')::float8 end as confidence,
               act.id as action_id, ac.kind as action_kind, m.payload->>'status' as action_status,
               array(select distinct p.handle from messages x join principals p on p.id = x.author_id
                     where m.parent_id is not null and (x.id = m.parent_id or x.parent_id = m.parent_id) and x.seq < m.seq and p.kind = 'human') as thread_humans,
               array(select rp.handle from principals rp where rp.id = ac.requested_by and rp.kind = 'human'
                     union
                     select ip.handle from messages im join principals ip on ip.id = im.author_id where im.id = ac.on_behalf_of and ip.kind = 'human') as action_humans
        from messages m
        join principals a on a.id = m.author_id
        join channels c on c.id = m.channel_id
        left join incidents i on i.id = m.incident_id
        -- Only the board's own action_result carries a trusted action id; never cast an agent's payload text.
        left join lateral (select case when m.type = 'action_result' and a.kind = 'system'
                                        and (m.payload->>'action_id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                                       then (m.payload->>'action_id')::uuid end as id) act on true
        left join actions ac on ac.id = act.id
        """;

    private async Task<List<MessageRow>> MessageRowsAsync(string where, Action<Npgsql.NpgsqlCommand> bind, CancellationToken ct)
    {
        var rows = new List<MessageRow>();
        await using var cmd = db.Command($"{MessageRowSql} {where}");
        bind(cmd);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            var facts = new MessageFacts(r.GetGuid(0), r.GetString(2), r.GetString(3), r.GetString(4), r.GetFieldValue<string[]>(6),
                r.Get<Guid?>("parent_id"), r.Get<string>("severity"), r.Get<string>("classification"),
                r.GetFieldValue<string[]>(r.GetOrdinal("thread_humans")), r.GetFieldValue<string[]>(r.GetOrdinal("action_humans")));
            rows.Add(new MessageRow(facts, r.GetInt64(1), r.GetString(r.GetOrdinal("channel")), r.GetString(5), r.GetString(r.GetOrdinal("body")),
                r.Get<string>("graph_id"), r.Get<string>("incident_title"), r.Get<double?>("confidence"), r.Get<Guid?>("action_id"),
                r.Get<string>("action_kind"), r.Get<string>("action_status")));
        }
        return rows;
    }

    /// <summary>
    /// New messages since the cursor (kv_state notify.message_cursor, by seq), at most an hour old and 50 a sweep. The
    /// first run starts at the newest message, so turning notifications on never replays history.
    /// </summary>
    private async Task<int> MessagesAsync(string[] sinks, NotificationSettings defaults, IReadOnlyList<Person> people, DateTimeOffset now, CancellationToken ct)
    {
        var kv = new KvState(db);
        long cursor;
        await using (var c = db.Command("""
            select (select (value #>> '{}')::bigint from kv_state where key = @k),
                   (select coalesce(max(seq), 0) from messages),
                   (select seq from messages where created_at < now() - interval '1 hour' order by seq desc limit 1)
            """).With("k", MessageCursorKey))
        await using (var r = await c.ExecuteReaderAsync(ct))
        {
            await r.ReadAsync(ct);
            if (r.IsDBNull(0))
            {
                var start = r.GetInt64(1);
                await r.DisposeAsync();
                await kv.SetAsync(MessageCursorKey, start, ct);
                return 0;
            }
            cursor = Math.Max(r.GetInt64(0), r.IsDBNull(2) ? 0 : r.GetInt64(2));
        }

        var rows = await MessageRowsAsync("where m.seq > @c order by m.seq limit @n", cmd => cmd.With("c", cursor).With("n", Batch), ct);
        var sent = 0;
        var done = cursor;
        try
        {
            foreach (var row in rows)
            {
                var plan = NotificationRules.Route(NotificationRules.Events(row.Facts, people), sinks, defaults, row.Facts.IncidentSeverity, now);
                foreach (var p in plan)
                {
                    if (await ClaimMessageAsync(row.Facts.Id, p.Event, p.Sink, p.Recipient, p.HoldUntil, ct) is not { } id || p.HoldUntil is not null) continue;
                    if (await DeliverAsync(id, p.Sink, Render(ToNotice(row, p.Event, p.To, p.IncludeSummary)), p.Event, row.Facts.Id.ToString(), ct)) sent++;
                }
                done = row.Seq;
            }
        }
        finally
        {
            if (done > cursor) await kv.SetAsync(MessageCursorKey, done, CancellationToken.None);
        }
        return sent;
    }

    /// <summary>
    /// Notices held for quiet hours whose window has ended. Each is claimed (held → sending) by one instance, then
    /// re-checked: a person who has since turned that event or sink off, or been disabled, isn't sent it. For an
    /// approval, only the newest held notice per action and sink goes out, and a request that has been decided in the
    /// meantime is dropped, so the end of quiet hours isn't a burst of stale reminders.
    /// </summary>
    private async Task<int> HeldAsync(string[] sinks, NotificationSettings defaults, IReadOnlyList<Person> people, CancellationToken ct)
    {
        var due = new List<(long Id, Guid? MessageId, Guid? ActionId, string Event, string Sink, string? Recipient)>();
        await using (var cmd = db.Command("""
            update notifications set status = 'sending'
            where id in (select id from notifications where status = 'held' and send_after <= now() order by send_after, id limit @n for update skip locked)
            returning id, message_id, action_id, event, sink, recipient
            """).With("n", Batch))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) due.Add((r.GetInt64(0), r.Get<Guid?>("message_id"), r.Get<Guid?>("action_id"), r.GetString(3), r.GetString(4), r.Get<string>("recipient")));
        if (due.Count == 0) return 0;

        var rows = (await MessageRowsAsync("where m.id = any(@ids)", cmd => cmd.With("ids", due.Where(d => d.MessageId is not null).Select(d => d.MessageId!.Value).Distinct().ToArray()), ct))
            .ToDictionary(r => r.Facts.Id);
        var byHandle = people.ToDictionary(p => p.Handle);
        var newest = due.Where(d => d.ActionId is not null).GroupBy(d => (d.ActionId, d.Sink)).Select(g => g.Max(d => d.Id)).ToHashSet();
        var sent = 0;
        foreach (var d in due)
        {
            Rendered? notice = null;
            if (d.ActionId is { } actionId && newest.Contains(d.Id) && sinks.Contains(d.Sink) && await BuildAsync(actionId, d.Event, ct) is { } n
                && !(n.Event is "action.pending_approval" or "action.second_approval_needed" or "action.reminder" && n.Status is not ("pending_approval" or "approved_once")))
            {
                var to = people.Where(p => p.IsApprover && p.Settings is { Enabled: true, Events.Approvals: true } && NotificationRules.SinkOn(p.Settings, d.Sink)).ToList();
                if (to.Count > 0) notice = Render(n with { Recipients = to.Select(p => p.Recipient).ToList() });
            }
            else if (d.MessageId is { } messageId && rows.TryGetValue(messageId, out var row) && d.Recipient is not null && byHandle.TryGetValue(d.Recipient, out var p)
                     && p.Settings.Enabled && NotificationRules.EventOn(p.Settings, d.Event) && NotificationRules.SinkOn(p.Settings, d.Sink) && sinks.Contains(d.Sink))
                notice = Render(ToNotice(row, d.Event, [p], defaults.IncludeSummary && p.Settings.IncludeSummary));

            if (notice is null)
            {
                await using var skip = db.Command("update notifications set status = 'skipped' where id = @id").With("id", d.Id);
                await skip.ExecuteNonQueryAsync(ct);
                continue;
            }
            if (await DeliverAsync(d.Id, d.Sink, notice, d.Event, (d.ActionId ?? d.MessageId)!.Value.ToString(), ct)) sent++;
        }
        return sent;
    }

    private MessageNotice ToNotice(MessageRow row, string evt, IReadOnlyList<Person> to, bool includeSummary)
    {
        NoticeAction? action = row.ActionId is { } aid
            ? new(aid, Catalog.All.GetValueOrDefault(row.ActionKind ?? "")?.Title ?? row.ActionKind ?? "Action", row.ActionStatus == "succeeded" ? "succeeded" : "failed")
            : null;
        return new MessageNotice(evt, row.Facts.Id, row.Channel, new Author(row.Facts.AuthorHandle, row.AuthorName, row.Facts.AuthorKind), row.Facts.Type,
            includeSummary ? NotificationRules.Summary(row.Body) : null, row.IncidentGraphId, row.IncidentTitle, row.Facts.IncidentSeverity,
            row.Facts.Classification, row.Confidence, action, to.Select(p => p.Recipient).ToList(), MessageLink(row.Channel, row.Facts.ParentId ?? row.Facts.Id));
    }

    /// <summary>The Approvals page scrolled to this action. Only an https base (or http on localhost) from settings.</summary>
    internal string? DeepLink(Guid id) => Base() is { } b ? $"{b}/approvals#{id}" : null;

    /// <summary>The message's permalink as the web app builds it: /channels/&lt;name&gt;#m-&lt;thread root id&gt;.</summary>
    internal string? MessageLink(string channel, Guid rootId) => Base() is { } b ? $"{b}/channels/{Uri.EscapeDataString(channel)}#m-{rootId}" : null;

    private string? Base() =>
        settings.WebBaseUrl is { } b && Uri.TryCreate(b, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.IsLoopback)
            ? u.GetLeftPart(UriPartial.Authority)
            : null;

    private async Task<bool> DeliverAsync(long row, string sink, Rendered n, string evt, string subject, CancellationToken ct)
    {
        try
        {
            await SendAsync(sink, n, ct);
            await using var up = db.Command("update notifications set status = 'sent', sent_at = now(), attempts = attempts + 1 where id = @id").With("id", row);
            await up.ExecuteNonQueryAsync(ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            var error = SafeError(ex);
            _log.LogWarning("notification to {Sink} failed: {Error}", sink, error);
            await using (var up = db.Command("update notifications set status = 'failed', error = @err, attempts = attempts + 1 where id = @id")
                             .With("err", error).With("id", row))
                await up.ExecuteNonQueryAsync(CancellationToken.None);
            await audit.WriteAsync(null, "notify.failed", subject, new { sink, @event = evt, error }, CancellationToken.None);
            return false;
        }
    }

    /// <summary>Error text without URLs (a webhook URL is itself a secret).</summary>
    internal static string SafeError(Exception ex) => ex switch
    {
        HttpRequestException { StatusCode: { } s } => $"HTTP {(int)s}",
        HttpRequestException => "connection failed",
        TaskCanceledException => "timed out",
        BoardException b => UrlLike().Replace(b.Message, "<url>"),
        _ => ex.GetType().Name,
    };

    [GeneratedRegex(@"https?://\S+")] private static partial Regex UrlLike();

    // ── sinks ────────────────────────────────────────────────────────────────────────────────────
    /// <summary>One notice in each sink's format.</summary>
    internal sealed record Rendered(object Card, object Payload, string Subject, string Html, NtfyNotice Ntfy);

    internal static Rendered Render(Notice n) => new(TeamsCard(n), WebhookPayload(n), Subject(n), MailHtml(n), Ntfy(n));
    internal static Rendered Render(MessageNotice n) => new(TeamsCard(n), WebhookPayload(n), Subject(n), MailHtml(n), Ntfy(n));

    private async Task SendAsync(string sink, Rendered n, CancellationToken ct)
    {
        switch (sink)
        {
            case "teams":
                await PostAsync(settings.NotifyTeamsWebhookUrl!, Json.Serialize(n.Card), null, ct);
                break;
            case "webhook":
                var body = Json.Serialize(n.Payload);
                await PostAsync(settings.NotifyWebhookUrl!, body, Sign(body, settings.NotifyWebhookSecret!), ct);
                break;
            case "mail":
                await ms.SendAsync(MsApi.Graph, $"/v1.0/users/{Uri.EscapeDataString(settings.NotifyMailFrom!)}/sendMail", HttpMethod.Post, new
                {
                    message = new
                    {
                        subject = n.Subject,
                        body = new { contentType = "HTML", content = n.Html },
                        toRecipients = settings.NotifyMailTo.Select(t => new { emailAddress = new { address = t } }),
                    },
                    saveToSentItems = false,
                }, ct);
                break;
            case "ntfy":
                // JSON publishing goes to the server root, with the topic in the body (docs.ntfy.sh/publish/#publish-as-json).
                if (NtfyProblem(settings.NotifyNtfyUrl!) is { } problem) throw new BoardException(problem);
                var url = new Uri(settings.NotifyNtfyUrl!);
                await SendRawAsync(new Uri(url.GetLeftPart(UriPartial.Authority) + "/"), NtfyJson(n.Ntfy, url.AbsolutePath.Trim('/')), null, settings.NotifyNtfyToken, ct);
                break;
        }
    }

    private async Task PostAsync(string url, string body, string? signature, CancellationToken ct)
    {
        if (UrlProblem(url, "notification URL") is { } problem) throw new BoardException(problem);
        await SendRawAsync(new Uri(url), body, signature, null, ct);
    }

    /// <summary>One POST, already checked by the caller's guard. Never logs the URL or the token.</summary>
    private async Task SendRawAsync(Uri url, string body, string? signature, string? bearer, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        req.Headers.UserAgent.ParseAdd("blueboard-notifier/1");
        if (signature is not null) req.Headers.TryAddWithoutValidation("X-Blueboard-Signature", signature);
        if (bearer is not null) req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
        // Headers only: the response body is never read, so a hostile endpoint can't stream data back at us.
        using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if ((int)res.StatusCode is >= 300 and < 400) throw new HttpRequestException("redirects are not followed", null, res.StatusCode);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>X-Blueboard-Signature: sha256=&lt;hex HMAC-SHA256 of the raw UTF-8 body&gt;.</summary>
    public static string Sign(string body, string secret) =>
        "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body)));

    // ── formatting (all untrusted fields escaped) ────────────────────────────────────────────────
    internal static string Headline(Notice n) => (n.Test && n.Event != "test" ? "Test: " : "") + n.Event switch
    {
        "action.pending_approval" => "Approval needed",
        "action.second_approval_needed" => "Second approval needed (1 of 2 received)",
        "action.reminder" => "Still waiting for approval",
        "action.expired" => "Approval request expired",
        "action.interrupted" => "Action interrupted: outcome unknown, check Defender",
        "action.failed" => "Action failed: check Defender",
        _ when n.Event.StartsWith("agent.", StringComparison.Ordinal) => n.Title,
        _ => "Test notification",
    };

    internal static string Headline(MessageNotice n)
    {
        var who = "@" + n.Author.Handle;
        var incident = n.IncidentGraphId is null ? "" : $" on incident {n.IncidentGraphId}";
        var text = n.Event switch
        {
            "question" => $"{who} needs your input",
            "mention" => $"{who} mentioned you",
            "reply" => $"{who} replied in your thread",
            "verdict" => $"{NotificationRules.ClassificationLabel(n.Classification)} verdict{(incident.Length > 0 ? incident : $" from {who}")}",
            "finding" => $"Finding{(incident.Length > 0 ? incident : $" from {who}")}",
            "incident" => $"New {n.IncidentSeverity ?? "unknown"} severity incident {n.IncidentGraphId}",
            "action_result" => $"Action {(n.Action?.Status == "succeeded" ? "succeeded" : "failed")}: {n.Action?.Title ?? "action"}",
            _ => "Board activity",
        };
        return (n.Test ? "Test: " : "") + text;
    }

    internal static string Subject(Notice n) =>
        OneLine($"[blueboard] {Headline(n)}: {n.Title}{(n.IncidentGraphId is null ? "" : $", incident {n.IncidentGraphId}")}", 200);

    internal static string Subject(MessageNotice n) =>
        OneLine($"[blueboard] {Headline(n)}{(n.IncidentGraphId is null || n.Event is "verdict" or "finding" or "incident" ? "" : $", incident {n.IncidentGraphId}")}", 200);

    /// <summary>Plain one-line text: no control characters, BiDi overrides or line breaks, capped.</summary>
    internal static string OneLine(string? s, int max = 300)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(Math.Min(s.Length, max));
        foreach (var ch in s)
        {
            if (sb.Length >= max) break;
            if (ch is (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069') or '\u200E' or '\u200F' or '\u061C') continue;
            sb.Append(char.IsControl(ch) ? ' ' : ch);
        }
        return sb.ToString().Trim();
    }

    /// <summary>
    /// Backslash-escapes every CommonMark punctuation character Adaptive Card markdown reacts to (links, emphasis,
    /// headings, lists, braces), on one line, so untrusted text renders as literal text.
    /// </summary>
    internal static string CardText(string? s)
    {
        var sb = new StringBuilder();
        foreach (var ch in OneLine(s))
        {
            if (@"\`*_{}[]()<>#+-.!|~".Contains(ch)) sb.Append('\\');
            sb.Append(ch);
        }
        return sb.ToString();
    }

    private static string For(IReadOnlyList<NotificationRecipient>? to) => string.Join(", ", (to ?? []).Select(r => "@" + r.Handle));

    private static object Card(string headline, IEnumerable<(string Title, string Value)> facts, string footer, string? url)
    {
        var body = new List<object>
        {
            new { type = "TextBlock", text = CardText(headline), weight = "Bolder", size = "Medium", wrap = true },
            new { type = "FactSet", facts = facts.Select(f => new { title = f.Title, value = CardText(f.Value) }).ToList() },
            new { type = "TextBlock", text = footer, wrap = true, isSubtle = true },
        };
        var card = new Dictionary<string, object>
        {
            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
            ["type"] = "AdaptiveCard",
            ["version"] = "1.4",
            ["body"] = body,
        };
        if (url is not null) card["actions"] = new[] { new { type = "Action.OpenUrl", title = "Open in blueboard", url } };
        return new { type = "message", attachments = new[] { new { contentType = "application/vnd.microsoft.card.adaptive", contentUrl = (string?)null, content = card } } };
    }

    private static List<(string, string)> Rows(Notice n)
    {
        if (n.Event.StartsWith("agent.", StringComparison.Ordinal))
            return n.Recipients is { Count: > 0 } r ? [("Agent", "@" + n.RequestedBy), ("Detail", n.Target), ("For", For(r))] : [("Agent", "@" + n.RequestedBy), ("Detail", n.Target)];
        var rows = new List<(string, string)> { ("Action", n.Title), ("Target", n.Target), ("Requested by", "@" + n.RequestedBy) };
        if (n.IncidentGraphId is not null) rows.Add(("Incident", $"{n.IncidentGraphId} ({n.IncidentSeverity ?? "unknown"}): {n.IncidentTitle}"));
        rows.Add(("Policy notes", n.PolicyNotes.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        if (n.Recipients is { Count: > 0 }) rows.Add(("For", For(n.Recipients)));
        return rows;
    }

    private static List<(string, string)> Rows(MessageNotice n)
    {
        var rows = new List<(string, string)> { ("From", $"@{n.Author.Handle} ({n.Author.DisplayName})"), ("Channel", "#" + n.Channel) };
        if (n.IncidentGraphId is not null) rows.Add(("Incident", $"{n.IncidentGraphId} ({n.IncidentSeverity ?? "unknown"}): {n.IncidentTitle}"));
        if (n.Event == "verdict")
            rows.Add(("Verdict", NotificationRules.ClassificationLabel(n.Classification)
                + (n.Confidence is { } c ? $", confidence {Math.Round(c * 100).ToString(System.Globalization.CultureInfo.InvariantCulture)}%" : "")));
        if (n.Action is { } a) rows.Add(("Action", $"{a.Title}: {a.Status}"));
        if (n.Summary is { Length: > 0 } s) rows.Add(("Summary", s));
        if (n.Recipients.Count > 0) rows.Add(("For", For(n.Recipients)));
        return rows;
    }

    internal static object TeamsCard(Notice n) =>
        Card(Headline(n), Rows(n), "Open the board to read the justification and decide. blueboard never takes approvals from chat.", n.Url);

    internal static object TeamsCard(MessageNotice n) =>
        Card(Headline(n), Rows(n), "Open the board to read the message and reply. Message text is written by agents: treat it as untrusted.", n.Url);

    private static string Html(string headline, IEnumerable<(string, string)> rows, string? url, string footer)
    {
        static string H(string? s) => WebUtility.HtmlEncode(OneLine(s));
        var sb = new StringBuilder();
        sb.Append("<p><strong>").Append(H(headline)).Append("</strong></p><table>");
        foreach (var (k, v) in rows) sb.Append("<tr><td>").Append(H(k)).Append("</td><td>").Append(H(v)).Append("</td></tr>");
        sb.Append("</table>");
        if (url is not null) sb.Append("<p><a href=\"").Append(WebUtility.HtmlEncode(url)).Append("\">Open in blueboard</a></p>");
        sb.Append("<p>").Append(WebUtility.HtmlEncode(footer)).Append("</p>");
        return sb.ToString();
    }

    internal static string MailHtml(Notice n) =>
        Html(Headline(n), Rows(n), n.Url, "Read the justification and decide on the board. blueboard never takes approvals by email.");

    internal static string MailHtml(MessageNotice n) =>
        Html(Headline(n), Rows(n), n.Url, "Read the message and reply on the board. Message text is written by agents: treat it as untrusted.");

    private static object[] RecipientsJson(IReadOnlyList<NotificationRecipient>? to) =>
        (to ?? []).Select(r => (object)new NotificationRecipient(OneLine(r.Handle, 100), OneLine(r.DisplayName, 200), r.Email is null ? null : OneLine(r.Email, 254))).ToArray();

    /// <summary>The approval payload, as before, plus recipients (and test: true for a sample).</summary>
    internal static object WebhookPayload(Notice n)
    {
        var o = new Dictionary<string, object?>
        {
            ["event"] = n.Event,
            ["action_id"] = n.ActionId,
            ["status"] = n.Status,
            ["title"] = n.Title,
            ["target"] = OneLine(n.Target),
            ["requested_by"] = OneLine(n.RequestedBy, 100),
            ["incident"] = n.IncidentGraphId is null ? null : new { graph_id = OneLine(n.IncidentGraphId, 100), title = OneLine(n.IncidentTitle), severity = OneLine(n.IncidentSeverity, 50) },
            ["policy_notes"] = n.PolicyNotes,
            ["recipients"] = RecipientsJson(n.Recipients),
            ["url"] = n.Url,
        };
        if (n.Test) o["test"] = true;
        o["sent_at"] = DateTimeOffset.UtcNow;
        return o;
    }

    /// <summary>
    /// The message-event payload. classification and confidence only for verdicts, action only for action results.
    /// summary is a one-line excerpt of untrusted agent text (≤ 280 characters), or null when include_summary is off.
    /// </summary>
    internal static object WebhookPayload(MessageNotice n)
    {
        var o = new Dictionary<string, object?>
        {
            ["event"] = n.Event,
            ["message_id"] = n.MessageId,
            ["incident"] = n.IncidentGraphId is null ? null : new { graph_id = OneLine(n.IncidentGraphId, 100), title = OneLine(n.IncidentTitle), severity = OneLine(n.IncidentSeverity, 50) },
            ["channel"] = n.Channel,
            ["author"] = new { handle = OneLine(n.Author.Handle, 100), display_name = OneLine(n.Author.DisplayName, 200), kind = n.Author.Kind },
            ["type"] = n.Type,
            ["summary"] = n.Summary is null ? null : OneLine(n.Summary, 280),
        };
        if (n.Classification is not null) o["classification"] = n.Classification;
        if (n.Confidence is not null) o["confidence"] = n.Confidence;
        if (n.Action is { } a) o["action"] = new { id = a.Id, title = a.Title, status = a.Status };
        o["recipients"] = RecipientsJson(n.Recipients);
        o["url"] = n.Url;
        o["test"] = n.Test;
        o["sent_at"] = DateTimeOffset.UtcNow;
        return o;
    }

    // ── ntfy (phone push) ────────────────────────────────────────────────────────────────────────
    /// <summary>One ntfy notification before the topic is added. Title and message are plain text (markdown stays off).</summary>
    internal sealed record NtfyNotice(string Title, string Message, int Priority, string[] Tags, string? Click);

    internal const int NtfyTitleMax = 200;
    internal const int NtfyMessageMax = 600;

    internal static NtfyNotice Ntfy(Notice n)
    {
        var (priority, tags) = n.Event switch
        {
            "action.pending_approval" or "action.second_approval_needed" or "action.reminder" => (4, new[] { "lock" }),
            "action.failed" or "action.interrupted" => (5, new[] { "x" }),
            "action.expired" => (3, new[] { "lock" }),
            _ => (3, Array.Empty<string>()),
        };
        return new(OneLine(Headline(n), NtfyTitleMax), NtfyMessage(Rows(n)), priority, tags, n.Url);
    }

    internal static NtfyNotice Ntfy(MessageNotice n)
    {
        var high = NotificationRules.IsHighSeverity(n.IncidentSeverity);
        var (priority, tags) = n.Event switch
        {
            "question" => (4, new[] { "question" }),
            "mention" => (4, new[] { "speech_balloon" }),
            "verdict" when n.Classification == "truePositive" => (5, new[] { "rotating_light" }),
            "verdict" => (3, new[] { "mag" }),
            "finding" => (high ? 4 : 3, new[] { "mag" }),
            "incident" => (high ? 4 : 3, new[] { "warning" }),
            "action_result" when n.Action?.Status == "succeeded" => (3, new[] { "white_check_mark" }),
            "action_result" => (5, new[] { "x" }),
            _ => (3, Array.Empty<string>()),
        };
        return new(OneLine(Headline(n), NtfyTitleMax), NtfyMessage(Rows(n)), priority, tags, n.Url);
    }

    /// <summary>"Key: value" per line, each value one plain line, at most <see cref="NtfyMessageMax"/> characters in all.</summary>
    internal static string NtfyMessage(IEnumerable<(string Key, string Value)> rows)
    {
        var sb = new StringBuilder();
        foreach (var (k, v) in rows)
        {
            var line = $"{OneLine(k, 40)}: {OneLine(v)}";
            var room = NtfyMessageMax - sb.Length - (sb.Length > 0 ? 1 : 0);
            if (room < 2) break;
            if (sb.Length > 0) sb.Append('\n');
            if (line.Length <= room) { sb.Append(line); continue; }
            var cut = line[..(room - 1)];
            if (char.IsHighSurrogate(cut[^1])) cut = cut[..^1];
            sb.Append(cut.TrimEnd()).Append('…');
            break;
        }
        return sb.ToString();
    }

    /// <summary>ntfy's JSON publish body: topic, title, message, priority (1-5), tags, and click when there is a link.</summary>
    internal static string NtfyJson(NtfyNotice n, string topic)
    {
        var o = new Dictionary<string, object?>
        {
            ["topic"] = topic,
            ["title"] = n.Title,
            ["message"] = n.Message,
            ["priority"] = n.Priority,
            ["tags"] = n.Tags,
        };
        if (n.Click is not null) o["click"] = n.Click;
        return Json.Serialize(o);
    }

    // ── test button (setup page) ─────────────────────────────────────────────────────────────────
    public sealed record TestResult(string Sink, bool Ok, string Detail);

    /// <summary>Sends a sample notice to every configured sink and reports each result (setup page). Audited.</summary>
    public async Task<IReadOnlyList<TestResult>> SendTestAsync(Principal p, CancellationToken ct = default)
    {
        p.Require(Roles.Admin);
        var notice = new Notice("test", null, "Test notification", "No action: this checks the notification path", p.Handle,
            null, null, null, 0, Base() is { } b ? $"{b}/approvals" : null, "test");
        var results = await SendToAsync(Sinks(), Render(notice), ct);
        await audit.WriteAsync(p.Id, "notify.test", null, new { results = results.Select(r => new { r.Sink, r.Ok }) }, ct);
        return results;
    }

    private async Task<List<TestResult>> SendToAsync(IEnumerable<SinkState> sinks, Rendered n, CancellationToken ct)
    {
        var results = new List<TestResult>();
        foreach (var s in sinks)
        {
            if (s.Problem is not null) { results.Add(new(s.Sink, false, s.Problem)); continue; }
            try
            {
                await SendAsync(s.Sink, n, ct);
                results.Add(new(s.Sink, true, "sent"));
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                results.Add(new(s.Sink, false, SafeError(ex)));
            }
        }
        return results;
    }

    /// <summary>Latest delivery outcome per sink (setup page). Held and skipped notices aren't deliveries.</summary>
    public async Task<IReadOnlyDictionary<string, (string Status, DateTimeOffset At, string? Error)>> LastDeliveryAsync(CancellationToken ct = default)
    {
        var map = new Dictionary<string, (string, DateTimeOffset, string?)>();
        await using var cmd = db.Command("select distinct on (sink) sink, status, created_at, error from notifications where status in ('sent', 'failed') order by sink, created_at desc");
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) map[r.GetString(0)] = (r.GetString(1), r.GetFieldValue<DateTimeOffset>(2), r.Get<string>("error"));
        return map;
    }
}
