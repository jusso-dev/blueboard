using System.Net;
using System.Security.Cryptography;
using System.Text;
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
    string? IncidentGraphId, string? IncidentTitle, string? IncidentSeverity, int PolicyNotes, string? Url, string Status);

/// <summary>
/// Tells approvers when an action waits for them (and reminds them, and says when one expired, was interrupted or
/// failed) through Teams, email and a signed webhook. Runs from a timer. Each (action, event, sink) is claimed by
/// inserting its row in `notifications` before sending, so it goes out once across every instance. Justification
/// text never leaves the board: it is untrusted agent text. A failing sink is logged and audited, never blocking.
/// </summary>
public sealed partial class Notifier(HttpClient http, Db db, Audit audit, MsClient ms, Settings settings, ILogger<Notifier>? log = null)
{
    private readonly ILogger _log = log ?? NullLogger<Notifier>.Instance;
    private const int MaxReminders = 8;

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
        return list;
    }

    private IEnumerable<string> ReadySinks() => Sinks().Where(s => s.Problem is null).Select(s => s.Sink);

    /// <summary>Outbound guard: https only, default port, no credentials in the URL, and an exact host from NOTIFY_ALLOWED_HOSTS.</summary>
    internal string? UrlProblem(string url, string name)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return $"{name} must be an https URL";
        if (u.UserInfo.Length > 0 || !u.IsDefaultPort) return $"{name} must not carry credentials or a custom port";
        if (!settings.NotifyAllowedHosts.Contains(u.IdnHost, StringComparer.OrdinalIgnoreCase)) return $"{u.IdnHost} is not in NOTIFY_ALLOWED_HOSTS";
        return null;
    }

    // ── the sweep (timer) ────────────────────────────────────────────────────────────────────────
    /// <summary>Finds events that still need a notice and sends each once per ready sink. Returns notices sent.</summary>
    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        var sinks = ReadySinks().ToArray();
        if (sinks.Length == 0) return 0;
        var due = new List<(Guid Id, string Event)>();
        await using (var cmd = db.Command("""
            with events as (
              select id, 'requested' as event from actions
               where status = 'pending_approval' and created_at > now() - interval '1 day'
              union all
              select id, 'reminder:' || floor(extract(epoch from now() - created_at) / 60 / @m)::int from actions
               where status = 'pending_approval' and created_at > now() - interval '1 day'
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
                if (!await ClaimAsync(id, evt, sink, ct)) continue;
                if (await DeliverAsync(sink, notice, id, evt, ct)) sent++;
            }
        }
        return sent;
    }

    private async Task<bool> ClaimAsync(Guid actionId, string evt, string sink, CancellationToken ct)
    {
        await using var cmd = db.Command("insert into notifications (action_id, event, sink) values (@a, @e, @s) on conflict do nothing returning id")
            .With("a", actionId).With("e", evt).With("s", sink);
        return await cmd.ExecuteScalarAsync(ct) is not null;
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
        try { target = def is null ? r.GetString(0) : def.Describe(def.Validate(System.Text.Json.JsonDocument.Parse(r.GetString(1)).RootElement)); }
        catch (BoardException) { target = "(parameters no longer valid)"; }
        var name = evt.StartsWith("reminder:", StringComparison.Ordinal) ? "action.reminder" : evt switch
        {
            "requested" => "action.pending_approval",
            "expired" => "action.expired",
            "interrupted" => "action.interrupted",
            _ => "action.failed",
        };
        return new Notice(name, id, def?.Title ?? r.GetString(0), target, r.GetString(4), r.Get<string>("graph_id"), r.Get<string>("display_name"),
            r.Get<string>("severity"), r.GetFieldValue<string[]>(3).Length, DeepLink(id), r.GetString(2));
    }

    /// <summary>The Approvals page scrolled to this action. Only an https base (or http on localhost) from settings.</summary>
    internal string? DeepLink(Guid id) =>
        settings.WebBaseUrl is { } b && Uri.TryCreate(b, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.IsLoopback)
            ? $"{u.GetLeftPart(UriPartial.Authority)}/approvals#{id}"
            : null;

    private async Task<bool> DeliverAsync(string sink, Notice n, Guid actionId, string evt, CancellationToken ct)
    {
        try
        {
            await SendAsync(sink, n, ct);
            await using var up = db.Command("update notifications set status = 'sent', sent_at = now(), attempts = attempts + 1 where action_id = @a and event = @e and sink = @s")
                .With("a", actionId).With("e", evt).With("s", sink);
            await up.ExecuteNonQueryAsync(ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            var error = SafeError(ex);
            _log.LogWarning("notification to {Sink} failed: {Error}", sink, error);
            await using (var up = db.Command("update notifications set status = 'failed', error = @err, attempts = attempts + 1 where action_id = @a and event = @e and sink = @s")
                             .With("err", error).With("a", actionId).With("e", evt).With("s", sink))
                await up.ExecuteNonQueryAsync(CancellationToken.None);
            await audit.WriteAsync(null, "notify.failed", actionId.ToString(), new { sink, @event = n.Event, error }, CancellationToken.None);
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
    private async Task SendAsync(string sink, Notice n, CancellationToken ct)
    {
        switch (sink)
        {
            case "teams":
                await PostAsync(settings.NotifyTeamsWebhookUrl!, Json.Serialize(TeamsCard(n)), null, ct);
                break;
            case "webhook":
                var body = Json.Serialize(WebhookPayload(n));
                await PostAsync(settings.NotifyWebhookUrl!, body, Sign(body, settings.NotifyWebhookSecret!), ct);
                break;
            case "mail":
                await ms.SendAsync(MsApi.Graph, $"/v1.0/users/{Uri.EscapeDataString(settings.NotifyMailFrom!)}/sendMail", HttpMethod.Post, new
                {
                    message = new
                    {
                        subject = Subject(n),
                        body = new { contentType = "HTML", content = MailHtml(n) },
                        toRecipients = settings.NotifyMailTo.Select(t => new { emailAddress = new { address = t } }),
                    },
                    saveToSentItems = false,
                }, ct);
                break;
        }
    }

    private async Task PostAsync(string url, string body, string? signature, CancellationToken ct)
    {
        if (UrlProblem(url, "notification URL") is { } problem) throw new BoardException(problem);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        req.Headers.UserAgent.ParseAdd("blueboard-notifier/1");
        if (signature is not null) req.Headers.TryAddWithoutValidation("X-Blueboard-Signature", signature);
        // Headers only: the response body is never read, so a hostile endpoint can't stream data back at us.
        using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if ((int)res.StatusCode is >= 300 and < 400) throw new HttpRequestException("redirects are not followed", null, res.StatusCode);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>X-Blueboard-Signature: sha256=&lt;hex HMAC-SHA256 of the raw UTF-8 body&gt;.</summary>
    public static string Sign(string body, string secret) =>
        "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body)));

    // ── formatting (all untrusted fields escaped) ────────────────────────────────────────────────
    internal static string Headline(Notice n) => n.Event switch
    {
        "action.pending_approval" => "Approval needed",
        "action.reminder" => "Still waiting for approval",
        "action.expired" => "Approval request expired",
        "action.interrupted" => "Action interrupted: outcome unknown, check Defender",
        "action.failed" => "Action failed: check Defender",
        _ => "Test notification",
    };

    internal static string Subject(Notice n) =>
        OneLine($"[blueboard] {Headline(n)}: {n.Title}{(n.IncidentGraphId is null ? "" : $", incident {n.IncidentGraphId}")}", 200);

    /// <summary>Plain one-line text: no control characters or line breaks, capped.</summary>
    internal static string OneLine(string? s, int max = 300)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(Math.Min(s.Length, max));
        foreach (var ch in s)
        {
            if (sb.Length >= max) break;
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

    internal static object TeamsCard(Notice n)
    {
        var facts = new List<object>
        {
            new { title = "Action", value = CardText(n.Title) },
            new { title = "Target", value = CardText(n.Target) },
            new { title = "Requested by", value = CardText("@" + n.RequestedBy) },
        };
        if (n.IncidentGraphId is not null)
            facts.Add(new { title = "Incident", value = CardText($"{n.IncidentGraphId} ({n.IncidentSeverity ?? "unknown"}): {n.IncidentTitle}") });
        facts.Add(new { title = "Policy notes", value = n.PolicyNotes.ToString(System.Globalization.CultureInfo.InvariantCulture) });
        var body = new List<object>
        {
            new { type = "TextBlock", text = CardText(Headline(n)), weight = "Bolder", size = "Medium", wrap = true },
            new { type = "FactSet", facts },
            new { type = "TextBlock", text = "Open the board to read the justification and decide. blueboard never takes approvals from chat.", wrap = true, isSubtle = true },
        };
        var card = new Dictionary<string, object>
        {
            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
            ["type"] = "AdaptiveCard",
            ["version"] = "1.4",
            ["body"] = body,
        };
        if (n.Url is not null) card["actions"] = new[] { new { type = "Action.OpenUrl", title = "Open in blueboard", url = n.Url } };
        return new { type = "message", attachments = new[] { new { contentType = "application/vnd.microsoft.card.adaptive", contentUrl = (string?)null, content = card } } };
    }

    internal static string MailHtml(Notice n)
    {
        static string H(string? s) => WebUtility.HtmlEncode(OneLine(s));
        var rows = new List<(string, string)>
        {
            ("Action", n.Title), ("Target", n.Target), ("Requested by", "@" + n.RequestedBy),
        };
        if (n.IncidentGraphId is not null) rows.Add(("Incident", $"{n.IncidentGraphId} ({n.IncidentSeverity ?? "unknown"}): {n.IncidentTitle}"));
        rows.Add(("Policy notes", n.PolicyNotes.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        var sb = new StringBuilder();
        sb.Append("<p><strong>").Append(H(Headline(n))).Append("</strong></p><table>");
        foreach (var (k, v) in rows) sb.Append("<tr><td>").Append(H(k)).Append("</td><td>").Append(H(v)).Append("</td></tr>");
        sb.Append("</table>");
        if (n.Url is not null) sb.Append("<p><a href=\"").Append(WebUtility.HtmlEncode(n.Url)).Append("\">Open in blueboard</a></p>");
        sb.Append("<p>Read the justification and decide on the board. blueboard never takes approvals by email.</p>");
        return sb.ToString();
    }

    internal static object WebhookPayload(Notice n) => new
    {
        @event = n.Event,
        action_id = n.ActionId,
        status = n.Status,
        title = n.Title,
        target = OneLine(n.Target),
        requested_by = OneLine(n.RequestedBy, 100),
        incident = n.IncidentGraphId is null ? null : new { graph_id = OneLine(n.IncidentGraphId, 100), title = OneLine(n.IncidentTitle), severity = OneLine(n.IncidentSeverity, 50) },
        policy_notes = n.PolicyNotes,
        url = n.Url,
        sent_at = DateTimeOffset.UtcNow,
    };

    // ── test button ──────────────────────────────────────────────────────────────────────────────
    public sealed record TestResult(string Sink, bool Ok, string Detail);

    /// <summary>Sends a sample notice to every configured sink and reports each result (setup page). Audited.</summary>
    public async Task<IReadOnlyList<TestResult>> SendTestAsync(Principal p, CancellationToken ct = default)
    {
        p.Require(Roles.Admin);
        var notice = new Notice("test", null, "Test notification", "No action: this checks the notification path", p.Handle,
            null, null, null, 0, settings.WebBaseUrl is null ? null : DeepLink(Guid.Empty)?.Replace($"#{Guid.Empty}", "", StringComparison.Ordinal), "test");
        var results = new List<TestResult>();
        foreach (var s in Sinks())
        {
            if (s.Problem is not null) { results.Add(new(s.Sink, false, s.Problem)); continue; }
            try
            {
                await SendAsync(s.Sink, notice, ct);
                results.Add(new(s.Sink, true, "sent"));
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                results.Add(new(s.Sink, false, SafeError(ex)));
            }
        }
        await audit.WriteAsync(p.Id, "notify.test", null, new { results = results.Select(r => new { r.Sink, r.Ok }) }, ct);
        return results;
    }

    /// <summary>Latest delivery outcome per sink (setup page).</summary>
    public async Task<IReadOnlyDictionary<string, (string Status, DateTimeOffset At, string? Error)>> LastDeliveryAsync(CancellationToken ct = default)
    {
        var map = new Dictionary<string, (string, DateTimeOffset, string?)>();
        await using var cmd = db.Command("select distinct on (sink) sink, status, created_at, error from notifications order by sink, created_at desc");
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) map[r.GetString(0)] = (r.GetString(1), r.GetFieldValue<DateTimeOffset>(2), r.Get<string>("error"));
        return map;
    }
}
