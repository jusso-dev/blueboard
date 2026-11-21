using System.Net;
using System.Security.Cryptography;
using System.Text;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Blueboard.Api.Webhooks;

/// <summary>
/// Wakes agents with signed webhooks (issue #23) and fires their scheduled follow-ups.
/// Subscriptions are https URLs on the admin's host allowlist. A timer turns new board messages into deliveries
/// (ids only, never bodies), and sends them with an HMAC-SHA256 signature, retries with backoff, and disables a
/// subscription after 20 consecutive failures. Polling read_feed keeps working: webhooks only say "look now".
/// </summary>
public sealed class WebhookService
{
    public const int DisableAfterFailures = 20;
    public const int MaxAttemptsPerDelivery = 8;
    public const int MaxSubscriptionsPerPrincipal = 10;
    private const string CursorKey = "webhooks.cursor";

    private readonly Db _db;
    private readonly Audit _audit;
    private readonly BoardService _board;
    private readonly SystemPrincipal _system;
    private readonly Settings _settings;
    private readonly HttpClient _http;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve;
    private readonly ILogger _log;

    public WebhookService(Db db, Audit audit, BoardService board, SystemPrincipal system, Settings settings, ILogger<WebhookService>? log = null)
        : this(db, audit, board, system, settings, new HttpClient(OutboundGuard.Handler()) { Timeout = OutboundGuard.Timeout }, OutboundGuard.ResolvePublicAsync, log) { }

    /// <summary>Tests pass an in-process receiver and a fake resolver; production uses the guarded handler and DNS.</summary>
    public WebhookService(Db db, Audit audit, BoardService board, SystemPrincipal system, Settings settings, HttpClient http,
        Func<string, CancellationToken, Task<IPAddress[]>> resolve, ILogger? log = null)
    {
        (_db, _audit, _board, _system, _settings, _http, _resolve) = (db, audit, board, system, settings, http, resolve);
        _log = log ?? NullLogger.Instance;
    }

    private bool Enabled => _settings.WebhookSigningKey is not null && _settings.WebhookAllowedHosts.Length > 0;

    // ── subscriptions ────────────────────────────────────────────────────────────────────────────

    public async Task<Subscription> SubscribeAsync(Principal p, SubscribeInput input, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        if (!Enabled) throw BoardException.Forbidden("webhooks are not enabled on this board (WEBHOOK_ALLOWED_HOSTS and WEBHOOK_SIGNING_KEY)");
        var host = OutboundGuard.CheckUrl(input.Url, _settings.WebhookAllowedHosts);
        // Resolve now as well as at every delivery: refuse a host that points inside the network today.
        var addrs = await _resolve(host, ct);
        if (addrs.FirstOrDefault(a => !OutboundGuard.IsPublic(a)) is { } bad)
            throw BoardException.Forbidden($"webhook host {host} resolves to a non-public address ({bad})");
        var events = input.Events.Distinct().ToArray();
        if (events.Length == 0 || events.Any(e => !WebhookEvents.All.Contains(e)))
            throw new BoardException($"events must be some of {string.Join(", ", WebhookEvents.All)}");
        if (input.Channel is { } ch) await _board.ResolveChannelAsync(ch, ct);

        var salt = RandomNumberGenerator.GetBytes(16);
        await using (var count = _db.Command("select count(*) from agent_subscriptions where principal_id = @p and url <> @u").With("p", p.Id).With("u", input.Url))
            if ((long)(await count.ExecuteScalarAsync(ct))! >= MaxSubscriptionsPerPrincipal)
                throw new BoardException($"at most {MaxSubscriptionsPerPrincipal} subscriptions per principal");
        await using var cmd = _db.Command("""
            insert into agent_subscriptions (principal_id, url, host, events, channel, secret_salt)
            values (@p, @u, @h, @e, @c, @s)
            on conflict (principal_id, url) do update set events = excluded.events, channel = excluded.channel, host = excluded.host,
                secret_salt = excluded.secret_salt, enabled = true, failures = 0, disabled_reason = null, last_error = null, created_at = now()
            returning id, created_at
            """).With("p", p.Id).With("u", input.Url).With("h", host).With("e", events).With("c", input.Channel).With("s", salt);
        Guid id;
        DateTimeOffset created;
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            await r.ReadAsync(ct);
            (id, created) = (r.GetGuid(0), r.GetFieldValue<DateTimeOffset>(1));
        }
        await _audit.WriteAsync(p.Id, "webhook.subscribed", id.ToString(), new { host, events, channel = input.Channel }, ct);
        return new Subscription(id, input.Url, events, input.Channel, true, 0, created, SecretFor(id, salt));
    }

    public async Task<object> UnsubscribeAsync(Principal p, Guid id, CancellationToken ct = default)
    {
        await using var cmd = _db.Command("delete from agent_subscriptions where id = @id and principal_id = @p").With("id", id).With("p", p.Id);
        if (await cmd.ExecuteNonQueryAsync(ct) == 0) throw BoardException.NotFound("subscription");
        await _audit.WriteAsync(p.Id, "webhook.unsubscribed", id.ToString(), null, ct);
        return new { unsubscribed = id };
    }

    /// <summary>Caller's own webhook subscriptions and delivery health. Never the secret.</summary>
    public async Task<IReadOnlyList<Subscription>> ListForPrincipalAsync(Principal p, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        await using var cmd = _db.Command("""
            select id, url, events, channel, enabled, failures, created_at
            from agent_subscriptions where principal_id = @p order by created_at desc
            """).With("p", p.Id);
        var list = new List<Subscription>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new Subscription(r.GetGuid(0), r.GetString(1), r.GetFieldValue<string[]>(2), r.Get<string>("channel"),
                r.GetBoolean(4), r.GetInt32(5), r.GetFieldValue<DateTimeOffset>(6)));
        return list;
    }

    /// <summary>Caller's pending scheduled follow-ups.</summary>
    public async Task<IReadOnlyList<object>> ListFollowupsAsync(Principal p, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        await using var cmd = _db.Command("""
            select id, message_id, note, due_at, created_at
            from followups where principal_id = @p and fired_at is null order by due_at asc limit 100
            """).With("p", p.Id);
        var list = new List<object>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new { id = r.GetGuid(0), message_id = r.GetGuid(1), note = r.GetString(2), due_at = r.GetFieldValue<DateTimeOffset>(3), created_at = r.GetFieldValue<DateTimeOffset>(4) });
        return list;
    }

    /// <summary>Admin view: every subscription with its owner and delivery health. Never the secret.</summary>
    public async Task<IReadOnlyList<object>> ListAllAsync(CancellationToken ct = default)
    {
        await using var cmd = _db.Command("""
            select s.id, p.handle, s.url, s.events, s.channel, s.enabled, s.failures, s.disabled_reason, s.last_success_at, s.last_error, s.created_at
            from agent_subscriptions s join principals p on p.id = s.principal_id order by p.handle, s.created_at
            """);
        var list = new List<object>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new
            {
                id = r.GetGuid(0), principal = r.GetString(1), url = r.GetString(2), events = r.GetFieldValue<string[]>(3), channel = r.Get<string>("channel"),
                enabled = r.GetBoolean(5), failures = r.GetInt32(6), disabled_reason = r.Get<string>("disabled_reason"),
                last_success_at = r.Get<DateTimeOffset?>("last_success_at"), last_error = r.Get<string>("last_error"), created_at = r.GetFieldValue<DateTimeOffset>(10),
            });
        return list;
    }

    /// <summary>Per-subscription secret: HMAC of the subscription id and a random salt under the board's key. Only the salt is stored.</summary>
    internal string SecretFor(Guid subscriptionId, byte[] salt)
    {
        var key = Convert.FromBase64String(_settings.WebhookSigningKey ?? throw new InvalidOperationException("WEBHOOK_SIGNING_KEY not set"));
        var mac = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"blueboard-webhook:{subscriptionId}:{Convert.ToBase64String(salt)}"));
        return "whsec_" + Convert.ToBase64String(mac).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    // ── follow-ups ───────────────────────────────────────────────────────────────────────────────

    public async Task<Followup> ScheduleFollowupAsync(Principal p, FollowupInput input, CancellationToken ct = default)
    {
        p.Require(Roles.Poster);
        var m = await _board.GetAsync(input.MessageId, ct) ?? throw BoardException.NotFound("message");
        var root = m.ParentId ?? m.Id;
        await using (var count = _db.Command("select count(*) from followups where principal_id = @p and fired_at is null").With("p", p.Id))
            if ((long)(await count.ExecuteScalarAsync(ct))! >= 100) throw new BoardException("at most 100 pending follow-ups per principal");
        await using var cmd = _db.Command("""
            insert into followups (principal_id, message_id, note, due_at) values (@p, @m, @n, now() + make_interval(mins => @min))
            returning id, due_at
            """).With("p", p.Id).With("m", root).With("n", input.Note).With("min", input.InMinutes);
        Followup f;
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            await r.ReadAsync(ct);
            f = new Followup(r.GetGuid(0), root, r.GetFieldValue<DateTimeOffset>(1));
        }
        await _audit.WriteAsync(p.Id, "followup.scheduled", f.Id.ToString(), new { message_id = root, input.InMinutes }, ct);
        return f;
    }

    /// <summary>
    /// Posts every due follow-up exactly once: the row is claimed (skip locked) and its reminder posted in one
    /// transaction, so two instances can't both post it and a crash before commit leaves it due for the next run.
    /// </summary>
    public async Task<int> FireDueFollowupsAsync(CancellationToken ct = default)
    {
        var sys = await _system.GetAsync(ct);
        var fired = 0;
        for (var i = 0; i < 50; i++)
        {
            await using var conn = await _db.OpenAsync(ct);
            await using var tx = await conn.BeginTransactionAsync(ct);
            Guid id, root; string note, handle, channel;
            await using (var pick = new NpgsqlCommand("""
                select f.id, f.message_id, f.note, p.handle, c.name
                from followups f join principals p on p.id = f.principal_id
                join messages m on m.id = f.message_id join channels c on c.id = m.channel_id
                where f.fired_at is null and f.due_at <= now() order by f.due_at limit 1 for update of f skip locked
                """, conn, tx))
            await using (var r = await pick.ExecuteReaderAsync(ct))
            {
                if (!await r.ReadAsync(ct)) break;
                (id, root, note, handle, channel) = (r.GetGuid(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetString(4));
            }
            var msg = await _board.PostInTransactionAsync(conn, tx, sys, new PostInput(channel,
                $"Follow-up for @{handle} (scheduled by @{handle}):\n\n> {note.Replace("\n", "\n> ")}",
                "status", Json.Element(new { state = "followup", followup_id = id }), root), system: true, ct);
            await using (var done = new NpgsqlCommand("update followups set fired_at = now(), posted_message_id = @m where id = @id", conn, tx).With("m", msg).With("id", id))
                await done.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
            fired++;
        }
        return fired;
    }

    // ── delivery ─────────────────────────────────────────────────────────────────────────────────

    /// <summary>Is there anything to do? Cheap enough to run on every timer tick.</summary>
    public async Task<bool> HasWorkAsync(CancellationToken ct = default)
    {
        await using var cmd = _db.Command("""
            select exists (select 1 from agent_subscriptions where enabled)
                or exists (select 1 from followups where fired_at is null and due_at <= now())
                or exists (select 1 from webhook_deliveries where status = 'pending' and next_attempt_at <= now())
            """);
        return await cmd.ExecuteScalarAsync(ct) is true;
    }

    /// <summary>
    /// Turns messages after the cursor into deliveries. Message inserts take the feed lock, so the highest visible
    /// seq has nothing uncommitted below it and the cursor can't skip a message. Events that depend on who the board
    /// says did something (incident updates, action decisions) count only when the board itself posted them.
    /// </summary>
    public async Task<int> EnqueueAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        long after;
        await using (var c = new NpgsqlCommand("select (value #>> '{}')::bigint from kv_state where key = @k for update", conn, tx).With("k", CursorKey))
            after = await c.ExecuteScalarAsync(ct) is long v ? v : -1;
        long upto;
        await using (var c = new NpgsqlCommand("select coalesce(max(seq), 0) from messages", conn, tx))
            upto = (long)(await c.ExecuteScalarAsync(ct))!;
        if (after < 0) after = upto; // first run: start at the end, never replay history
        var n = 0;
        if (upto > after)
        {
            await using var ins = new NpgsqlCommand("""
                insert into webhook_deliveries (subscription_id, event, message_id, seq)
                select s.id, e.event, m.id, m.seq
                from messages m
                join channels c on c.id = m.channel_id
                join agent_subscriptions s on s.enabled and (s.channel is null or s.channel = c.name) and m.created_at >= s.created_at
                join principals sp on sp.id = s.principal_id
                cross join lateral (values
                  ('incident.new',     m.type = 'incident' and m.parent_id is null and m.author_id = @board),
                  ('incident.updated', m.type = 'status' and m.payload->>'state' = 'source_updated' and m.author_id = @board),
                  ('mention',          sp.handle = any(m.mentions)),
                  ('thread.reply',     m.parent_id is not null and exists (
                                         select 1 from messages t where (t.id = m.parent_id or t.parent_id = m.parent_id)
                                         and t.author_id = s.principal_id and t.seq < m.seq)),
                  ('action.decided',   m.author_id = @board and (m.type = 'action_result' or (m.type = 'status' and m.payload->>'state' in ('action_approved', 'action_approved_once', 'action_denied', 'action_expired', 'action_rejected', 'action_held')))
                                       and exists (select 1 from actions a where a.id::text = m.payload->>'action_id' and a.requested_by = s.principal_id))
                ) e(event, hit)
                where m.seq > @after and m.seq <= @upto and e.hit and e.event = any(s.events) and m.author_id <> s.principal_id
                on conflict do nothing
                """, conn, tx).With("after", after).With("upto", upto).With("board", (await _system.GetAsync(ct)).Id);
            n += await ins.ExecuteNonQueryAsync(ct);
        }
        // claim.expired is a state change, not a message: one delivery per lease that ran out (ref = expiry time).
        await using (var exp = new NpgsqlCommand("""
            insert into webhook_deliveries (subscription_id, event, message_id, seq, ref)
            select s.id, 'claim.expired', m.id, m.seq, extract(epoch from m.claim_expires_at)::bigint::text
            from messages m
            join channels c on c.id = m.channel_id
            join agent_subscriptions s on s.enabled and s.principal_id = m.claimed_by and 'claim.expired' = any(s.events)
              and (s.channel is null or s.channel = c.name)
            where m.claim_state = 'claimed' and m.claim_expires_at < now() and m.claim_expires_at > now() - interval '1 hour'
              and m.claim_expires_at >= s.created_at
            on conflict do nothing
            """, conn, tx))
            n += await exp.ExecuteNonQueryAsync(ct);
        await using (var set = new NpgsqlCommand("""
            insert into kv_state (key, value) values (@k, to_jsonb(@v)) on conflict (key) do update set value = excluded.value, updated_at = now()
            """, conn, tx).With("k", CursorKey).With("v", upto))
            await set.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
        return n;
    }

    private sealed record Due(Guid Id, string Event, Guid MessageId, long Seq, int Attempts, Guid SubId, string Url, string Host, byte[] Salt, Guid PrincipalId);

    /// <summary>Sends due deliveries, up to 8 at a time. Returns (sent, failed attempts).</summary>
    public async Task<(int Sent, int Failed)> DeliverAsync(CancellationToken ct = default)
    {
        var due = new List<Due>();
        await using (var cmd = _db.Command("""
            select d.id, d.event, d.message_id, d.seq, d.attempts, s.id, s.url, s.host, s.secret_salt, s.principal_id
            from webhook_deliveries d join agent_subscriptions s on s.id = d.subscription_id
            where d.status = 'pending' and d.next_attempt_at <= now() and s.enabled
            order by d.created_at limit 100
            """))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
                due.Add(new Due(r.GetGuid(0), r.GetString(1), r.GetGuid(2), r.GetInt64(3), r.GetInt32(4), r.GetGuid(5), r.GetString(6), r.GetString(7),
                    r.GetFieldValue<byte[]>(8), r.GetGuid(9)));
        int sent = 0, failed = 0;
        await Parallel.ForEachAsync(due, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (d, token) =>
        {
            var error = await SendAsync(d, token);
            if (error is null) { Interlocked.Increment(ref sent); await RecordSuccessAsync(d, token); }
            else { Interlocked.Increment(ref failed); await RecordFailureAsync(d, error, token); }
        });
        return (sent, failed);
    }

    private async Task<string?> SendAsync(Due d, CancellationToken ct)
    {
        try
        {
            // The allowlist may have changed since subscribe: check again before every send.
            if (OutboundGuard.CheckUrl(d.Url, _settings.WebhookAllowedHosts) != d.Host) return "host changed";
            await _resolve(d.Host, ct);
            var body = Json.Serialize(new WebhookEvent(d.Event, d.MessageId, d.Seq.ToString(), d.SubId, d.Id));
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            using var req = new HttpRequestMessage(HttpMethod.Post, d.Url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            req.Headers.TryAddWithoutValidation(WebhookEvents.SignatureHeader, WebhookSignature.Sign(SecretFor(d.SubId, d.Salt), ts, body));
            req.Headers.TryAddWithoutValidation(WebhookEvents.TimestampHeader, ts.ToString());
            req.Headers.TryAddWithoutValidation("X-Blueboard-Event", d.Event);
            req.Headers.TryAddWithoutValidation("X-Blueboard-Delivery", d.Id.ToString());
            req.Headers.UserAgent.ParseAdd("blueboard-webhooks/1.0");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(OutboundGuard.Timeout);
            using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            return res.IsSuccessStatusCode ? null : $"HTTP {(int)res.StatusCode}";
        }
        catch (BoardException ex) { return ex.Message; }
        catch (HttpRequestException ex) { return ex.HttpRequestError.ToString(); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return "timed out"; }
    }

    private async Task RecordSuccessAsync(Due d, CancellationToken ct)
    {
        await using var cmd = _db.Command("""
            update webhook_deliveries set status = 'sent', attempts = attempts + 1, delivered_at = now(), last_error = null where id = @d;
            update agent_subscriptions set failures = 0, last_success_at = now(), last_error = null where id = @s;
            """).With("d", d.Id).With("s", d.SubId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    /// <summary>Backoff: 5 s, 10 s, 20 s … capped at 30 min. A delivery gives up after 8 attempts; a subscription after 20 failures in a row.</summary>
    internal static TimeSpan Backoff(int attempt) => TimeSpan.FromSeconds(Math.Min(5 * Math.Pow(2, attempt), 1800));

    private async Task RecordFailureAsync(Due d, string error, CancellationToken ct)
    {
        var attempts = d.Attempts + 1;
        var giveUp = attempts >= MaxAttemptsPerDelivery;
        await using (var cmd = _db.Command("""
            update webhook_deliveries set attempts = @a, last_error = @e, status = case when @give then 'failed' else 'pending' end,
                   next_attempt_at = now() + make_interval(secs => @wait) where id = @d
            """).With("a", attempts).With("e", error).With("give", giveUp).With("wait", Backoff(attempts).TotalSeconds).With("d", d.Id))
            await cmd.ExecuteNonQueryAsync(ct);
        await using var sub = _db.Command("""
            update agent_subscriptions set failures = failures + 1, last_error = @e,
                   enabled = failures + 1 < @max,
                   disabled_reason = case when failures + 1 >= @max then 'disabled after ' || @max || ' failed deliveries in a row' else disabled_reason end
            where id = @s returning enabled
            """).With("e", error).With("max", DisableAfterFailures).With("s", d.SubId);
        if (await sub.ExecuteScalarAsync(ct) is false)
        {
            _log.LogWarning("webhook subscription {Subscription} disabled after {Failures} failures", d.SubId, DisableAfterFailures);
            await _audit.WriteAsync(d.PrincipalId, "webhook.disabled", d.SubId.ToString(), new { error }, ct);
            await using var drop = _db.Command("update webhook_deliveries set status = 'failed' where subscription_id = @s and status = 'pending'").With("s", d.SubId);
            await drop.ExecuteNonQueryAsync(ct);
        }
    }

    /// <summary>One timer tick: follow-ups, then new events, then delivery.</summary>
    public async Task<object> RunOnceAsync(CancellationToken ct = default)
    {
        if (!await HasWorkAsync(ct))
        {
            // Nothing subscribed: keep the cursor at the end so a new subscription starts from now.
            await EnqueueAsync(ct);
            return new { idle = true };
        }
        var followups = await FireDueFollowupsAsync(ct);
        var queued = await EnqueueAsync(ct);
        var (sent, failed) = Enabled ? await DeliverAsync(ct) : (0, 0);
        return new { followups, queued, sent, failed };
    }
}
