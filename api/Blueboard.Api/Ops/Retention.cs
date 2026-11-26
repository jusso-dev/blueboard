using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Npgsql;

namespace Blueboard.Api.Ops;

/// <summary>What one retention run removed (or, in a dry run, would remove).</summary>
public sealed record RetentionResult(
    DateTimeOffset At, DateTimeOffset Cutoff, int Days, bool DryRun,
    int Incidents, int Messages, int Actions, int Deliveries, string? Error = null)
{
    public int Total => Incidents + Messages + Actions + Deliveries;
}

/// <summary>
/// Data retention (RETENTION_DAYS, off by default). Removes board records older than the retention period:
///  - resolved or redirected incidents not updated since the cutoff, with every message, action and delivery record
///    that belongs to them;
///  - channel threads with no incident whose last post is older than the cutoff;
///  - finished actions (denied, succeeded, failed, rejected, expired) with no incident, last changed before the cutoff;
///  - sent, failed or skipped notification and webhook delivery records, and fired follow-ups, older than the cutoff.
/// Never removed: anything tied to an action still pending, approved or running; threads with a follow-up still due;
/// open incidents; principals, channels, settings and policy. audit_log is append-only and is never removed: it keeps
/// who did what (with ids, not content) for as long as the database lives, and its Sentinel copy (BlueboardAudit_CL)
/// has its own retention. Each run that removes something writes one retention.purged audit row with the counts.
/// The work runs in one transaction per batch, so a failure leaves nothing half-deleted; a dry run rolls it back.
/// </summary>
public sealed class Retention(Db db, Audit audit, SystemPrincipal system, Settings settings)
{
    public const int MinimumDays = 30;
    public const int BatchSize = 500;
    private const int MaxBatches = 40;
    public const string LastRunKey = "retention.lastRun";

    internal const string Active = "('pending_approval','approved_once','approved','running')";
    internal const string Finished = "('denied','succeeded','failed','rejected','expired')";

    public bool Enabled => settings.RetentionDays > 0;

    /// <summary>One run, in batches until nothing is left (bounded). days overrides RETENTION_DAYS (CLI).</summary>
    public async Task<RetentionResult> RunAsync(bool dryRun, int? days = null, CancellationToken ct = default)
    {
        var d = days ?? settings.RetentionDays;
        if (d < MinimumDays) throw new BoardException($"retention needs at least {MinimumDays} days (got {d})");
        var now = DateTimeOffset.UtcNow;
        var cutoff = now.AddDays(-d);
        int inc = 0, msg = 0, act = 0, del = 0;
        for (var i = 0; i < MaxBatches; i++)
        {
            var (bi, bm, ba, bd, more) = await BatchAsync(cutoff, dryRun, ct);
            inc += bi; msg += bm; act += ba; del += bd;
            // A dry run rolls back, so a second batch would count the same rows again.
            if (!more || dryRun) break;
        }
        var result = new RetentionResult(now, cutoff, d, dryRun, inc, msg, act, del);
        if (!dryRun && result.Total > 0)
        {
            var board = await system.GetAsync(ct);
            await audit.WriteAsync(board.Id, "retention.purged", $"older than {d} days",
                new { cutoff, days = d, incidents = inc, messages = msg, actions = act, deliveries = del }, ct);
        }
        return result;
    }

    private async Task<(int Incidents, int Messages, int Actions, int Deliveries, bool More)> BatchAsync(DateTimeOffset cutoff, bool dryRun, CancellationToken ct)
    {
        await using var conn = await db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        async Task<int> Exec(string sql)
        {
            await using var c = new NpgsqlCommand(sql, conn, tx);
            c.Parameters.AddWithValue("cutoff", cutoff);
            c.Parameters.AddWithValue("batch", BatchSize);
            return await c.ExecuteNonQueryAsync(ct);
        }

        // 1. What goes, in temporary tables dropped at commit. Threads an unfinished action or a pending follow-up
        //    still points at are pinned: they, and the incidents they are in, stay.
        await Exec($"""
            create temp table rt_pinned on commit drop as
            select m.id, coalesce(m.parent_id, m.id) as root, m.incident_id from messages m
            where m.id in (select request_message_id from actions where status in {Active}
                           union select on_behalf_of from actions where status in {Active}
                           union select message_id from followups where fired_at is null)
            """);
        await Exec("insert into rt_pinned select r.id, r.id, r.incident_id from messages r where r.id in (select root from rt_pinned)");
        var incidents = await Exec($"""
            create temp table rt_incidents on commit drop as
            select i.id from incidents i
            where lower(i.status) in ('resolved', 'redirected')
              and coalesce(i.updated_at_src, i.first_seen_at) < @cutoff and i.last_synced_at < @cutoff
              and not exists (select 1 from actions a where a.incident_id = i.id and a.status in {Active})
              and not exists (select 1 from messages m where m.incident_id = i.id and m.created_at >= @cutoff)
              and not exists (select 1 from messages r join messages x on x.parent_id = r.id
                              where r.incident_id = i.id and x.created_at >= @cutoff)
              and i.id not in (select incident_id from rt_pinned where incident_id is not null)
            order by i.first_seen_at limit @batch
            """);
        var roots = await Exec("""
            create temp table rt_roots on commit drop as
            select r.id from messages r
            where r.parent_id is null and r.incident_id is null and r.created_at < @cutoff
              and not exists (select 1 from messages x where x.parent_id = r.id and x.created_at >= @cutoff)
              and r.id not in (select root from rt_pinned)
            order by r.seq limit @batch
            """);
        await Exec("insert into rt_roots select r.id from messages r where r.parent_id is null and r.incident_id in (select id from rt_incidents)");
        // Whole threads (a root never outlives its replies), plus stray replies filed under a purged incident.
        await Exec("""
            create temp table rt_messages on commit drop as
            select m.id from messages m
            where (coalesce(m.parent_id, m.id) in (select id from rt_roots) or m.incident_id in (select id from rt_incidents))
              and coalesce(m.parent_id, m.id) not in (select root from rt_pinned)
            """);
        await Exec($"""
            create temp table rt_actions on commit drop as
            select a.id from actions a
            where a.status in {Finished}
              and (a.incident_id in (select id from rt_incidents)
                or a.request_message_id in (select id from rt_messages) or a.on_behalf_of in (select id from rt_messages)
                or (a.incident_id is null and a.updated_at < @cutoff))
            """);

        // 2. Children first. Unfinished actions never point at a purged row (pinned above). Rows that only mention a
        //    purged row (threat intel post markers, playbook roots, posted follow-ups) lose the reference, not the row.
        var deliveries = 0;
        await Exec("delete from action_approvals where action_id in (select id from rt_actions)");
        deliveries += await Exec("delete from notifications where action_id in (select id from rt_actions) or message_id in (select id from rt_messages)");
        var actions = await Exec("delete from actions where id in (select id from rt_actions)");
        await Exec("delete from message_reactions where message_id in (select id from rt_messages)");
        deliveries += await Exec("delete from webhook_deliveries where message_id in (select id from rt_messages)");
        await Exec("delete from followups where message_id in (select id from rt_messages)");
        await Exec("update followups set posted_message_id = null where posted_message_id in (select id from rt_messages)");
        await Exec("update ti_posts set message_id = null where message_id in (select id from rt_messages)");
        // Sentinel auto-enrichment markers name a board incident (sentinel-auto:<id>, thread incident:<id>): they go
        // with the incident, so no incident-linked row outlives it.
        await Exec("delete from ti_posts where thread_key in (select 'incident:' || id::text from rt_incidents)");
        await Exec("delete from typing where root_id in (select id from rt_messages) or incident_id in (select id from rt_incidents)");
        await Exec("delete from incident_playbooks where incident_id in (select id from rt_incidents)");
        await Exec("update incident_playbooks set root_message_id = null where root_message_id in (select id from rt_messages)");
        // A pinned thread with a post filed under a purged incident keeps the post, without the incident.
        await Exec("update messages set incident_id = null where incident_id in (select id from rt_incidents) and id not in (select id from rt_messages)");
        var messages = await Exec("delete from messages where id in (select id from rt_messages)");
        var purgedIncidents = await Exec("delete from incidents where id in (select id from rt_incidents)");

        // 3. Delivery bookkeeping that outlived its subject.
        deliveries += await Exec("delete from notifications where created_at < @cutoff and status in ('sent', 'failed', 'skipped')");
        deliveries += await Exec("delete from webhook_deliveries where created_at < @cutoff and status in ('sent', 'failed')");
        await Exec("delete from followups where fired_at < @cutoff");

        if (dryRun) await tx.RollbackAsync(ct);
        else await tx.CommitAsync(ct);
        return (purgedIncidents, messages, actions, deliveries, incidents >= BatchSize || roots >= BatchSize);
    }
}
