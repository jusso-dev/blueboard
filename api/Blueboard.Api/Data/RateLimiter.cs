using Blueboard.Api.Actions;
using Blueboard.Api.Core;

namespace Blueboard.Api.Data;

/// <summary>Current state of one principal's bucket, for the participants admin page.</summary>
public sealed record BucketUsage(string Handle, string Kind, string Bucket, int Capacity, int PerSeconds, double Available, DateTimeOffset? LimitedAt);

/// <summary>
/// Per-principal token buckets (issue #5), stored in Postgres so every Function App instance shares them. Taking a
/// token is one atomic upsert: refill by elapsed time, then spend one only if a whole token is available. The board's
/// own system principal is never limited.
/// </summary>
public sealed class RateLimiter(Db db, Audit audit, Policy policy)
{
    /// <summary>Spend one token from <paramref name="bucket"/> or throw a 429 BoardException with Retry-After.</summary>
    public async Task TakeAsync(Principal p, string bucket, CancellationToken ct = default)
    {
        if (p.Kind == "system") return;
        var limit = policy.Limits.For(p.Kind, bucket);
        await using (var cmd = db.Command("""
            insert into rate_buckets as b (principal_id, bucket, tokens, refilled_at) values (@p, @b, @cap - 1, now())
            on conflict (principal_id, bucket) do update
              set tokens = least(@cap, b.tokens + extract(epoch from now() - b.refilled_at) * @rate) - 1, refilled_at = now()
              where least(@cap, b.tokens + extract(epoch from now() - b.refilled_at) * @rate) >= 1
            returning tokens
            """).With("p", p.Id).With("b", bucket).With("cap", (double)limit.Capacity).With("rate", limit.RefillPerSecond))
            if (await cmd.ExecuteScalarAsync(ct) is not null) return;

        // Refused. Work out when the next whole token arrives, and audit at most once a minute per bucket.
        double available;
        bool first;
        await using (var cmd = db.Command("""
            update rate_buckets as b set limited_at = case when b.limited_at is null or b.limited_at < now() - interval '1 minute' then now() else b.limited_at end
            where principal_id = @p and bucket = @b
            returning least(@cap, b.tokens + extract(epoch from now() - b.refilled_at) * @rate), b.limited_at = now()
            """).With("p", p.Id).With("b", bucket).With("cap", (double)limit.Capacity).With("rate", limit.RefillPerSecond))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            await r.ReadAsync(ct);
            available = r.GetDouble(0);
            first = r.GetBoolean(1);
        }
        var retry = RetryAfter(available, limit);
        if (first) await audit.WriteAsync(p.Id, "limit.hit", p.Handle, new { bucket, limit = limit.ToString(), retry_after_s = retry }, ct);
        throw BoardException.RateLimited(bucket, retry);
    }

    /// <summary>Whole seconds until one token is available again (at least 1).</summary>
    public static int RetryAfter(double available, RateLimit limit) =>
        Math.Max(1, (int)Math.Ceiling((1 - available) / limit.RefillPerSecond));

    /// <summary>
    /// Current usage per principal and bucket (only buckets that have been used). For the participants admin page:
    /// pass a principal id for one principal, or null for everyone.
    /// </summary>
    public async Task<IReadOnlyList<BucketUsage>> UsageAsync(Guid? principalId = null, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select p.handle, p.kind, b.bucket, b.tokens, extract(epoch from now() - b.refilled_at)::float8, b.limited_at
            from rate_buckets b join principals p on p.id = b.principal_id
            where @id::uuid is null or b.principal_id = @id
            order by p.handle, b.bucket
            """).With("id", principalId);
        var list = new List<BucketUsage>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            var (kind, bucket) = (r.GetString(1), r.GetString(2));
            if (!Limits.Buckets.Contains(bucket)) continue;
            var limit = policy.Limits.For(kind, bucket);
            var available = Math.Min(limit.Capacity, r.GetDouble(3) + r.GetDouble(4) * limit.RefillPerSecond);
            list.Add(new BucketUsage(r.GetString(0), kind, bucket, limit.Capacity, limit.PerSeconds, Math.Round(available, 2), r.Get<DateTimeOffset?>("limited_at")));
        }
        return list;
    }
}
