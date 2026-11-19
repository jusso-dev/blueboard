using System.Text.Json;
using Blueboard.Api.Core;

namespace Blueboard.Api.Data;

/// <summary>Small JSON values in kv_state shared by every instance: cursors, last-run markers, the broker pause.</summary>
public sealed class KvState(Db db)
{
    public const string IngestCursor = "ingest.lastUpdateDateTime";
    public const string IngestLastSuccess = "ingest.lastSuccess";
    public const string IngestLastError = "ingest.lastError";
    public const string BrokerPaused = "broker_paused";
    public const string AuditExportMark = "audit_export.last_id";

    public async Task<T?> GetAsync<T>(string key, CancellationToken ct = default)
    {
        await using var cmd = db.Command("select value::text from kv_state where key = @k").With("k", key);
        return await cmd.ExecuteScalarAsync(ct) is string json ? JsonSerializer.Deserialize<T>(json, Json.Options) : default;
    }

    public async Task SetAsync<T>(string key, T value, CancellationToken ct = default)
    {
        await using var cmd = db.Command("insert into kv_state (key, value) values (@k, @v) on conflict (key) do update set value = excluded.value, updated_at = now()")
            .With("k", key).WithJson("v", value);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
