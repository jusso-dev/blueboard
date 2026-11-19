using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Core;
using Azure.Identity;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Ops;

/// <summary>
/// Ships new audit_log rows to the BlueboardAudit_CL table in Log Analytics (Microsoft Sentinel) through the Logs
/// Ingestion API, with the Function App's managed identity. A high-water mark (the last audit_log id accepted) lives
/// in kv_state and only moves after Azure Monitor accepts a batch, so rows are never skipped and a batch that was
/// accepted is never sent again. The token goes only to the configured ingestion host, which must be an exact
/// *.ingest.monitor.azure.com https origin. Runs from a timer under the single-runner lock.
/// </summary>
public sealed partial class AuditExporter(HttpClient http, Db db, Settings settings, TokenCredential? credential = null)
{
    private const string Scope = "https://monitor.azure.com//.default";
    private const int BatchRows = 500;
    private const int MaxBytes = 900_000; // the API takes up to 1 MB per call
    private readonly TokenCredential _cred = credential ?? new DefaultAzureCredential();

    public sealed record Mark(long LastId, DateTimeOffset? SentAt = null, string? Error = null, DateTimeOffset? ErrorAt = null);

    [GeneratedRegex(@"^dcr-[0-9a-f]{32}$")] private static partial Regex DcrId();
    [GeneratedRegex(@"^Custom-[A-Za-z0-9_]{1,100}$")] private static partial Regex Stream();

    public bool Enabled => settings.AuditDceEndpoint is not null && settings.AuditDcrId is not null;

    /// <summary>Why this endpoint can't be used, or null. https only, default port, an Azure Monitor ingestion host.</summary>
    public static string? EndpointProblem(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps || !u.IsDefaultPort || u.UserInfo.Length > 0)
            return "AUDIT_DCE_ENDPOINT must be an https URL on the default port";
        if (!u.IdnHost.EndsWith(".ingest.monitor.azure.com", StringComparison.OrdinalIgnoreCase))
            return "AUDIT_DCE_ENDPOINT must be an Azure Monitor logs ingestion host (*.ingest.monitor.azure.com)";
        return null;
    }

    /// <summary>The exact ingestion URL. Public for tests: the token is only ever attached to a URL built here.</summary>
    public static Uri BuildUri(string endpoint, string dcrId, string stream)
    {
        if (EndpointProblem(endpoint) is { } p) throw new InvalidOperationException(p);
        if (!DcrId().IsMatch(dcrId)) throw new InvalidOperationException("AUDIT_DCR_ID must be the rule's immutable id (dcr-<32 hex>)");
        if (!Stream().IsMatch(stream)) throw new InvalidOperationException("AUDIT_STREAM must look like Custom-<Table>_CL");
        var origin = new Uri(endpoint).GetLeftPart(UriPartial.Authority);
        var uri = new Uri($"{origin}/dataCollectionRules/{dcrId}/streams/{stream}?api-version=2023-01-01");
        if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("refusing to send token to another host");
        return uri;
    }

    /// <summary>Sends every row above the mark, in batches. Returns how many rows Azure Monitor accepted.</summary>
    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        if (!Enabled) return 0;
        var uri = BuildUri(settings.AuditDceEndpoint!, settings.AuditDcrId!, settings.AuditStream);
        var kv = new KvState(db);
        var mark = await kv.GetAsync<Mark>(KvState.AuditExportMark, ct) ?? new Mark(0);
        var total = 0;
        for (var round = 0; round < 20; round++)
        {
            var (rows, lastId) = await ReadAsync(mark.LastId, ct);
            if (rows.Count == 0) break;
            try
            {
                await PostAsync(uri, rows, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                await kv.SetAsync(KvState.AuditExportMark, mark with { Error = Notifier.SafeError(ex), ErrorAt = DateTimeOffset.UtcNow }, CancellationToken.None);
                throw;
            }
            mark = new Mark(lastId, DateTimeOffset.UtcNow);
            await kv.SetAsync(KvState.AuditExportMark, mark, CancellationToken.None);
            total += rows.Count;
        }
        return total;
    }

    /// <summary>Rows after the mark, oldest first, capped by count and size. Public for tests.</summary>
    public async Task<(List<Dictionary<string, object?>> Rows, long LastId)> ReadAsync(long after, CancellationToken ct = default)
    {
        await using var cmd = db.Command("""
            select l.id, l.at, l.event, p.handle, p.kind, l.subject, l.detail::text
            from audit_log l left join principals p on p.id = l.actor_id
            where l.id > @after order by l.id limit @n
            """).With("after", after).With("n", BatchRows);
        var rows = new List<Dictionary<string, object?>>();
        long last = after;
        var bytes = 2;
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>
            {
                ["TimeGenerated"] = r.GetFieldValue<DateTimeOffset>(1),
                ["AuditId"] = r.GetInt64(0),
                ["Event"] = r.GetString(2),
                ["Actor"] = r.Get<string>("handle") ?? "board",
                ["ActorKind"] = r.Get<string>("kind") ?? "system",
                ["Subject"] = r.Get<string>("subject"),
                ["Detail"] = r.Get<string>("detail") is { } d ? JsonDocument.Parse(d).RootElement.Clone() : null,
            };
            var size = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(row)) + 1;
            if (rows.Count > 0 && bytes + size > MaxBytes) break;
            bytes += size;
            rows.Add(row);
            last = r.GetInt64(0);
        }
        return (rows, last);
    }

    private async Task PostAsync(Uri uri, List<Dictionary<string, object?>> rows, CancellationToken ct)
    {
        var token = await _cred.GetTokenAsync(new TokenRequestContext([Scope]), ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var req = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            // Column names are PascalCase, as the custom table declares them: plain serialiser, not the snake_case one.
            Content = new StringContent(JsonSerializer.Serialize(rows), Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (!res.IsSuccessStatusCode) throw new HttpRequestException($"logs ingestion returned {(int)res.StatusCode}", null, res.StatusCode);
    }
}
