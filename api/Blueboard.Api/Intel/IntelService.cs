using Blueboard.Contracts;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Blueboard.Api.Intel;

/// <summary>What one source says about a key. Status is found, not_found or not_checked (off, failing, or not allowed).</summary>
public sealed record IntelCard(
    string Source, string Name, string Status, string Attribution, string? Url, DateTimeOffset? RetrievedAt,
    string? Title = null, string? Severity = null, JsonNode? Data = null, string? Reason = null);

public sealed record RelatedIncident(Guid Id, string GraphId, string DisplayName, string Severity, string Status);
public sealed record IntelLookup(string Key, string Kind, IReadOnlyList<IntelCard> Cards, IReadOnlyList<string> Agree, IReadOnlyList<string> Differ,
    IReadOnlyList<RelatedIncident> Incidents, IReadOnlyList<Message> Messages, DateTimeOffset CheckedAt);

public sealed record CveExposure(string Cve, int Devices, IReadOnlyList<string> DeviceNames, IReadOnlyList<string> Software, string? Severity,
    IReadOnlyList<string> Remediation, int InOpenIncidents, DateTimeOffset RetrievedAt, long AgeSeconds);

public sealed record CveBadge(string Cve, bool KnownExploited, string? DueDate, bool Ransomware, double? Epss, double? Percentile);

/// <summary>
/// Threat intel and CVE feeds (issues #15 to #21): scheduled feed ingest, on-demand lookups with per-source caching,
/// one card per source, agree / differ, watchlist posts to #intel, Defender exposure and Sentinel TI checks.
/// Everything outside the tenant is untrusted text: it is stored, shown and quoted, never treated as instructions.
/// </summary>
public sealed partial class IntelService(
    Db db, IntelStore store, TiFetcher fetcher, MicrosoftIntel microsoft, BoardService board, Search search,
    SystemPrincipal system, Settings settings, ILogger<IntelService> log)
{
    private TiSettings Ti => settings.Ti;
    private static readonly TimeSpan Day = TimeSpan.FromHours(24);
    private const int MaxPostsPerRun = 20;

    private static readonly FetchPolicy PwnPolicy = new(Sources.PwnWatch, ["pwn.watch"], TimeSpan.FromHours(1));
    private static readonly FetchPolicy PwnSlowPolicy = PwnPolicy with { MinTtl = TimeSpan.FromHours(6) };
    private static readonly FetchPolicy KevPolicy = new(Sources.Kev, ["www.cisa.gov"], TimeSpan.FromHours(6));
    private static readonly FetchPolicy EpssPolicy = new(Sources.Epss, ["api.first.org"], Day);
    private static readonly FetchPolicy NvdPolicy = new(Sources.Nvd, ["services.nvd.nist.gov"], Day);
    private static readonly FetchPolicy OsvPolicy = new(Sources.Osv, ["api.osv.dev"], Day);
    private static readonly FetchPolicy CveWatchPolicy = new(Sources.CveWatch, ["cve.watch", "www.cve.watch"], TimeSpan.FromMinutes(1));

    // ── scheduled runs ──────────────────────────────────────────────────────────────────────────

    /// <summary>Every 15 minutes: feeds whose TTL has passed. Each source is isolated: one failing never stops another.</summary>
    public async Task<object> RunFeedsAsync(CancellationToken ct = default)
    {
        await store.SyncSourcesAsync(Ti, ct);
        var results = new Dictionary<string, string>();
        if (Ti.PwnWatch) results[Sources.PwnWatch] = await Guarded(Sources.PwnWatch, () => RunPwnWatchAsync(ct), ct);
        if (Ti.Kev) results[Sources.Kev] = await Guarded(Sources.Kev, () => RunKevAsync(ct), ct);
        return results;
    }

    /// <summary>Daily: the EPSS batch and automatic watches from Defender inventory.</summary>
    public async Task<object> RunDailyAsync(CancellationToken ct = default)
    {
        await store.SyncSourcesAsync(Ti, ct);
        var results = new Dictionary<string, string>();
        if (Ti.Epss) results[Sources.Epss] = await Guarded(Sources.Epss, async () => $"{(await EpssDailyAsync(ct)).Requests} request(s)", ct);
        if (Ti.Exposure) results["inventory"] = await Guarded(Sources.Exposure, async () => $"{await RefreshInventoryWatchesAsync(ct)} inventory watch(es)", ct);
        return results;
    }

    /// <summary>Monthly: is cve.watch still unavailable? A HEAD request; only the status is recorded.</summary>
    public async Task<string> RecheckCveWatchAsync(CancellationToken ct = default)
    {
        string status;
        try
        {
            var apex = await fetcher.HeadAsync(CveWatchPolicy, "https://cve.watch/", TimeSpan.FromSeconds(15), ct);
            status = $"apex answered HTTP {apex}: review docs/ti/sources.md before integrating";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TiFetchException)
        {
            status = "apex did not answer";
        }
        await store.SetStatusAsync(Sources.CveWatch, "unavailable", $"Re-checked {DateTimeOffset.UtcNow:dd-MM-yyyy}: {status}. Still not integrated.", null, ct);
        return status;
    }

    private async Task<string> Guarded(string source, Func<Task<string>> run, CancellationToken ct)
    {
        try
        {
            return await run();
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            var msg = ex is TiFetchException or BoardException or JsonException ? ex.Message : $"{ex.GetType().Name}: {ex.Message}";
            log.LogWarning(ex, "threat intel source {Source} failed", source);
            await store.SetStatusAsync(source, "error", msg, null, CancellationToken.None);
            return $"error: {msg}";
        }
    }

    /// <summary>True when the body differs from the one parsed last time (a cache hit or 304 returns the same body).</summary>
    private async Task<bool> ChangedAsync(string name, string body, CancellationToken ct)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        await using var cmd = db.Command("""
            insert into kv_state (key, value) values (@k, @v) on conflict (key) do update set value = excluded.value, updated_at = now()
            where kv_state.value is distinct from excluded.value
            """).With("k", $"ti.parsed.{name}").WithJson("v", hash);
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    private async Task<bool> FlagAsync(string key, CancellationToken ct)
    {
        await using var cmd = db.Command("select 1 from kv_state where key = @k").With("k", key);
        return await cmd.ExecuteScalarAsync(ct) is not null;
    }

    private async Task SetFlagAsync(string key, CancellationToken ct)
    {
        await using var cmd = db.Command("insert into kv_state (key, value) values (@k, 'true') on conflict (key) do nothing").With("k", key);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ── pwn.watch (#16) ─────────────────────────────────────────────────────────────────────────

    public async Task<string> RunPwnWatchAsync(CancellationToken ct = default)
    {
        var changes = await fetcher.GetAsync(PwnPolicy, PwnWatchParser.ChangesUrl, "pwnwatch/changes.json", ct: ct);
        var incidents = await fetcher.GetAsync(PwnSlowPolicy, PwnWatchParser.IncidentsUrl, "pwnwatch/incidents.json", ct: ct);
        var tags = await fetcher.GetAsync(PwnSlowPolicy, PwnWatchParser.TagsUrl, "pwnwatch/tags.json", ct: ct);
        var skipped = 0;
        var notes = new List<string>();
        IReadOnlySet<string> newIncidents = new HashSet<string>();
        var parsed = await ChangedAsync("pwnwatch.incidents", incidents.Body, ct);
        DateTimeOffset? asOf = null;
        if (parsed)
        {
            var r = PwnWatchParser.Incidents(incidents.Body, incidents.FetchedAt);
            skipped += r.Skipped;
            asOf = r.DataAsOf;
            newIncidents = await store.UpsertManyAsync(r.Records, ct);
            notes.Add($"{r.Records.Count} incidents");
        }
        if (await ChangedAsync("pwnwatch.tags", tags.Body, ct))
        {
            var (list, sk) = PwnWatchParser.Tags(tags.Body);
            skipped += sk;
            await using var cmd = db.Command("insert into kv_state (key, value) values ('ti.pwnwatch.tags', @v) on conflict (key) do update set value = excluded.value, updated_at = now()")
                .WithJson("v", list.OrderByDescending(t => t.Incidents).Take(300).Select(t => new { id = t.Id, label = t.Label, incidents = t.Incidents }));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        var baseline = !await FlagAsync("ti.pwnwatch.baseline", ct);
        if (await ChangedAsync("pwnwatch.changes", changes.Body, ct) || parsed)
        {
            var (list, sk) = PwnWatchParser.Changes(changes.Body);
            skipped += sk;
            var (posted, more) = await PostPwnChangesAsync(list, baseline, ct);
            notes.Add(baseline ? $"baseline of {list.Count} changes (nothing posted on the first run)" : $"{posted} post(s) to #intel");
            if (more)
            {
                // Over the per-run cap: forget the parse marker so the next run picks up the rest from the cached body.
                await using var forget = db.Command("delete from kv_state where key = 'ti.parsed.pwnwatch.changes'");
                await forget.ExecuteNonQueryAsync(ct);
                notes.Add("more next run");
            }
            if (baseline) await SetFlagAsync("ti.pwnwatch.baseline", ct);
        }
        if (!baseline && newIncidents.Count > 0) notes.Add($"{await PostExposedAsync(Sources.PwnWatch, newIncidents, ct)} exposure post(s)");
        await store.SetStatusAsync(Sources.PwnWatch, "ok", skipped > 0 ? $"skipped {skipped} malformed item(s)" : null, asOf, ct);
        return notes.Count > 0 ? string.Join("; ", notes) : "up to date (cached)";
    }

    /// <summary>
    /// One #intel finding per new change to a watched incident, threaded per incident, idempotent on the change hash.
    /// The first run only records what already exists, so switching the source on doesn't flood the channel.
    /// </summary>
    internal async Task<(int Posted, bool More)> PostPwnChangesAsync(IReadOnlyList<PwnChange> changes, bool baseline, CancellationToken ct)
    {
        var seen = new HashSet<string>();
        await using (var sc = db.Command("select hash from ti_posts where hash = any(@h)").With("h", changes.Select(c => c.Hash).ToArray()))
        await using (var sr = await sc.ExecuteReaderAsync(ct))
            while (await sr.ReadAsync(ct)) seen.Add(sr.GetString(0));
        changes = changes.Where(c => !seen.Contains(c.Hash)).DistinctBy(c => c.Hash).ToList();
        var watches = await store.WatchesAsync(enabledOnly: true, ct);
        var bySlug = (await store.GetManyAsync(Sources.PwnWatch, changes.Select(c => c.Incident).Distinct().ToList(), ct)).ToDictionary(r => r.Key);
        var posted = 0;
        var more = false;
        var silent = new List<PwnChange>();
        // Oldest first, so a thread reads in order.
        foreach (var c in changes.Reverse())
        {
            // A change for an incident the store hasn't loaded yet waits: incidents.json refreshes less often than changes.json.
            if (!baseline && !bySlug.ContainsKey(c.Incident)) continue;
            var watched = !baseline ? Watches.Matching(watches, Watchable(bySlug[c.Incident])) : [];
            if (watched.Count == 0) { silent.Add(c); continue; }
            if (posted >= MaxPostsPerRun) { more = true; continue; } // left for the next run
            var r = bySlug[c.Incident];
            if (await PostOnceAsync(c.Hash, $"pwn:{c.Incident}", PwnBody(c, r, watched), new JsonObject
                {
                    ["source"] = Sources.PwnWatch, ["url"] = r.Url, ["retrieved_at"] = r.RetrievedAt.ToString("O"), ["slug"] = c.Incident,
                    ["cve_ids"] = JsonNode.Parse(r.Data.GetProperty("cve_ids").GetRawText()), ["watches"] = J.Array(watched),
                }, ct)) posted++;
        }
        if (silent.Count > 0)
        {
            await using var cmd = db.Command("""
                insert into ti_posts (hash, thread_key) select x.hash, x.thread_key from jsonb_to_recordset(@rows) as x(hash text, thread_key text)
                on conflict do nothing
                """).WithJson("rows", silent.Select(c => new { hash = c.Hash, thread_key = $"pwn:{c.Incident}" }));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        return (posted, more);
    }

    private static Watchable Watchable(StoredRecord r)
    {
        var d = r.Data;
        IReadOnlyCollection<string> Arr(string k) => d.TryGetProperty(k, out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Select(x => x.GetString()).OfType<string>().ToList() : [];
        var product = d.TryGetProperty("product", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString()! : "";
        var summary = d.TryGetProperty("summary", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString()! : "";
        return new Watchable(r.Title ?? "", summary, Arr("tags"), Arr("cve_ids"), product.Length > 0 ? [product] : []);
    }

    private static string PwnBody(PwnChange c, StoredRecord r, IReadOnlyList<string> watched)
    {
        var d = r.Data;
        string? S(string k) => d.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        IEnumerable<string> A(string k) => d.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Select(x => x.GetString()).OfType<string>() : [];
        var fixedV = A("fixed_versions").Take(5).Select(Clean).ToList();
        var cves = A("cve_ids").Take(10).ToList();
        var sb = new StringBuilder();
        sb.Append($"**pwn.watch:** {Clean(r.Title ?? c.Incident)}\n\n");
        sb.Append($"> {Clean(c.Title)}{(c.Date is null ? "" : $" ({Clean(c.Date)})")}\n\n");
        sb.Append($"- Severity: {Clean(S("severity") ?? "unknown")} · Patch status: {Clean(S("patch_status") ?? "unknown")}\n");
        if (fixedV.Count > 0) sb.Append($"- Fixed versions: {string.Join("; ", fixedV)}\n");
        if (cves.Count > 0) sb.Append($"- CVEs: {string.Join(", ", cves)}\n");
        sb.Append($"- Watched: {string.Join(", ", watched)}\n\n");
        if (r.Url is { } url) sb.Append($"[Open on pwn.watch]({url})\n\n");
        sb.Append("Source: pwn.watch");
        return sb.ToString();
    }

    // ── CISA KEV (#17) ──────────────────────────────────────────────────────────────────────────

    public async Task<string> RunKevAsync(CancellationToken ct = default)
    {
        var res = await fetcher.GetAsync(KevPolicy, KevParser.Url, "kev.json", ct: ct);
        if (!await ChangedAsync("kev", res.Body, ct))
        {
            await store.SetStatusAsync(Sources.Kev, "ok", null, null, ct);
            return "up to date (cached)";
        }
        var baseline = await store.CountAsync(Sources.Kev, ct) == 0;
        var r = KevParser.Parse(res.Body, res.FetchedAt);
        var created = await store.UpsertManyAsync(r.Records, ct);
        var note = $"{r.Records.Count} CVEs, {created.Count} new";
        if (!baseline && created.Count > 0) note += $"; {await PostExposedAsync(Sources.Kev, created, ct)} exposure post(s)";
        await store.SetStatusAsync(Sources.Kev, "ok", r.Skipped > 0 ? $"skipped {r.Skipped} malformed item(s)" : null, r.DataAsOf, ct);
        return note;
    }

    /// <summary>
    /// New KEV CVEs or new pwn.watch incidents that are present in Defender inventory: one #intel finding each
    /// (issues #17, #18), with counts and a link, mentioning nobody. Needs TI_EXPOSURE_ENABLED.
    /// </summary>
    private async Task<int> PostExposedAsync(string source, IReadOnlySet<string> keys, CancellationToken ct)
    {
        if (!Ti.Exposure || keys.Count == 0) return 0;
        var records = await store.GetManyAsync(source, keys.Take(200).ToList(), ct);
        var cvesOf = records.ToDictionary(r => r.Key, r => source == Sources.Kev ? [r.Key] : Watchable(r).Cves.ToList());
        var all = cvesOf.Values.SelectMany(x => x).Distinct().Take(Kql.MaxValues).ToList();
        if (all.Count == 0) return 0;
        var exposure = (await ExposureAsync(null, all, ct)).ToDictionary(e => e.Cve);
        var posted = 0;
        foreach (var r in records)
        {
            var hits = cvesOf[r.Key].Select(c => exposure.GetValueOrDefault(c)).OfType<CveExposure>().Where(e => e.Devices > 0).ToList();
            if (hits.Count == 0 || posted >= MaxPostsPerRun) continue;
            var label = source == Sources.Kev ? "Newly added to CISA KEV" : "New on pwn.watch";
            var body = new StringBuilder($"**{label} and present in this tenant:** {Clean(r.Title ?? r.Key)}\n\n");
            foreach (var e in hits)
                body.Append($"- {e.Cve}: present on {e.Devices} device(s) ({e.InOpenIncidents} in open incidents)"
                            + (e.Software.Count > 0 ? $", e.g. {Clean(e.Software[0])}" : "") + "\n");
            if (r.Url is { } url) body.Append($"\n[Open the source record]({url})\n");
            body.Append($"\n{Sources.Get(source).Attribution} · {Sources.Get(Sources.Exposure).Attribution}");
            if (await PostOnceAsync($"exposed:{source}:{r.Key}", $"exposed:{source}:{r.Key}", body.ToString(), new JsonObject
                {
                    ["source"] = source, ["url"] = r.Url, ["retrieved_at"] = r.RetrievedAt.ToString("O"),
                    ["cve_ids"] = J.Array(hits.Select(h => h.Cve)), ["devices"] = hits.Sum(h => h.Devices),
                }, ct)) posted++;
        }
        return posted;
    }

    /// <summary>Posts a board finding in #intel at most once per hash, replying to the thread for threadKey if one exists.</summary>
    private async Task<bool> PostOnceAsync(string hash, string threadKey, string body, JsonObject payload, CancellationToken ct, string channel = "intel", Guid? parent = null, string? incident = null)
    {
        var sys = await system.GetAsync(ct);
        var root = parent ?? await store.ThreadRootAsync(threadKey, ct);
        await using var conn = await db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await using (var claim = new NpgsqlCommand("insert into ti_posts (hash, thread_key) values (@h, @t) on conflict do nothing", conn, tx).With("h", hash).With("t", threadKey))
            if (await claim.ExecuteNonQueryAsync(ct) == 0) { await tx.RollbackAsync(ct); return false; }
        var id = await board.PostInTransactionAsync(conn, tx, sys,
            new PostInput(channel, body.Length > 19000 ? body[..19000] : body, "finding", Json.Element(payload), root, incident), system: true, ct);
        await using (var set = new NpgsqlCommand("update ti_posts set message_id = @m where hash = @h", conn, tx).With("m", id).With("h", hash))
            await set.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
        return true;
    }

    [GeneratedRegex(@"\s+")] private static partial Regex Spaces();

    /// <summary>Outside text going into a board message: one line, capped, and unable to @mention anyone.</summary>
    internal static string Clean(string s)
    {
        var one = Spaces().Replace(s, " ").Trim();
        if (one.Length > 400) one = one[..400] + "…";
        return one.Replace("@", "@\u200b").Replace("`", "'");
    }

    // ── FIRST EPSS (#17) ────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// EPSS for these CVEs: from the store when retrieved in the last 24 hours, otherwise fetched in batches of 100.
    /// Returns the records and how many requests were made.
    /// </summary>
    public async Task<(IReadOnlyDictionary<string, StoredRecord> Records, int Requests)> EpssAsync(IEnumerable<string> cveIds, CancellationToken ct = default)
    {
        var cves = cveIds.Select(Indicators.NormaliseCve).OfType<string>().Distinct().ToList();
        var have = (await store.GetManyAsync(Sources.Epss, cves, ct)).ToDictionary(r => r.Key);
        var stale = cves.Where(c => !have.TryGetValue(c, out var r) || DateTimeOffset.UtcNow - r.RetrievedAt > Day).ToList();
        var requests = 0;
        foreach (var batch in stale.Chunk(EpssParser.BatchSize))
        {
            if (await store.TryTakeAsync("epss", 60, TimeSpan.FromMinutes(1), ct) is not null) throw new TiFetchException("FIRST EPSS: local request budget used up, try again in a minute");
            var url = EpssParser.Url(batch);
            var res = await fetcher.GetAsync(EpssPolicy, url, "epss.json", ct: ct);
            requests++;
            await store.UpsertManyAsync(EpssParser.Parse(res.Body, batch, url, res.FetchedAt), ct);
        }
        if (requests > 0)
        {
            await store.SetStatusAsync(Sources.Epss, "ok", null, null, ct);
            foreach (var r in await store.GetManyAsync(Sources.Epss, stale, ct)) have[r.Key] = r;
        }
        return (have, requests);
    }

    /// <summary>
    /// The daily batch, kept small on purpose (FIRST says the API is for lookups, not for mirroring every score):
    /// CVEs mentioned on the board in the last 30 days plus those on the newest pwn.watch and KEV records, at most 500.
    /// </summary>
    public async Task<(int Cves, int Requests)> EpssDailyAsync(CancellationToken ct = default)
    {
        var cves = new List<string>();
        await using (var cmd = db.Command("select body from messages where created_at > now() - interval '30 days' and body ~* 'CVE-[0-9]{4}-[0-9]{4,}' order by seq desc limit 2000"))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) cves.AddRange(Indicators.CvesIn(r.GetString(0)));
        foreach (var rec in await store.RecentAsync([Sources.PwnWatch, Sources.Kev], 200, ct))
            cves.AddRange(rec.Source == Sources.Kev ? [rec.Key] : Watchable(rec).Cves);
        var list = cves.Distinct().Take(500).ToList();
        var (_, requests) = await EpssAsync(list, ct);
        return (list.Count, requests);
    }

    // ── on-demand sources: NVD, OSV (#21) ──────────────────────────────────────────────────────

    public async Task<StoredRecord> NvdAsync(string cve, CancellationToken ct = default)
    {
        if (await store.GetAsync(Sources.Nvd, cve, ct) is { } cached && DateTimeOffset.UtcNow - cached.RetrievedAt < Day) return cached;
        // NVD: 5 requests per rolling 30 seconds without a key, 50 with one. The budget is shared across instances.
        var limit = Ti.NvdApiKey is null ? 5 : 50;
        if (await store.TryTakeAsync("nvd", limit, TimeSpan.FromSeconds(30), ct) is { } wait)
        {
            if (wait > TimeSpan.FromSeconds(8)) throw new TiFetchException($"NVD rate limit ({limit} per 30 s) reached, try again in {Math.Ceiling(wait.TotalSeconds)} s");
            await Task.Delay(wait, ct);
            if (await store.TryTakeAsync("nvd", limit, TimeSpan.FromSeconds(30), ct) is not null) throw new TiFetchException($"NVD rate limit ({limit} per 30 s) reached, try again shortly");
        }
        var headers = Ti.NvdApiKey is { } key ? new Dictionary<string, string> { ["apiKey"] = key } : null;
        TiRecord rec;
        try
        {
            var res = await fetcher.GetAsync(NvdPolicy, NvdParser.Url(cve), $"nvd/{cve}.json", headers, ct);
            rec = NvdParser.Parse(res.Body, cve, res.FetchedAt);
        }
        catch (TiFetchException ex) when (ex.Status == 404)
        {
            rec = NvdParser.Parse("{}", cve, DateTimeOffset.UtcNow);
        }
        await store.UpsertManyAsync([rec], ct);
        await store.SetStatusAsync(Sources.Nvd, "ok", null, null, ct);
        return (await store.GetAsync(Sources.Nvd, cve, ct))!;
    }

    public async Task<StoredRecord> OsvAsync(string id, CancellationToken ct = default)
    {
        if (await store.GetAsync(Sources.Osv, id, ct) is { } cached && DateTimeOffset.UtcNow - cached.RetrievedAt < Day) return cached;
        var rec = await OsvFetchAsync(id, ct);
        // A CVE record often lists only git commits; its GHSA alias names the package and the fixed versions.
        if (rec.Found && !OsvParser.HasFixedPackages(rec) && rec.Data["aliases"] is JsonArray aliases
            && aliases.Select(a => a?.GetValue<string>()).FirstOrDefault(a => a?.StartsWith("GHSA-", StringComparison.Ordinal) == true) is { } ghsa
            && Indicators.Normalise("ghsa", ghsa) is { } g)
        {
            var alias = await OsvFetchAsync(g, ct);
            if (alias.Found)
            {
                rec.Data["packages"] = alias.Data["packages"]!.DeepClone();
                rec.Data["packages_from"] = g;
                rec = rec with { Keys = rec.Keys.Append(("ghsa", g)).ToList() };
            }
        }
        await store.UpsertManyAsync([rec], ct);
        await store.SetStatusAsync(Sources.Osv, "ok", null, null, ct);
        return (await store.GetAsync(Sources.Osv, id, ct))!;
    }

    private async Task<TiRecord> OsvFetchAsync(string id, CancellationToken ct)
    {
        try
        {
            var res = await fetcher.GetAsync(OsvPolicy, OsvParser.Url(id), $"osv/{id}.json", ct: ct);
            return OsvParser.Parse(res.Body, id, res.FetchedAt);
        }
        catch (TiFetchException ex) when (ex.Status == 404)
        {
            return OsvParser.NotFound(id, DateTimeOffset.UtcNow);
        }
    }

    // ── tenant sources: exposure (#18), Sentinel TI and Microsoft TI (#19) ───────────────────────

    /// <summary>
    /// "Are we exposed?" for up to 100 CVEs, one KQL query over DeviceTvmSoftwareVulnerabilities, cached 6 hours per CVE.
    /// actor is the person or agent asking (audited), or null for scheduled checks. A read: it never triggers an action.
    /// </summary>
    public async Task<IReadOnlyList<CveExposure>> ExposureAsync(Principal? actor, IEnumerable<string> cveIds, CancellationToken ct = default)
    {
        if (!Ti.Exposure) throw new BoardException("exposure checks are off: set TI_EXPOSURE_ENABLED=true");
        if (Ti.ExposureSource == "api") throw new BoardException("TI_EXPOSURE_SOURCE=api is not implemented yet: use kql (no extra permission)");
        actor?.Require(Roles.Hunter);
        var cves = Kql.ValidCves(cveIds);
        var have = (await store.GetManyAsync(Sources.Exposure, cves, ct)).ToDictionary(r => r.Key);
        var stale = cves.Where(c => !have.TryGetValue(c, out var r) || DateTimeOffset.UtcNow - r.RetrievedAt > TimeSpan.FromHours(6)).ToList();
        if (stale.Count > 0)
        {
            await TakeHuntingBudgetAsync(ct);
            var rows = MicrosoftIntel.ExposureRows(Filter(await microsoft.HuntAsync(actor?.Id, "ti.exposure", Kql.Exposure(stale), "exposure/vulnerabilities.json",
                new { cves = stale }, ct), "CveId", stale)).ToDictionary(r => r.Cve);
            var now = DateTimeOffset.UtcNow;
            await store.UpsertManyAsync(stale.Select(c =>
            {
                var row = rows.GetValueOrDefault(c);
                return new TiRecord(Sources.Exposure, c, "exposure", null, row?.Severity, null, "advanced hunting: DeviceTvmSoftwareVulnerabilities",
                    new JsonObject
                    {
                        ["devices"] = row?.Devices ?? 0, ["device_ids"] = J.Array(row?.DeviceIds ?? []), ["device_names"] = J.Array(row?.DeviceNames ?? []),
                        ["software"] = J.Array(row?.Software ?? []), ["remediation"] = J.Array(row?.Remediation ?? []),
                    }, null, null, now, [("cve", c)], Found: row is { Devices: > 0 });
            }).ToList(), ct);
            await store.SetStatusAsync(Sources.Exposure, "ok", null, null, ct);
            foreach (var r in await store.GetManyAsync(Sources.Exposure, stale, ct)) have[r.Key] = r;
        }
        var open = await OpenIncidentDevicesAsync(ct);
        return cves.Where(have.ContainsKey).Select(c =>
        {
            var d = have[c].Data;
            List<string> A(string k) => d.TryGetProperty(k, out var a) && a.ValueKind == JsonValueKind.Array ? a.EnumerateArray().Select(x => x.GetString()).OfType<string>().ToList() : [];
            var ids = A("device_ids");
            var names = A("device_names");
            var inOpen = ids.Count(open.Contains) + names.Count(n => !ids.Any() && (open.Contains(n) || open.Contains(n.Split('.')[0])));
            return new CveExposure(c, d.TryGetProperty("devices", out var n) && n.ValueKind == JsonValueKind.Number ? n.GetInt32() : 0, names, A("software"),
                have[c].Severity, A("remediation"), inOpen, have[c].RetrievedAt, (long)(DateTimeOffset.UtcNow - have[c].RetrievedAt).TotalSeconds);
        }).ToList();
    }

    /// <summary>Advanced hunting quota is shared with analysts and agents: board-built queries take at most 20 a minute.</summary>
    private async Task TakeHuntingBudgetAsync(CancellationToken ct)
    {
        if (await store.TryTakeAsync("hunting", 20, TimeSpan.FromMinutes(1), ct) is { } wait)
            throw new BoardException($"threat intel hunting budget used up (20 queries a minute), try again in {Math.Ceiling(wait.TotalSeconds)} s", 429);
    }

    /// <summary>Fixture rows stand in for any query, so keep only the ones for the values asked about.</summary>
    private IEnumerable<JsonElement> Filter(IEnumerable<JsonElement> rows, string column, IEnumerable<string> values)
    {
        if (Ti.FixturesDir is null) return rows;
        var set = values.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return rows.Where(r => J.Str(r, column) is { } v && set.Contains(v));
    }

    private async Task<HashSet<string>> OpenIncidentDevicesAsync(CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var cmd = db.Command("select data::text from incidents where lower(status) not in ('resolved', 'redirected') order by coalesce(updated_at_src, first_seen_at) desc limit 500");
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            foreach (var d in Entities.Extract(JsonDocument.Parse(r.GetString(0)).RootElement).Devices)
            {
                if (d.MdeDeviceId is { } id) set.Add(id);
                if (d.Name is { } n) { set.Add(n); set.Add(n.Split('.')[0]); }
            }
        return set;
    }

    /// <summary>Sentinel TI matches for up to 100 indicators, one KQL query, cached 1 hour per indicator.</summary>
    public async Task<IReadOnlyDictionary<string, StoredRecord>> SentinelAsync(Guid? actor, IReadOnlyList<IntelKey> keys, CancellationToken ct = default)
    {
        var valid = keys.Where(k => k.Kind != "cve" && k.Kind != "ghsa").DistinctBy(k => $"{k.Kind}:{k.Value}").Take(Kql.MaxValues).ToList();
        var ids = valid.Select(k => $"{k.Kind}:{k.Value}").ToList();
        var have = (await store.GetManyAsync(Sources.Sentinel, ids, ct)).ToDictionary(r => r.Key);
        var stale = valid.Where(k => !have.TryGetValue($"{k.Kind}:{k.Value}", out var r) || DateTimeOffset.UtcNow - r.RetrievedAt > TimeSpan.FromHours(1)).ToList();
        if (stale.Count > 0)
        {
            await TakeHuntingBudgetAsync(ct);
            var rows = Filter(await microsoft.HuntAsync(actor, "ti.sentinel", Kql.SentinelIndicators(stale), "sentinel/indicators.json",
                new { indicators = stale.Count }, ct), "ObservableValue", stale.Select(k => k.Value)).ToList();
            var now = DateTimeOffset.UtcNow;
            await store.UpsertManyAsync(stale.Select(k =>
            {
                var mine = rows.Where(r => string.Equals(J.Str(r, "ObservableValue"), k.Value, StringComparison.OrdinalIgnoreCase)).ToList();
                var matches = MicrosoftIntel.SentinelMatches(mine);
                var best = mine.Select(r => J.Num(r, "Confidence")).Max();
                return new TiRecord(Sources.Sentinel, $"{k.Kind}:{k.Value}", "indicator", mine.Count > 0 ? $"{mine.Count} active indicator(s)" : null,
                    null, null, "advanced hunting: ThreatIntelIndicators", new JsonObject { ["matches"] = matches, ["best_confidence"] = best },
                    null, null, now, [(k.Kind, k.Value)], Found: mine.Count > 0);
            }).ToList(), ct);
            await store.SetStatusAsync(Sources.Sentinel, "ok", null, null, ct);
            foreach (var r in await store.GetManyAsync(Sources.Sentinel, stale.Select(k => $"{k.Kind}:{k.Value}").ToList(), ct)) have[r.Key] = r;
        }
        return have;
    }

    /// <summary>Microsoft Threat Intelligence: vulnerability profile for a CVE, host reputation for an IP, domain or URL host. Cached 24 hours.</summary>
    public async Task<StoredRecord> MstiAsync(IntelKey key, CancellationToken ct = default)
    {
        var host = key.Kind == "url" ? new Uri(key.Value).Host.ToLowerInvariant() : key.Value;
        var cacheKey = key.IsCve ? key.Value : $"host:{host}";
        if (await store.GetAsync(Sources.Msti, cacheKey, ct) is { } cached && DateTimeOffset.UtcNow - cached.RetrievedAt < Day) return cached;
        if (!key.IsCve && Indicators.Normalise("domain", host) is null && Indicators.Normalise("ip", host) is null) throw new BoardException("invalid host");
        JsonObject data;
        bool found;
        string? severity = null;
        string url;
        if (key.IsCve)
        {
            var v = await microsoft.MstiAsync($"vulnerabilities/{key.Value}", $"vulnerability-{key.Value}.json", ct);
            found = v is not null;
            data = v is { } x ? MicrosoftIntel.MstiVulnerability(x) : new JsonObject();
            severity = found ? data["severity"]?.GetValue<string>() : null;
            if (found)
            {
                var arts = await microsoft.MstiAsync($"vulnerabilities/{key.Value}/articles?$top=5&$select=id,title,createdDateTime", $"vulnerability-{key.Value}-articles.json", ct);
                data["articles"] = new JsonArray(J.Arr(arts ?? default, "value").Take(5).Select(a => (JsonNode?)new JsonObject
                {
                    ["id"] = J.Str(a, "id"), ["title"] = J.Cap(J.Str(a, "title"), 300), ["created"] = J.Str(a, "createdDateTime"),
                }).ToArray());
            }
            url = $"https://security.microsoft.com/intel-explorer/cves/{key.Value}";
        }
        else
        {
            var r = await microsoft.MstiAsync($"hosts/{Uri.EscapeDataString(host)}/reputation", $"reputation-{host}.json", ct);
            found = r is not null;
            data = r is { } x ? MicrosoftIntel.MstiReputation(x) : new JsonObject();
            severity = data["classification"]?.GetValue<string>();
            url = "https://security.microsoft.com/threatintelligence";
        }
        data["host"] = key.IsCve ? null : host;
        await store.UpsertManyAsync([new TiRecord(Sources.Msti, cacheKey, key.IsCve ? "cve" : "indicator", null, severity, url,
            "https://graph.microsoft.com/v1.0/security/threatIntelligence", data, null, null, DateTimeOffset.UtcNow, [(key.Kind, key.Value)], found)], ct);
        await store.SetStatusAsync(Sources.Msti, "ok", null, null, ct);
        return (await store.GetAsync(Sources.Msti, cacheKey, ct))!;
    }

    /// <summary>
    /// After incident ingest: check each new incident's indicators against Sentinel TI once, and post one finding in the
    /// incident's thread only if something matched. Separate from ingest, so a failure here never stops Defender ingest.
    /// </summary>
    public async Task<int> AutoEnrichSentinelAsync(CancellationToken ct = default)
    {
        if (!Ti.Sentinel) return 0;
        var todo = new List<(Guid Id, string GraphId, JsonElement Data)>();
        await using (var cmd = db.Command("""
            select i.id, i.graph_id, i.data::text from incidents i
            where i.first_seen_at > now() - interval '1 day' and not exists (select 1 from ti_posts p where p.hash = 'sentinel-auto:' || i.id::text)
            order by i.first_seen_at limit 10
            """))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) todo.Add((r.GetGuid(0), r.GetString(1), JsonDocument.Parse(r.GetString(2)).RootElement.Clone()));
        var posted = 0;
        foreach (var (id, graphId, data) in todo)
        {
            var keys = IndicatorsOf(Entities.Extract(data));
            var matches = keys.Count == 0 ? [] : (await SentinelAsync(null, keys, ct)).Values.Where(r => r.Found).ToList();
            if (matches.Count == 0)
            {
                await store.ClaimPostAsync($"sentinel-auto:{id}", $"incident:{id}", ct);
                continue;
            }
            Guid? root;
            await using (var rc = db.Command("""
                select m.id from messages m join channels c on c.id = m.channel_id
                where m.incident_id = @i and m.type = 'incident' and m.parent_id is null and c.name = 'incidents' order by m.seq limit 1
                """).With("i", id))
                root = await rc.ExecuteScalarAsync(ct) as Guid?;
            var body = new StringBuilder($"**Sentinel threat intelligence matches** for incident {graphId}:\n\n");
            foreach (var m in matches.Take(20))
            {
                var first = m.Data.GetProperty("matches").EnumerateArray().FirstOrDefault();
                body.Append($"- `{Clean(m.Key)}`: confidence {Num(first, "confidence")}, source {Clean(J.Str(first, "source_system") ?? "unknown")}"
                            + (J.Str(first, "name") is { } n ? $", \"{Clean(n)}\"" : "") + "\n");
            }
            body.Append($"\nRetrieved {DateTimeOffset.UtcNow:dd-MM-yyyy HH:mm} UTC. {Sources.Get(Sources.Sentinel).Attribution}");
            if (await PostOnceAsync($"sentinel-auto:{id}", $"incident:{id}", body.ToString(), new JsonObject
                {
                    ["source"] = Sources.Sentinel, ["retrieved_at"] = DateTimeOffset.UtcNow.ToString("O"), ["matches"] = J.Array(matches.Select(m => m.Key)),
                }, ct, channel: "incidents", parent: root, incident: id.ToString())) posted++;
        }
        return posted;
    }

    private static string Num(JsonElement e, string k) => J.Num(e, k) is { } d ? d.ToString("0", System.Globalization.CultureInfo.InvariantCulture) : "unknown";

    internal static List<IntelKey> IndicatorsOf(IncidentEntities e)
    {
        var raw = e.Ips.Select(v => ("ip", v)).Concat(e.Urls.Select(v => ("url", v))).Concat(e.Domains.Select(v => ("domain", v)))
            .Concat(e.Files.SelectMany(f => new[] { ("sha256", f.Sha256), ("sha1", f.Sha1) }).Where(x => x.Item2 is not null).Select(x => (x.Item1, x.Item2!)))
            .Concat(e.Emails.Where(m => m.Sender is not null).Select(m => ("email", m.Sender!)));
        return raw.Select(x => Indicators.Normalise(x.Item1, x.Item2) is { } v ? new IntelKey(x.Item1, v) : null).OfType<IntelKey>()
            .DistinctBy(k => $"{k.Kind}:{k.Value}").Take(Kql.MaxValues).ToList();
    }

    // ── watches (#16, #18) ──────────────────────────────────────────────────────────────────────

    /// <summary>Nightly: a "product" watch for each installed product in Defender inventory, so pwn.watch matching follows the tenant.</summary>
    public async Task<int> RefreshInventoryWatchesAsync(CancellationToken ct = default)
    {
        await TakeHuntingBudgetAsync(ct);
        var rows = await microsoft.HuntAsync(null, "ti.inventory", Kql.Inventory, "exposure/inventory.json", null, ct);
        var n = 0;
        foreach (var r in rows)
        {
            var name = J.Str(r, "SoftwareName")?.Replace('_', ' ').Trim().ToLowerInvariant();
            if (name is not { Length: >= 3 and <= 100 } || name.Any(char.IsControl)) continue;
            var vendor = J.Str(r, "SoftwareVendor")?.Replace('_', ' ');
            await store.AddWatchAsync("product", name, "inventory", $"from Defender inventory: {J.Cap(vendor, 60)} {name} ({J.Num(r, "Devices") ?? 0} devices)", ct);
            n++;
        }
        await store.SetStatusAsync(Sources.Exposure, "ok", null, null, ct);
        return n;
    }

    // ── lookups (#15) ───────────────────────────────────────────────────────────────────────────

    private static readonly string[] TenantSources = [Sources.Sentinel, Sources.Msti, Sources.Exposure];

    /// <summary>
    /// One card per source that can speak to this kind of key. Tenant sources (Sentinel TI, Microsoft TI, exposure) use the
    /// board's Microsoft permissions, so they need Board.Hunt; without it they show as "not checked".
    /// </summary>
    public async Task<IntelLookup> LookupAsync(Principal me, string raw, CancellationToken ct = default)
    {
        me.Require(Roles.Poster);
        var key = Indicators.Parse(raw);
        var statuses = await store.StatusesAsync(ct);
        var cards = new List<IntelCard>();
        foreach (var src in Sources.All.Where(s => s.Kinds.Contains(key.Kind) || (key.Kind is "domain" or "ip" or "url" && s.Id == Sources.Msti)))
        {
            if (!s_enabled(src)) { cards.Add(Off(src)); continue; }
            if (TenantSources.Contains(src.Id) && !me.Has(Roles.Hunter)) { cards.Add(NotChecked(src, "needs the Board.Hunt role")); continue; }
            try
            {
                cards.Add(await CardAsync(src, key, me, statuses, ct));
            }
            catch (Exception ex) when (ex is TiFetchException or BoardException or HttpRequestException or JsonException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                var reason = ex is TaskCanceledException ? "timed out" : ex.Message;
                await store.SetStatusAsync(src.Id, "error", reason, null, ct);
                cards.Add(NotChecked(src, $"lookup failed: {reason}"));
            }
        }
        var (agree, differ) = Compare(key.Value, cards);
        var (incidents, messages) = await RelatedAsync(key, ct);
        return new IntelLookup(key.Value, key.Kind, cards, agree, differ, incidents, messages, DateTimeOffset.UtcNow);

        bool s_enabled(SourceInfo s) => Sources.Enabled(Ti, s.Id);
    }

    private static IntelCard Off(SourceInfo s) => s.Id == Sources.CveWatch
        ? new IntelCard(s.Id, s.Name, "not_checked", s.Attribution, null, null, Reason: "unavailable: parked domain, see docs/ti/sources.md")
        : new IntelCard(s.Id, s.Name, "not_checked", s.Attribution, null, null, Reason: $"off: set {s.Flag}=true to turn it on");

    private static IntelCard NotChecked(SourceInfo s, string reason) => new(s.Id, s.Name, "not_checked", s.Attribution, null, null, Reason: reason);

    private static IntelCard FromRecord(SourceInfo s, StoredRecord? r, string notFoundUrl, string? title = null, JsonNode? extra = null)
    {
        if (r is null || !r.Found) return new IntelCard(s.Id, s.Name, "not_found", s.Attribution, notFoundUrl, r?.RetrievedAt ?? DateTimeOffset.UtcNow);
        var data = JsonNode.Parse(r.Data.GetRawText())!;
        if (extra is JsonObject eo) foreach (var (k, v) in eo) data[k] = v?.DeepClone();
        return new IntelCard(s.Id, s.Name, "found", s.Attribution, r.Url ?? notFoundUrl, r.RetrievedAt, title ?? r.Title, r.Severity, data);
    }

    private async Task<IntelCard> CardAsync(SourceInfo s, IntelKey key, Principal me, IReadOnlyDictionary<string, SourceStatus> statuses, CancellationToken ct)
    {
        switch (s.Id)
        {
            case Sources.PwnWatch:
            case Sources.Kev:
            {
                // Stored feeds: "not found" only means something once the feed has loaded.
                var st = statuses.GetValueOrDefault(s.Id);
                var recs = await store.FindAsync("cve", key.Value, [s.Id], 5, ct);
                if (recs.Count == 0 && st?.LastStatus != "ok")
                    return NotChecked(s, st?.LastError is { } e ? $"last fetch failed: {e}" : "not loaded yet (first run is on the next timer)");
                JsonObject? extra = null;
                if (s.Id == Sources.PwnWatch)
                {
                    extra = Freshness(st?.DataAsOf);
                    if (recs.Count > 1) extra["also"] = new JsonArray(recs.Skip(1).Select(r => (JsonNode?)new JsonObject { ["title"] = r.Title, ["url"] = r.Url, ["slug"] = r.Key }).ToArray());
                }
                return FromRecord(s, recs.FirstOrDefault(), s.Id == Sources.Kev ? KevParser.PageUrl(key.Value) : $"{PwnWatchParser.Base}/", extra: extra);
            }
            case Sources.Epss:
            {
                var (recs, _) = await EpssAsync([key.Value], ct);
                return FromRecord(s, recs.GetValueOrDefault(key.Value), "https://www.first.org/epss/");
            }
            case Sources.Nvd:
                return FromRecord(s, await NvdAsync(key.Value, ct), NvdParser.PageUrl(key.Value));
            case Sources.Osv:
                return FromRecord(s, await OsvAsync(key.Value, ct), OsvParser.PageUrl(key.Value));
            case Sources.Msti:
                return FromRecord(s, await MstiAsync(key, ct), "https://security.microsoft.com/threatintelligence");
            case Sources.Sentinel:
            {
                var recs = await SentinelAsync(me.Id, [key], ct);
                return FromRecord(s, recs.GetValueOrDefault($"{key.Kind}:{key.Value}"), "https://security.microsoft.com/threatintelligence");
            }
            case Sources.Exposure:
            {
                var e = (await ExposureAsync(me, [key.Value], ct)).Single();
                var data = JsonSerializer.SerializeToNode(e, Json.Options);
                var line = e.Devices > 0 ? $"Present on {e.Devices} device(s) ({e.InOpenIncidents} in open incidents)" : "Not found in Defender inventory";
                return new IntelCard(s.Id, s.Name, e.Devices > 0 ? "found" : "not_found", s.Attribution, "https://security.microsoft.com/vulnerabilities/vulnerability/" + e.Cve,
                    e.RetrievedAt, line, e.Severity, data);
            }
            default:
                return Off(s);
        }
    }

    /// <summary>"pwn.watch data from 8 Nov 2026 (11 days old)", stale after 3 days.</summary>
    internal static JsonObject Freshness(DateTimeOffset? asOf, DateTimeOffset? now = null)
    {
        if (asOf is not { } at) return new JsonObject { ["freshness"] = null, ["stale"] = false };
        var days = (int)Math.Floor(((now ?? DateTimeOffset.UtcNow) - at).TotalDays);
        return new JsonObject
        {
            ["data_as_of"] = at.ToString("O"),
            ["age_days"] = days,
            ["stale"] = days > 3,
            ["freshness"] = $"pwn.watch data from {at.ToString("d MMM yyyy", System.Globalization.CultureInfo.InvariantCulture)} ({days} day{(days == 1 ? "" : "s")} old)",
        };
    }

    /// <summary>Deterministic agree / differ lines over the found cards (ported from Crosswire's compare.ts). No model involved.</summary>
    internal static (List<string> Agree, List<string> Differ) Compare(string key, IReadOnlyList<IntelCard> cards)
    {
        var found = cards.Where(c => c.Status == "found").ToList();
        var agree = new List<string>();
        var differ = new List<string>();
        if (found.Count == 0)
        {
            agree.Add(cards.Any(c => c.Status == "not_found") ? $"No checked source has a record for {key}." : $"No source was checked for {key}.");
            return (agree, differ);
        }
        string? D(IntelCard c, string k) => c.Data?[k] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

        var exploited = new List<(string Source, bool Yes)>();
        foreach (var c in found)
        {
            bool? claim = c.Source switch
            {
                Sources.Kev => true,
                Sources.PwnWatch => c.Data?["tags"] is JsonArray t && t.Any(x => x?.GetValue<string>() is "cisa-kev" or "exploited" or "in-the-wild" or "zero-day") ? true : null,
                Sources.Msti => c.Data?["active_exploits_observed"] is JsonValue v && v.TryGetValue<bool>(out var b) ? b : null,
                _ => null,
            };
            if (claim is { } y) exploited.Add((c.Name, y));
        }
        if (exploited.Count > 0)
        {
            var yes = exploited.Where(x => x.Yes).Select(x => x.Source).ToList();
            var no = exploited.Where(x => !x.Yes).Select(x => x.Source).ToList();
            if (no.Count == 0) agree.Add($"Exploitation in the wild reported by {string.Join(", ", yes)}.");
            else if (yes.Count == 0) agree.Add($"No active exploitation observed by {string.Join(", ", no)}.");
            else differ.Add($"Exploitation reported by {string.Join(", ", yes)}, not by {string.Join(", ", no)}.");
        }

        var sev = found.Where(c => c.Source is Sources.PwnWatch or Sources.Nvd or Sources.Osv or Sources.Msti && c.Severity is { Length: > 0 })
            .Select(c => (c.Name, Level: c.Severity!.ToLowerInvariant() == "moderate" ? "medium" : c.Severity!.ToLowerInvariant())).ToList();
        if (sev.Count >= 2)
        {
            if (sev.Select(x => x.Level).Distinct().Count() == 1) agree.Add($"Severity {sev[0].Level} ({string.Join(", ", sev.Select(x => x.Name))}).");
            else differ.Add($"Severity differs: {string.Join("; ", sev.Select(x => $"{x.Name} {x.Level}"))}.");
        }

        var dates = found.Select(c => (c.Name, Date: c.Source switch
        {
            Sources.PwnWatch => D(c, "started_at"),
            Sources.Kev => D(c, "date_added"),
            Sources.Nvd => D(c, "published"),
            Sources.Osv => D(c, "published"),
            Sources.Msti => D(c, "published"),
            _ => null,
        })).Where(x => x.Date is { Length: >= 10 }).Select(x => (x.Name, Day: x.Date![..10])).ToList();
        if (dates.Count >= 2)
        {
            if (dates.Select(x => x.Day).Distinct().Count() == 1) agree.Add($"Same date: {dates[0].Day}.");
            else differ.Add($"Dates differ: {string.Join("; ", dates.Select(x => $"{x.Name} {x.Day}"))}.");
        }
        if (found.Count == 1 && agree.Count + differ.Count == 0) agree.Add($"Only {found[0].Name} has a record; nothing to compare yet.");
        return (agree, differ);
    }

    private async Task<(IReadOnlyList<RelatedIncident>, IReadOnlyList<Message>)> RelatedAsync(IntelKey key, CancellationToken ct)
    {
        var messages = new List<Message>();
        try
        {
            messages.AddRange((await search.RunAsync(new SearchQuery(Q: $"\"{key.Value.Replace("\"", "")}\"", Limit: 20), ct)).Hits);
        }
        catch (BoardException) { /* a value websearch can't parse: no related messages */ }
        var incidents = new List<RelatedIncident>();
        var pattern = "%" + key.Value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
        var linked = messages.Select(m => m.IncidentId).OfType<Guid>().Distinct().ToArray();
        await using var cmd = db.Command("""
            select id, graph_id, display_name, severity, status from incidents
            where data::text ilike @p escape '\' or id = any(@ids)
            order by coalesce(updated_at_src, first_seen_at) desc limit 20
            """).With("p", pattern).With("ids", linked);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) incidents.Add(new RelatedIncident(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4)));
        return (incidents, messages);
    }

    // ── badges, index, posts ────────────────────────────────────────────────────────────────────

    /// <summary>KEV and EPSS for CVE ids shown in the UI, from the store only: rendering a message never fetches anything.</summary>
    public async Task<IReadOnlyList<CveBadge>> BadgesAsync(IEnumerable<string> ids, CancellationToken ct = default)
    {
        var cves = ids.Select(Indicators.NormaliseCve).OfType<string>().Distinct().Take(100).ToList();
        var kev = Ti.Kev ? (await store.GetManyAsync(Sources.Kev, cves, ct)).ToDictionary(r => r.Key) : [];
        var epss = Ti.Epss ? (await store.GetManyAsync(Sources.Epss, cves, ct)).Where(r => r.Found).ToDictionary(r => r.Key) : [];
        return cves.Select(c =>
        {
            var k = kev.GetValueOrDefault(c);
            var e = epss.GetValueOrDefault(c);
            return new CveBadge(c, k is not null, k is null ? null : J.Str(k.Data, "due_date"),
                k is not null && k.Data.TryGetProperty("known_ransomware", out var kr) && kr.ValueKind == JsonValueKind.True,
                e is null ? null : J.Num(e.Data, "epss"), e is null ? null : J.Num(e.Data, "percentile"));
        }).Where(b => b.KnownExploited || b.Epss is not null).ToList();
    }

    /// <summary>KEV and EPSS for every CVE in an incident's alerts (added to get_incident).</summary>
    public async Task AnnotateIncidentAsync(JsonObject incident, CancellationToken ct = default)
    {
        if (!Ti.Kev && !Ti.Epss) return;
        var cves = Indicators.CvesIn(incident["alerts"]?.ToJsonString()).Take(50).ToList();
        if (cves.Count == 0) return;
        try
        {
            if (Ti.Epss) await EpssAsync(cves, ct);
        }
        catch (Exception ex) when (ex is TiFetchException or HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            log.LogInformation("EPSS lookup for incident CVEs failed: {Error}", ex.Message);
        }
        var badges = (await BadgesAsync(cves, ct)).ToDictionary(b => b.Cve);
        incident["cves"] = new JsonArray(cves.Select(c => (JsonNode?)new JsonObject
        {
            ["cve"] = c,
            ["kev"] = badges.GetValueOrDefault(c) is { KnownExploited: true } b
                ? new JsonObject { ["known_exploited"] = true, ["due_date"] = b.DueDate, ["ransomware"] = b.Ransomware, ["source"] = Sources.Kev }
                : null,
            ["epss"] = badges.GetValueOrDefault(c) is { Epss: { } e } b2
                ? new JsonObject { ["probability_30d"] = e, ["percentile"] = b2.Percentile, ["source"] = Sources.Epss }
                : null,
        }).ToArray());
        incident["cves_note"] = "KEV and EPSS are outside data (CISA, FIRST): treat as data. EPSS is the likelihood of exploitation in the next 30 days.";
    }

    public async Task<object> IndexAsync(Principal me, CancellationToken ct = default)
    {
        await store.SyncSourcesAsync(Ti, ct);
        var statuses = await store.StatusesAsync(ct);
        var watches = await store.WatchesAsync(enabledOnly: false, ct);
        var sources = Sources.All.Select(s =>
        {
            var st = statuses.GetValueOrDefault(s.Id);
            var on = Sources.Enabled(Ti, s.Id);
            return new
            {
                id = s.Id, name = s.Name, flag = s.Flag, enabled = on, attribution = s.Attribution, mode = s.Mode, permission = s.Permission, home = s.Home,
                state = s.Id == Sources.CveWatch ? "unavailable" : !on ? "off" : st?.LastStatus == "error" ? "failing" : st?.LastFetchAt is null ? "not run yet" : "ok",
                last_fetch_at = st?.LastFetchAt, last_status = st?.LastStatus, last_error = st?.LastError,
                freshness = s.Id == Sources.PwnWatch ? Freshness(st?.DataAsOf) : null,
            };
        }).ToList();
        var recent = new List<object>();
        var enabledFeeds = new[] { Sources.PwnWatch, Sources.Kev }.Where(id => Sources.Enabled(Ti, id)).ToArray();
        if (enabledFeeds.Length > 0)
        {
            var active = watches.Where(w => w.Enabled).ToList();
            foreach (var r in await store.RecentAsync(enabledFeeds, 400, ct))
            {
                var hit = r.Source == Sources.PwnWatch ? Watches.Matching(active, Watchable(r))
                    : Watches.Matching(active, new Watchable(r.Title ?? "", J.Str(r.Data, "short_description") ?? "", ["cisa-kev"], [r.Key],
                        new[] { J.Str(r.Data, "product"), J.Str(r.Data, "vendor") }.OfType<string>().ToList()));
                if (hit.Count == 0) continue;
                recent.Add(new
                {
                    source = r.Source, key = r.Key, title = r.Title, severity = r.Severity, url = r.Url, retrieved_at = r.RetrievedAt,
                    published_at = r.PublishedAt, updated_at = r.UpdatedAt, watches = hit,
                    cve_ids = r.Source == Sources.Kev ? [r.Key] : Watchable(r).Cves,
                    patch_status = J.Str(r.Data, "patch_status"), attribution = Sources.Get(r.Source).Attribution,
                });
                if (recent.Count >= 50) break;
            }
        }
        JsonElement? tags = null;
        await using (var cmd = db.Command("select value::text from kv_state where key = 'ti.pwnwatch.tags'"))
            if (await cmd.ExecuteScalarAsync(ct) is string t) tags = JsonDocument.Parse(t).RootElement.Clone();
        return new
        {
            any_enabled = Ti.AnyEnabled,
            fixture_mode = Ti.FixturesDir is not null,
            can_hunt = me.Has(Roles.Hunter),
            sources, watches, recent, pwnwatch_tags = tags,
        };
    }

    /// <summary>The pwn.watch agent brief for one incident, fetched only when someone opens it. Untrusted Markdown, shown quoted.</summary>
    public async Task<object> PwnBriefAsync(string slug, CancellationToken ct = default)
    {
        if (!Ti.PwnWatch) throw new BoardException("pwn.watch is off: set TI_PWNWATCH_ENABLED=true");
        if (await store.GetAsync(Sources.PwnWatch, slug, ct) is not { } rec) throw BoardException.NotFound("pwn.watch incident");
        var res = await fetcher.GetAsync(PwnSlowPolicy, PwnWatchParser.DetailUrl(slug), $"pwnwatch/incident-{slug}.json", ct: ct);
        return new { slug, url = rec.Url, retrieved_at = res.FetchedAt, brief = PwnWatchParser.AgentBrief(res.Body), attribution = Sources.Get(Sources.PwnWatch).Attribution };
    }

    public async Task<Watch> AddWatchAsync(Principal me, string kind, string value, CancellationToken ct = default)
    {
        me.Require(Roles.Hunter);
        var w = await store.AddWatchAsync(kind, Watches.Normalise(kind, value), "manual", null, ct);
        await new Audit(db).WriteAsync(me.Id, "ti.watch_added", $"{w.Kind}:{w.Value}", null, ct);
        return w;
    }

    public async Task<object> SetWatchAsync(Principal me, Guid id, bool enabled, CancellationToken ct = default)
    {
        me.Require(Roles.Hunter);
        if (!await store.SetWatchEnabledAsync(id, enabled, ct)) throw BoardException.NotFound("watch");
        await new Audit(db).WriteAsync(me.Id, enabled ? "ti.watch_enabled" : "ti.watch_disabled", id.ToString(), null, ct);
        return new { id, enabled };
    }

    /// <summary>"Post to #intel": a finding by the caller summarising every card, each line crediting its source.</summary>
    public async Task<Message> PostSummaryAsync(Principal me, string raw, CancellationToken ct = default)
    {
        var l = await LookupAsync(me, raw, ct);
        var sb = new StringBuilder($"**Intel: {l.Key}**\n\n");
        foreach (var c in l.Cards)
        {
            var what = c.Status switch
            {
                "found" => Clean(Summary(c)),
                "not_found" => "no record",
                _ => $"not checked ({Clean(c.Reason ?? "off")})",
            };
            sb.Append($"- {c.Name}: {what}{(c.RetrievedAt is { } at && c.Status != "not_checked" ? $", retrieved {at:dd-MM-yyyy HH:mm} UTC" : "")}. {c.Attribution}\n");
        }
        foreach (var a in l.Agree) sb.Append($"\nAgree: {a}");
        foreach (var d in l.Differ) sb.Append($"\nDiffer: {d}");
        return await board.PostAsync(me, new PostInput("intel", sb.ToString(), "finding", Json.Element(new
        {
            intel_key = l.Key,
            sources = l.Cards.Where(c => c.Status != "not_checked").Select(c => new { source = c.Source, url = c.Url, retrieved_at = c.RetrievedAt }),
        })), ct: ct);
    }

    private static string Summary(IntelCard c)
    {
        string? D(string k) => c.Data?[k] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
        double? N(string k) => c.Data?[k] is JsonValue v && v.TryGetValue<double>(out var d) ? d : null;
        return c.Source switch
        {
            Sources.Kev => $"known exploited, added {D("date_added")}, due {D("due_date")}{(c.Data?["known_ransomware"]?.GetValue<bool>() == true ? ", used in ransomware" : "")}",
            Sources.Epss => $"EPSS {Math.Round((N("epss") ?? 0) * 100)}% (percentile {Math.Floor((N("percentile") ?? 0) * 100)}), likelihood of exploitation in the next 30 days",
            Sources.PwnWatch => $"{c.Title}, severity {c.Severity ?? "unknown"}, patch status {D("patch_status") ?? "unknown"}",
            Sources.Nvd => c.Data?["cvss"] is JsonObject cv ? $"CVSS {cv["version"]} {cv["score"]} {cv["severity"]}" : "record without CVSS",
            Sources.Osv => c.Title ?? "advisory",
            _ => c.Title ?? c.Severity ?? "match",
        };
    }
}
