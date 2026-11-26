using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;

namespace Blueboard.Api.Board;

public sealed record GifItem(
    string Id,
    string Title,
    string Url,
    string PreviewUrl,
    int? Width,
    int? Height,
    string Provider,
    string[] Tags);

public sealed record GifSearchResult(
    bool Enabled,
    string Provider,
    IReadOnlyList<GifItem> Items);

/// <summary>
/// Strict GIF attachment validation and Slack-style GIF search (GIPHY / Tenor proxy when configured, or a curated
/// built-in reaction catalogue when no third-party API key is configured). Only exact trusted GIF CDN hosts over
/// HTTPS are ever accepted or returned, preventing arbitrary remote image tracking pixels and SSRF.
/// </summary>
public static class Gifs
{
    public static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "media.giphy.com",
        "media0.giphy.com",
        "media1.giphy.com",
        "media2.giphy.com",
        "media3.giphy.com",
        "media4.giphy.com",
        "i.giphy.com",
        "media.tenor.com",
        "c.tenor.com",
    };

    /// <summary>Curated SOC &amp; team reaction GIFs that work out of the box with zero API keys.</summary>
    public static readonly IReadOnlyList<GifItem> Curated =
    [
        Giphy("3o7abKhOpu0NwenH3O", "Thumbs up — looks good", ["thumbs", "up", "lgtm", "approve", "approved", "yes", "ok", "good", "nice"]),
        Giphy("QMHoU66sBXqqLqYvGO", "This is fine", ["fine", "fire", "incident", "sev1", "alert", "chaos", "monday", "oncall", "panic"]),
        Giphy("l0MYt5jPR6QX5pnqM", "Party celebration", ["party", "celebrate", "win", "resolved", "closed", "done", "yay", "woohoo", "friday"]),
        Giphy("3ohzdIuqJoo8QdKlnW", "Yes! Let's go", ["yes", "letsgo", "celebrate", "win", "awesome", "ship", "done"]),
        Giphy("xT0xeJpnrWC4XWblEk", "Mind blown", ["mind", "blown", "wow", "whoa", "discovery", "finding", "cve", "zero", "day"]),
        Giphy("13HgwGsXF0aiGY", "Typing furiously", ["hack", "hacker", "hackerman", "typing", "coding", "kql", "hunt", "hunting", "investigating"]),
        Giphy("3o6Zt481isNVuQI1l6", "Cat typing on keyboard", ["cat", "typing", "work", "triage", "investigating", "busy", "keyboard"]),
        Giphy("uWzS6ZLs0AaVOJlgRd", "Grabbing popcorn", ["popcorn", "watching", "waiting", "drama", "logs", "audit"]),
        Giphy("3o7TKTDn976rzVgky4", "Suspicious squinting", ["suspicious", "sus", "hmm", "doubt", "ioc", "phishing", "threat", "investigate"]),
        Giphy("TJawtKM6OCKkvwCIqX", "Facepalm", ["facepalm", "oops", "fail", "false", "positive", "sigh", "bruh", "misconfig"]),
        Giphy("l41lFw057lAJQMwg0", "Coffee time", ["coffee", "morning", "oncall", "shift", "handover", "tired", "caffeine"]),
        Giphy("3oriO0OEd9QIDdllqo", "Hello wave", ["hello", "hi", "wave", "hey", "welcome", "morning", "handover", "general"]),
        Giphy("26u4lOMA8JKSnL9Uk", "Mission accomplished", ["done", "complete", "contained", "eradicated", "mission", "accomplished", "ship", "clean"]),
        Giphy("xT5LMHxhOfscxPfIfm", "Ship it!", ["ship", "deploy", "release", "merge", "go", "rocket", "launch"]),
        Giphy("5VKbvrjxpVJCM", "Excited reaction", ["wow", "nice", "excited", "awesome", "cool", "amazing", "great"]),
        Giphy("3oEjI6SIIHBdRxXI40", "Waiting / loading", ["waiting", "loading", "pending", "approval", "soon", "patience"]),
        Giphy("d3mlE7uhX8KFgEmY", "Smart move", ["smart", "big", "brain", "idea", "clever", "genius", "playbook"]),
        Giphy("l2JehQ2GitHGdVG9y", "Alert / alarm", ["alert", "alarm", "siren", "critical", "high", "incident", "breach", "paged"]),
        Giphy("111ebonMs90YLu", "Approved nod", ["approve", "approved", "nod", "nice", "good", "lgtm", "agree", "cheers"]),
        Giphy("Ju7l5y9osyymQ", "Never gonna give you up", ["rick", "rickroll", "music", "dance", "fun", "troll"]),
    ];

    private static GifItem Giphy(string id, string title, string[] tags) => new(
        id,
        title,
        $"https://media.giphy.com/media/{id}/giphy.gif",
        $"https://media.giphy.com/media/{id}/200w.gif",
        480,
        270,
        "giphy",
        tags);

    public static bool IsAllowedUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 2048) return false;
        foreach (var ch in raw)
            if (char.IsControl(ch) || char.IsWhiteSpace(ch) || ch is '(' or ')' or '<' or '>')
                return false;
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u)) return false;
        if (u.Scheme != Uri.UriSchemeHttps || !u.IsDefaultPort) return false;
        if (!string.IsNullOrEmpty(u.UserInfo) || !string.IsNullOrEmpty(u.Fragment)) return false;
        var host = u.IdnHost.TrimEnd('.');
        return AllowedHosts.Contains(host);
    }

    public static string ProviderOf(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && u.IdnHost.EndsWith("tenor.com", StringComparison.OrdinalIgnoreCase)
            ? "tenor"
            : "giphy";

    /// <summary>Validates and normalises a message's payload.gif object. Throws BoardException on any invalid URL or field.</summary>
    public static JsonObject ValidatePayload(JsonElement gif)
    {
        if (gif.ValueKind != JsonValueKind.Object)
            throw new BoardException("invalid gif payload: must be an object");
        var url = Str(gif, "url");
        if (!IsAllowedUrl(url))
            throw new BoardException("invalid gif url: must be an https URL on an allowed GIF host (GIPHY or Tenor)");

        var outObj = new JsonObject { ["url"] = url! };
        var preview = Str(gif, "preview_url");
        if (preview is not null)
        {
            if (!IsAllowedUrl(preview))
                throw new BoardException("invalid gif preview_url: must be an https URL on an allowed GIF host");
            outObj["preview_url"] = preview;
        }
        var title = Str(gif, "title")?.Trim();
        if (!string.IsNullOrEmpty(title))
        {
            if (title.Length > 200) throw new BoardException("gif title must be at most 200 characters");
            outObj["title"] = StripControls(title);
        }
        if (TryInt(gif, "width", out var w))
        {
            if (w is < 1 or > 4096) throw new BoardException("gif width must be 1–4096");
            outObj["width"] = w;
        }
        if (TryInt(gif, "height", out var h))
        {
            if (h is < 1 or > 4096) throw new BoardException("gif height must be 1–4096");
            outObj["height"] = h;
        }
        var provider = Str(gif, "provider")?.Trim().ToLowerInvariant();
        outObj["provider"] = provider is "giphy" or "tenor" ? provider : ProviderOf(url!);
        return outObj;
    }

    public static IReadOnlyList<GifItem> SearchCurated(string? query, int limit)
    {
        var q = (query ?? "").Trim();
        if (q.Length == 0) return Curated.Take(limit).ToList();
        var tokens = q.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var scored = Curated
            .Select(g => (item: g, score: Score(g, tokens)))
            .Where(x => x.score > 0)
            .OrderByDescending(x => x.score)
            .Select(x => x.item)
            .Take(limit)
            .ToList();
        return scored.Count > 0 ? scored : Curated.Take(Math.Min(limit, 6)).ToList();
    }

    private static int Score(GifItem g, string[] tokens)
    {
        var score = 0;
        foreach (var t in tokens)
        {
            if (g.Tags.Any(tag => tag.Equals(t, StringComparison.OrdinalIgnoreCase))) score += 10;
            else if (g.Tags.Any(tag => tag.StartsWith(t, StringComparison.OrdinalIgnoreCase))) score += 6;
            else if (g.Title.Contains(t, StringComparison.OrdinalIgnoreCase)) score += 4;
            else if (g.Tags.Any(tag => tag.Contains(t, StringComparison.OrdinalIgnoreCase))) score += 2;
        }
        return score;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool TryInt(JsonElement e, string name, out int value)
    {
        value = 0;
        return e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out value);
    }

    private static string StripControls(string s) =>
        new(s.Where(c => !char.IsControl(c)).ToArray());
}

/// <summary>
/// Server-side GIF search proxy so API keys never reach the browser and every returned URL is verified against
/// <see cref="Gifs.AllowedHosts"/>. Falls back to the built-in curated library when no upstream key is configured.
/// </summary>
public sealed class GifService(HttpClient http, Settings settings, RateLimiter? limiter = null)
{
    private const int MaxResponseBytes = 512 * 1024;

    public async Task<GifSearchResult> SearchAsync(Principal caller, string? query, int? limit, CancellationToken ct = default)
    {
        if (!settings.GifsEnabled)
            return new GifSearchResult(false, "disabled", []);
        if (limiter is not null) await limiter.TakeAsync(caller, "post", ct);
        var take = Math.Clamp(limit ?? 12, 1, 24);
        var q = (query ?? "").Trim();
        if (q.Length > 100) q = q[..100];

        if (!string.IsNullOrWhiteSpace(settings.GiphyApiKey))
        {
            var items = await SearchGiphyAsync(q, take, ct);
            if (items is not null) return new GifSearchResult(true, "giphy", items);
        }
        if (!string.IsNullOrWhiteSpace(settings.TenorApiKey))
        {
            var items = await SearchTenorAsync(q, take, ct);
            if (items is not null) return new GifSearchResult(true, "tenor", items);
        }
        return new GifSearchResult(true, "curated", Gifs.SearchCurated(q, take));
    }

    private async Task<IReadOnlyList<GifItem>?> SearchGiphyAsync(string q, int take, CancellationToken ct)
    {
        var key = Uri.EscapeDataString(settings.GiphyApiKey!);
        var url = q.Length == 0
            ? $"https://api.giphy.com/v1/gifs/trending?api_key={key}&limit={take}&rating=pg"
            : $"https://api.giphy.com/v1/gifs/search?api_key={key}&q={Uri.EscapeDataString(q)}&limit={take}&rating=pg";
        var doc = await FetchJsonAsync(url, ct);
        if (doc is null) return null;
        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                return [];
            var list = new List<GifItem>();
            foreach (var item in data.EnumerateArray())
            {
                if (!item.TryGetProperty("images", out var imgs) || imgs.ValueKind != JsonValueKind.Object) continue;
                var full = PickImage(imgs, "downsized_medium", "fixed_height", "original");
                var preview = PickImage(imgs, "fixed_width_small", "fixed_width", "downsized_medium") ?? full;
                if (full is null || !Gifs.IsAllowedUrl(full.Value.Url)) continue;
                var prevUrl = preview is not null && Gifs.IsAllowedUrl(preview.Value.Url) ? preview.Value.Url : full.Value.Url;
                var id = item.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String ? idEl.GetString()! : Guid.NewGuid().ToString("n");
                var title = item.TryGetProperty("title", out var tEl) && tEl.ValueKind == JsonValueKind.String ? tEl.GetString()!.Trim() : "";
                if (title.Length > 200) title = title[..200];
                list.Add(new GifItem(id, title.Length > 0 ? title : "GIF", full.Value.Url, prevUrl, full.Value.Width, full.Value.Height, "giphy", []));
            }
            return list;
        }
    }

    private async Task<IReadOnlyList<GifItem>?> SearchTenorAsync(string q, int take, CancellationToken ct)
    {
        var key = Uri.EscapeDataString(settings.TenorApiKey!);
        var url = q.Length == 0
            ? $"https://tenor.googleapis.com/v2/featured?key={key}&limit={take}&contentfilter=medium&media_filter=gif,tinygif"
            : $"https://tenor.googleapis.com/v2/search?key={key}&q={Uri.EscapeDataString(q)}&limit={take}&contentfilter=medium&media_filter=gif,tinygif";
        var doc = await FetchJsonAsync(url, ct);
        if (doc is null) return null;
        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
                return [];
            var list = new List<GifItem>();
            foreach (var item in results.EnumerateArray())
            {
                if (!item.TryGetProperty("media_formats", out var formats) || formats.ValueKind != JsonValueKind.Object) continue;
                var full = PickTenor(formats, "gif", "tinygif");
                var prev = PickTenor(formats, "tinygif", "gif") ?? full;
                if (full is null || !Gifs.IsAllowedUrl(full.Value.Url)) continue;
                var prevUrl = prev is not null && Gifs.IsAllowedUrl(prev.Value.Url) ? prev.Value.Url : full.Value.Url;
                var id = item.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String ? idEl.GetString()! : Guid.NewGuid().ToString("n");
                var title = item.TryGetProperty("content_description", out var tEl) && tEl.ValueKind == JsonValueKind.String ? tEl.GetString()!.Trim() : "";
                if (title.Length > 200) title = title[..200];
                list.Add(new GifItem(id, title.Length > 0 ? title : "GIF", full.Value.Url, prevUrl, full.Value.Width, full.Value.Height, "tenor", []));
            }
            return list;
        }
    }

    private async Task<JsonDocument?> FetchJsonAsync(string url, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            if (!res.IsSuccessStatusCode) return null;
            await using var stream = await res.Content.ReadAsStreamAsync(cts.Token);
            using var ms = new MemoryStream();
            var buf = new byte[8192];
            int n;
            while ((n = await stream.ReadAsync(buf, cts.Token)) > 0)
            {
                if (ms.Length + n > MaxResponseBytes) return null;
                ms.Write(buf, 0, n);
            }
            ms.Position = 0;
            return await JsonDocument.ParseAsync(ms, cancellationToken: cts.Token);
        }
        catch
        {
            return null;
        }
    }

    private static (string Url, int? Width, int? Height)? PickImage(JsonElement imgs, params string[] names)
    {
        foreach (var name in names)
        {
            if (!imgs.TryGetProperty(name, out var e) || e.ValueKind != JsonValueKind.Object) continue;
            if (!e.TryGetProperty("url", out var u) || u.ValueKind != JsonValueKind.String) continue;
            var url = u.GetString();
            if (string.IsNullOrWhiteSpace(url)) continue;
            int? w = e.TryGetProperty("width", out var we) && int.TryParse(we.ToString(), out var wi) && wi is > 0 and <= 4096 ? wi : null;
            int? h = e.TryGetProperty("height", out var he) && int.TryParse(he.ToString(), out var hi) && hi is > 0 and <= 4096 ? hi : null;
            return (url, w, h);
        }
        return null;
    }

    private static (string Url, int? Width, int? Height)? PickTenor(JsonElement formats, params string[] names)
    {
        foreach (var name in names)
        {
            if (!formats.TryGetProperty(name, out var e) || e.ValueKind != JsonValueKind.Object) continue;
            if (!e.TryGetProperty("url", out var u) || u.ValueKind != JsonValueKind.String) continue;
            var url = u.GetString();
            if (string.IsNullOrWhiteSpace(url)) continue;
            int? w = null, h = null;
            if (e.TryGetProperty("dims", out var dims) && dims.ValueKind == JsonValueKind.Array && dims.GetArrayLength() >= 2)
            {
                if (dims[0].TryGetInt32(out var wi) && wi is > 0 and <= 4096) w = wi;
                if (dims[1].TryGetInt32(out var hi) && hi is > 0 and <= 4096) h = hi;
            }
            return (url, w, h);
        }
        return null;
    }
}
