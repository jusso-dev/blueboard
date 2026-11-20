using System.Text.Json;

namespace Blueboard.Api.Graph;

public sealed record DeviceRef(string? MdeDeviceId, string? Name);
public sealed record UserRef(string? Upn, string? AadUserId, string? Name);
public sealed record FileRef(string? Sha256, string? Sha1, string? Name);
public sealed record EmailRef(string? NetworkMessageId, string? Recipient, string? Sender, string? Subject);

public sealed record IncidentEntities(
    List<DeviceRef> Devices, List<UserRef> Users, List<string> Ips, List<string> Urls,
    List<string> Domains, List<FileRef> Files, List<EmailRef> Emails, List<string> Mitre)
{
    /// <summary>Every identifier in the evidence, lower-cased, for "is this target in the incident" checks.</summary>
    public HashSet<string> Keys()
    {
        var k = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? v) { if (!string.IsNullOrEmpty(v)) k.Add(v); }
        foreach (var d in Devices) { Add(d.MdeDeviceId); Add(d.Name); }
        foreach (var u in Users) { Add(u.Upn); Add(u.AadUserId); }
        Ips.ForEach(Add); Urls.ForEach(Add); Domains.ForEach(Add);
        foreach (var f in Files) { Add(f.Sha256); Add(f.Sha1); }
        foreach (var m in Emails) { Add(m.NetworkMessageId); Add(m.Recipient); Add(m.Sender); }
        return k;
    }
}

/// <summary>Normalised entity view of a Graph security incident's alert evidence.</summary>
public static class Entities
{
    public static IncidentEntities Extract(JsonElement incident)
    {
        var e = new IncidentEntities([], [], [], [], [], [], [], []);
        if (!incident.TryGetProperty("alerts", out var alerts) || alerts.ValueKind != JsonValueKind.Array) return Dedupe(e);
        foreach (var alert in alerts.EnumerateArray())
        {
            if (alert.TryGetProperty("mitreTechniques", out var mt) && mt.ValueKind == JsonValueKind.Array)
                e.Mitre.AddRange(mt.EnumerateArray().Select(x => x.GetString()).OfType<string>());
            if (!alert.TryGetProperty("evidence", out var evidence) || evidence.ValueKind != JsonValueKind.Array) continue;
            foreach (var ev in evidence.EnumerateArray())
            {
                var t = (S(ev, "@odata.type") ?? "").Replace("#microsoft.graph.security.", "");
                switch (t)
                {
                    case "deviceEvidence":
                        e.Devices.Add(new DeviceRef(S(ev, "mdeDeviceId"), S(ev, "deviceDnsName") ?? S(ev, "hostName")));
                        break;
                    case "userEvidence":
                        var ua = O(ev, "userAccount");
                        e.Users.Add(new UserRef(S(ua, "userPrincipalName"), S(ua, "azureAdUserId"), S(ua, "displayName") ?? S(ua, "accountName")));
                        break;
                    case "ipEvidence":
                        if (S(ev, "ipAddress") is { } ip) e.Ips.Add(ip);
                        break;
                    case "urlEvidence":
                        if (S(ev, "url") is { } url) e.Urls.Add(url);
                        break;
                    case "fileEvidence":
                    case "fileHashEvidence":
                        var fd = O(ev, "fileDetails");
                        var alg = S(ev, "algorithm");
                        e.Files.Add(new FileRef(S(fd, "sha256") ?? (alg == "sha256" ? S(ev, "value") : null),
                                                S(fd, "sha1") ?? (alg == "sha1" ? S(ev, "value") : null), S(fd, "fileName")));
                        break;
                    case "processEvidence":
                        if (O(ev, "imageFile") is { ValueKind: JsonValueKind.Object } img)
                            e.Files.Add(new FileRef(S(img, "sha256"), S(img, "sha1"), S(img, "fileName")));
                        break;
                    case "analyzedMessageEvidence":
                        e.Emails.Add(new EmailRef(S(ev, "networkMessageId"), S(ev, "recipientEmailAddress"),
                            S(O(ev, "p1Sender"), "emailAddress") ?? S(O(ev, "p2Sender"), "emailAddress"), S(ev, "subject")));
                        if (O(ev, "urls") is { ValueKind: JsonValueKind.Array } urls)
                            e.Urls.AddRange(urls.EnumerateArray().Select(u => u.GetString()).OfType<string>());
                        break;
                    case "mailboxEvidence":
                        e.Users.Add(new UserRef(S(ev, "primaryAddress") ?? S(O(ev, "userAccount"), "userPrincipalName"), S(O(ev, "userAccount"), "azureAdUserId"), null));
                        break;
                }
            }
        }
        foreach (var u in e.Urls)
            if (Uri.TryCreate(u, UriKind.Absolute, out var parsed)) e.Domains.Add(parsed.Host.ToLowerInvariant());
        return Dedupe(e);
    }

    private static IncidentEntities Dedupe(IncidentEntities e) => e with
    {
        Devices = e.Devices.DistinctBy(d => (d.MdeDeviceId ?? d.Name)?.ToLowerInvariant()).ToList(),
        Users = e.Users.DistinctBy(u => (u.AadUserId ?? u.Upn)?.ToLowerInvariant()).ToList(),
        Files = e.Files.DistinctBy(f => f.Sha256 ?? f.Sha1).ToList(),
        Emails = e.Emails.DistinctBy(m => $"{m.NetworkMessageId}|{m.Recipient}").ToList(),
        Ips = e.Ips.Distinct().ToList(),
        Urls = e.Urls.Distinct().ToList(),
        Domains = e.Domains.Distinct().ToList(),
        Mitre = e.Mitre.Distinct().ToList(),
    };

    private static string? S(JsonElement? e, string name) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static JsonElement? O(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : null;
}
