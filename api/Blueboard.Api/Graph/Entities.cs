using System.Text.Json;

namespace Blueboard.Api.Graph;

public sealed record DeviceRef(string? MdeDeviceId, string? Name);
public sealed record UserRef(string? Upn, string? AadUserId, string? Name);
public sealed record FileRef(string? Sha256, string? Sha1, string? Name, string? Md5 = null);
public sealed record EmailRef(string? NetworkMessageId, string? Recipient, string? Sender, string? Subject);
public sealed record CloudAppRef(string? AppId, string? ObjectId, string? DisplayName, string? Kind = null);
public sealed record AzureResourceRef(string? ResourceId, string? Name, string? ResourceType);

public sealed record IncidentEntities(
    List<DeviceRef> Devices, List<UserRef> Users, List<string> Ips, List<string> Urls,
    List<string> Domains, List<FileRef> Files, List<EmailRef> Emails, List<string> Mitre)
{
    public List<CloudAppRef> CloudApps { get; init; } = [];
    public List<AzureResourceRef> AzureResources { get; init; } = [];

    /// <summary>Every identifier in the evidence, case-insensitive, for "is this target in the incident" checks.</summary>
    public HashSet<string> Keys()
    {
        var k = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? v) { if (!string.IsNullOrEmpty(v)) k.Add(v); }
        foreach (var d in Devices) { Add(d.MdeDeviceId); Add(d.Name); }
        foreach (var u in Users) { Add(u.Upn); Add(u.AadUserId); }
        Ips.ForEach(Add); Urls.ForEach(Add); Domains.ForEach(Add);
        foreach (var f in Files) { Add(f.Sha256); Add(f.Sha1); Add(f.Md5); }
        foreach (var m in Emails) { Add(m.NetworkMessageId); Add(m.Recipient); Add(m.Sender); }
        foreach (var a in CloudApps) { Add(a.AppId); Add(a.ObjectId); Add(a.DisplayName); }
        foreach (var r in AzureResources) { Add(r.ResourceId); Add(r.Name); }
        return k;
    }
}

/// <summary>
/// Normalised entity view of a Graph Security API incident's alert evidence (Defender XDR + Sentinel + Defender for Cloud).
/// Merges partial records across alerts so device MDE ids and host names (and user object ids and UPNs) stay linked for
/// policy alias checks.
/// </summary>
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
                        AddDevice(e, S(ev, "mdeDeviceId"), S(ev, "deviceDnsName") ?? S(ev, "hostName"));
                        if (S(ev, "lastIpAddress") is { } dip) e.Ips.Add(dip);
                        break;
                    case "userEvidence":
                        AddUser(e, O(ev, "userAccount"));
                        break;
                    case "ipEvidence":
                        if (S(ev, "ipAddress") is { } ip) e.Ips.Add(ip);
                        break;
                    case "urlEvidence":
                        if (S(ev, "url") is { } url) e.Urls.Add(url);
                        break;
                    case "dnsEvidence":
                        if (S(ev, "domainName") is { Length: > 0 } dom) e.Domains.Add(dom.ToLowerInvariant().TrimEnd('.'));
                        if (O(ev, "hostIpAddress") is { } hip && S(hip, "ipAddress") is { } hostIp) e.Ips.Add(hostIp);
                        if (O(ev, "ipAddresses") is { ValueKind: JsonValueKind.Array } ips)
                            foreach (var item in ips.EnumerateArray())
                                if (S(item, "ipAddress") is { } dnsIp) e.Ips.Add(dnsIp);
                        break;
                    case "fileEvidence":
                    case "fileHashEvidence":
                        var fd = O(ev, "fileDetails");
                        var alg = S(ev, "algorithm")?.ToLowerInvariant();
                        var val = S(ev, "value");
                        e.Files.Add(new FileRef(
                            S(fd, "sha256") ?? (alg is "sha256" or "filesha256" ? val : null),
                            S(fd, "sha1") ?? (alg is "sha1" or "filesha1" ? val : null),
                            S(fd, "fileName"),
                            S(fd, "md5") ?? (alg is "md5" or "filemd5" ? val : null)));
                        break;
                    case "processEvidence":
                        if (S(ev, "mdeDeviceId") is { } procDev) AddDevice(e, procDev, null);
                        AddUser(e, O(ev, "userAccount"));
                        if (O(ev, "imageFile") is { ValueKind: JsonValueKind.Object } img)
                            e.Files.Add(new FileRef(S(img, "sha256"), S(img, "sha1"), S(img, "fileName"), S(img, "md5")));
                        if (O(ev, "parentProcessImageFile") is { ValueKind: JsonValueKind.Object } pimg)
                            e.Files.Add(new FileRef(S(pimg, "sha256"), S(pimg, "sha1"), S(pimg, "fileName"), S(pimg, "md5")));
                        break;
                    case "analyzedMessageEvidence":
                        e.Emails.Add(new EmailRef(S(ev, "networkMessageId"), S(ev, "recipientEmailAddress"),
                            S(O(ev, "p1Sender"), "emailAddress") ?? S(O(ev, "p2Sender"), "emailAddress"), S(ev, "subject")));
                        if (O(ev, "urls") is { ValueKind: JsonValueKind.Array } urls)
                            e.Urls.AddRange(urls.EnumerateArray().Select(u => u.GetString()).OfType<string>());
                        break;
                    case "mailClusterEvidence":
                        if (O(ev, "networkMessageIds") is { ValueKind: JsonValueKind.Array } nmids)
                            foreach (var nmid in nmids.EnumerateArray().Select(x => x.GetString()).OfType<string>())
                                e.Emails.Add(new EmailRef(nmid, null, null, S(ev, "query")));
                        break;
                    case "mailboxEvidence":
                        e.Users.Add(new UserRef(S(ev, "primaryAddress") ?? S(O(ev, "userAccount"), "userPrincipalName"), S(O(ev, "userAccount"), "azureAdUserId"), S(ev, "displayName")));
                        break;
                    case "mailboxConfigurationEvidence":
                        var mbox = S(ev, "mailboxPrimaryAddress");
                        var moid = S(ev, "externalDirectoryObjectId");
                        if (mbox is not null || moid is not null) e.Users.Add(new UserRef(mbox, moid, null));
                        break;
                    case "oauthApplicationEvidence":
                        e.CloudApps.Add(new CloudAppRef(S(ev, "appId"), S(ev, "objectId"), S(ev, "displayName"), "oauth_app"));
                        break;
                    case "servicePrincipalEvidence":
                        e.CloudApps.Add(new CloudAppRef(S(ev, "appId"), S(ev, "objectId"), S(ev, "appDisplayName") ?? S(ev, "servicePrincipalName"), "service_principal"));
                        break;
                    case "cloudApplicationEvidence":
                        e.CloudApps.Add(new CloudAppRef(S(ev, "appId")?.ToString(), S(ev, "instanceId"), S(ev, "displayName"), "cloud_app"));
                        break;
                    case "azureResourceEvidence":
                        e.AzureResources.Add(new AzureResourceRef(S(ev, "resourceId"), S(ev, "resourceName"), S(ev, "resourceType")));
                        break;
                }
            }
        }
        foreach (var u in e.Urls)
            if (Uri.TryCreate(u, UriKind.Absolute, out var parsed) && parsed.Host.Length > 0) e.Domains.Add(parsed.Host.ToLowerInvariant().TrimEnd('.'));
        return Dedupe(e);
    }

    private static void AddDevice(IncidentEntities e, string? id, string? name)
    {
        if (id is null && name is null) return;
        e.Devices.Add(new DeviceRef(id, name));
    }

    private static void AddUser(IncidentEntities e, JsonElement? ua)
    {
        if (ua is not { ValueKind: JsonValueKind.Object }) return;
        var upn = S(ua, "userPrincipalName");
        var oid = S(ua, "azureAdUserId");
        var name = S(ua, "displayName") ?? S(ua, "accountName");
        if (upn is null && oid is null && name is null) return;
        e.Users.Add(new UserRef(upn, oid, name));
    }

    private static IncidentEntities Dedupe(IncidentEntities e) => e with
    {
        Devices = MergeDevices(e.Devices),
        Users = MergeUsers(e.Users),
        Files = e.Files.Where(f => f.Sha256 is not null || f.Sha1 is not null || f.Md5 is not null || f.Name is not null)
            .DistinctBy(f => (f.Sha256 ?? f.Sha1 ?? f.Md5 ?? f.Name)!.ToLowerInvariant()).ToList(),
        Emails = e.Emails.DistinctBy(m => $"{m.NetworkMessageId}|{m.Recipient}".ToLowerInvariant()).ToList(),
        Ips = e.Ips.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        Urls = e.Urls.Distinct(StringComparer.Ordinal).ToList(),
        Domains = e.Domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        Mitre = e.Mitre.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        CloudApps = MergeCloudApps(e.CloudApps),
        AzureResources = e.AzureResources.Where(r => r.ResourceId is not null || r.Name is not null)
            .DistinctBy(r => (r.ResourceId ?? r.Name)!.ToLowerInvariant()).ToList(),
    };

    /// <summary>Merges device evidence across alerts so (MdeDeviceId, null) + (MdeDeviceId, Name) keeps both fields.</summary>
    private static List<DeviceRef> MergeDevices(List<DeviceRef> raw)
    {
        var merged = new List<DeviceRef>();
        foreach (var d in raw)
        {
            var cur = d;
            for (var i = merged.Count - 1; i >= 0; i--)
            {
                var x = merged[i];
                if ((cur.MdeDeviceId is not null && string.Equals(x.MdeDeviceId, cur.MdeDeviceId, StringComparison.OrdinalIgnoreCase)) ||
                    (cur.Name is not null && string.Equals(x.Name, cur.Name, StringComparison.OrdinalIgnoreCase)))
                {
                    cur = new DeviceRef(x.MdeDeviceId ?? cur.MdeDeviceId, x.Name ?? cur.Name);
                    merged.RemoveAt(i);
                }
            }
            merged.Add(cur);
        }
        return merged;
    }

    /// <summary>Merges user evidence across alerts so UPN, Entra object id and display name stay linked (including transitive bridges).</summary>
    private static List<UserRef> MergeUsers(List<UserRef> raw)
    {
        var merged = new List<UserRef>();
        foreach (var u in raw)
        {
            var cur = u;
            for (var i = merged.Count - 1; i >= 0; i--)
            {
                var x = merged[i];
                if ((cur.AadUserId is not null && string.Equals(x.AadUserId, cur.AadUserId, StringComparison.OrdinalIgnoreCase)) ||
                    (cur.Upn is not null && string.Equals(x.Upn, cur.Upn, StringComparison.OrdinalIgnoreCase)))
                {
                    cur = new UserRef(x.Upn ?? cur.Upn, x.AadUserId ?? cur.AadUserId, x.Name ?? cur.Name);
                    merged.RemoveAt(i);
                }
            }
            merged.Add(cur);
        }
        return merged;
    }

    private static List<CloudAppRef> MergeCloudApps(List<CloudAppRef> raw)
    {
        var merged = new List<CloudAppRef>();
        foreach (var a in raw)
        {
            if (a.AppId is null && a.ObjectId is null && a.DisplayName is null) continue;
            var cur = a;
            for (var i = merged.Count - 1; i >= 0; i--)
            {
                var x = merged[i];
                if ((cur.ObjectId is not null && string.Equals(x.ObjectId, cur.ObjectId, StringComparison.OrdinalIgnoreCase)) ||
                    (cur.AppId is not null && string.Equals(x.AppId, cur.AppId, StringComparison.OrdinalIgnoreCase)) ||
                    (cur.ObjectId is null && cur.AppId is null && cur.DisplayName is not null && string.Equals(x.DisplayName, cur.DisplayName, StringComparison.OrdinalIgnoreCase)))
                {
                    cur = new CloudAppRef(x.AppId ?? cur.AppId, x.ObjectId ?? cur.ObjectId, x.DisplayName ?? cur.DisplayName, x.Kind ?? cur.Kind);
                    merged.RemoveAt(i);
                }
            }
            merged.Add(cur);
        }
        return merged;
    }

    private static string? S(JsonElement? e, string name) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static JsonElement? O(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : null;
}
