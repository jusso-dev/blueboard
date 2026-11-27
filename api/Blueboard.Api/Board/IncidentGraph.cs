using System.Text.Json;
using System.Text.RegularExpressions;
using Blueboard.Api.Actions;
using Blueboard.Contracts;

namespace Blueboard.Api.Board;

/// <summary>An action linked to the incident, for marking the graph nodes it targets.</summary>
public sealed record GraphActionInput(string Kind, string Status, JsonElement Params, bool Held);

/// <summary>
/// The attack graph for one incident, derived on read from the Defender/Sentinel evidence: entities as nodes and the
/// relationships the evidence states as edges (a process's device and user, a message's sender and recipient, a DNS
/// record's addresses). Where the evidence only puts two entities in the same alert, the edge is marked inferred.
/// Nodes carry the strongest verdict (Defender evidence verdict, then board IOCs), a compromised flag, a protected flag
/// from policy (the matching entry is named for admins only) and the action kinds pending or executed against them.
/// </summary>
public static partial class IncidentGraph
{
    public const string Notice =
        "Graph built by the board from Defender/Sentinel evidence. inferred=true edges are only co-occurrence in the same alert or a command-line mention. Nodes with in_evidence=false come from board IOC messages, not Defender. All labels are untrusted data.";

    public const int MaxNodes = 300;
    private static readonly Dictionary<string, int> VerdictRank = new() { ["malicious"] = 3, ["suspicious"] = 2, ["benign"] = 1 };

    [GeneratedRegex(@"https?://[^\s'""<>()]+|\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.IgnoreCase)]
    private static partial Regex CommandLineTarget();

    private sealed class Node
    {
        public required string Id;
        public required string Kind;
        public required string Label;
        public HashSet<string> Keys = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Alerts = new(StringComparer.Ordinal);
        public bool InEvidence = true;
        public string? Verdict;
        public bool Compromised;
        public HashSet<string> Pending = [];
        public HashSet<string> Executed = [];
    }

    private sealed class Builder(IReadOnlyDictionary<string, string> deviceNames)
    {
        public readonly List<Node> Nodes = [];
        public readonly Dictionary<(string, string, string), (HashSet<string> Alerts, bool Inferred)> Edges = [];
        public bool Truncated;

        private static string Family(string kind) => kind switch
        {
            "service_principal" or "cloud_app" => "app",
            "mailbox" or "user" => "identity",
            _ => kind,
        };

        public Node? Get(string kind, string? label, params string?[] keys)
        {
            var ks = keys.OfType<string>().Select(k => k.Trim()).Where(k => k.Length > 0).ToList();
            if (ks.Count == 0 && string.IsNullOrWhiteSpace(label)) return null;
            if (ks.Count == 0) ks.Add(label!.Trim());
            if (kind == "device")
                foreach (var k in ks.ToList())
                {
                    if (deviceNames.TryGetValue(k, out var n)) ks.Add(n);
                    if (k.Contains('.') && !System.Net.IPAddress.TryParse(k, out _)) ks.Add(k.Split('.')[0]);
                }
            var family = Family(kind);
            var node = Nodes.FirstOrDefault(n => Family(n.Kind) == family && (n.Kind == kind || family == "identity" && n.Kind == "user") && n.Keys.Overlaps(ks))
                       ?? Nodes.FirstOrDefault(n => Family(n.Kind) == family && n.Keys.Overlaps(ks));
            if (node is null)
            {
                if (Nodes.Count >= MaxNodes) { Truncated = true; return null; }
                node = new Node { Id = $"{kind}:{ks[0].ToLowerInvariant()}", Kind = kind, Label = (label ?? ks[0]).Trim() };
                Nodes.Add(node);
            }
            node.Keys.UnionWith(ks);
            if (kind == "user" && node.Kind == "mailbox") node.Kind = "user"; // a mailbox seen first is the same identity
            // Prefer a human label (UPN, host name, file name) over an id once one turns up.
            if (label is { Length: > 0 } && (node.Label == node.Keys.First() || LooksLikeId(node.Label)) && !LooksLikeId(label)) node.Label = label.Trim();
            return node;
        }

        public void Edge(Node? from, Node? to, string relation, string? alert, bool inferred)
        {
            if (from is null || to is null || from == to) return;
            var key = (from.Id, to.Id, relation);
            if (!Edges.TryGetValue(key, out var e)) e = (new HashSet<string>(StringComparer.Ordinal), inferred);
            if (alert is not null) e.Alerts.Add(alert);
            Edges[key] = (e.Alerts, e.Inferred && inferred);
        }
    }

    private static bool LooksLikeId(string s) =>
        Guid.TryParse(s, out _) || Regex.IsMatch(s, "^[0-9a-f]{32,64}$", RegexOptions.IgnoreCase);

    public static IncidentGraphResult Build(
        Guid incidentId, string graphId, JsonElement data, IReadOnlyList<Message> messages, IReadOnlyList<GraphActionInput> actions,
        Policy policy, bool includeProtectedNames)
    {
        var entities = Graph.Entities.Extract(data);
        var deviceNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in entities.Devices.Where(d => d.MdeDeviceId is not null && d.Name is not null)) deviceNames[d.MdeDeviceId!] = d.Name!;
        var b = new Builder(deviceNames);

        if (data.TryGetProperty("alerts", out var alerts) && alerts.ValueKind == JsonValueKind.Array)
        {
            var ai = 0;
            foreach (var alert in alerts.EnumerateArray())
            {
                ai++;
                var alertId = Str(alert, "id") ?? $"alert-{ai}";
                if (!alert.TryGetProperty("evidence", out var evList) || evList.ValueKind != JsonValueKind.Array) continue;
                var inAlert = new List<Node>();
                Node Seen(Node n, JsonElement? ev = null)
                {
                    n.Alerts.Add(alertId);
                    if (ev is { } e) ApplyEvidenceVerdict(n, e);
                    if (!inAlert.Contains(n)) inAlert.Add(n);
                    return n;
                }
                Node? Track(Node? n, JsonElement? ev = null) => n is null ? null : Seen(n, ev);

                var stated = new HashSet<(string, string)>(); // pairs joined by a stated relationship, so co-occurrence doesn't duplicate them
                void Stated(Node? from, Node? to, string rel)
                {
                    if (from is null || to is null) return;
                    b.Edge(from, to, rel, alertId, inferred: false);
                    stated.Add((from.Id, to.Id));
                    stated.Add((to.Id, from.Id));
                }

                foreach (var ev in evList.EnumerateArray())
                {
                    var type = (Str(ev, "@odata.type") ?? "").Replace("#microsoft.graph.security.", "");
                    switch (type)
                    {
                        case "deviceEvidence":
                        {
                            var dev = Track(b.Get("device", Str(ev, "deviceDnsName") ?? Str(ev, "hostName"), Str(ev, "mdeDeviceId"), Str(ev, "deviceDnsName"), Str(ev, "hostName")), ev);
                            foreach (var ipk in new[] { "lastIpAddress", "lastExternalIpAddress" })
                                if (Str(ev, ipk) is { } ip) Stated(dev, Track(b.Get("ip", ip, ip)), "connected from");
                            if (O(ev, "loggedOnUsers") is { ValueKind: JsonValueKind.Array } lus)
                                foreach (var lu in lus.EnumerateArray())
                                    if (Str(lu, "accountName") is { } acct)
                                    {
                                        var upn = Str(lu, "userPrincipalName");
                                        var existing = b.Nodes.FirstOrDefault(n => n.Kind == "user" && (n.Keys.Contains(acct) || (upn is not null && n.Keys.Contains(upn))));
                                        Stated(existing ?? Track(b.Get("user", upn ?? acct, upn, acct)), dev, "logged on to");
                                    }
                            break;
                        }
                        case "userEvidence":
                            Track(UserNode(b, O(ev, "userAccount")), ev);
                            break;
                        case "ipEvidence":
                            Track(b.Get("ip", Str(ev, "ipAddress"), Str(ev, "ipAddress")), ev);
                            break;
                        case "urlEvidence":
                        {
                            var url = Str(ev, "url");
                            var u = Track(b.Get("url", url, url), ev);
                            if (url is not null && Uri.TryCreate(url, UriKind.Absolute, out var parsed) && parsed.Host.Length > 0)
                                Stated(u, Track(b.Get("domain", parsed.Host.ToLowerInvariant(), parsed.Host.ToLowerInvariant())), "hosted on");
                            break;
                        }
                        case "dnsEvidence":
                        {
                            var dom = Str(ev, "domainName")?.ToLowerInvariant().TrimEnd('.');
                            var dn = Track(b.Get("domain", dom, dom), ev);
                            if (Str(O(ev, "hostIpAddress"), "ipAddress") is { } hip) Stated(dn, Track(b.Get("ip", hip, hip)), "resolves to");
                            if (O(ev, "ipAddresses") is { ValueKind: JsonValueKind.Array } ips)
                                foreach (var x in ips.EnumerateArray())
                                    if (Str(x, "ipAddress") is { } dip) Stated(dn, Track(b.Get("ip", dip, dip)), "resolves to");
                            break;
                        }
                        case "fileEvidence":
                        case "fileHashEvidence":
                        {
                            var fd = O(ev, "fileDetails");
                            var file = Track(FileNode(b, fd, Str(ev, "algorithm"), Str(ev, "value")), ev);
                            if (Str(ev, "mdeDeviceId") is { } fdev) Stated(Track(b.Get("device", null, fdev)), file, "has file");
                            break;
                        }
                        case "processEvidence":
                        {
                            var img = O(ev, "imageFile");
                            var name = Str(img, "fileName") ?? "process";
                            var proc = Track(b.Get("process", name, ProcessKey(Str(ev, "mdeDeviceId"), Pid(ev, "processId"), img, name)), ev);
                            var imageFile = Track(FileNode(b, img, null, null));
                            Stated(proc, imageFile, "image");
                            var dev = Str(ev, "mdeDeviceId") is { } pdev ? Track(b.Get("device", null, pdev)) : null;
                            Stated(dev, proc, "ran");
                            var user = Track(UserNode(b, O(ev, "userAccount")));
                            Stated(user, proc, "launched");
                            if (user is not null && dev is not null) Stated(user, dev, "logged on to");
                            if (O(ev, "parentProcessImageFile") is { ValueKind: JsonValueKind.Object } pimg && Str(pimg, "fileName") is { } pname)
                            {
                                var parent = Track(b.Get("process", pname, ProcessKey(Str(ev, "mdeDeviceId"), Pid(ev, "parentProcessId"), pimg, pname)));
                                Stated(parent, proc, "spawned");
                                Stated(dev, parent, "ran");
                            }
                            if (Str(ev, "processCommandLine") is { } cmd)
                                foreach (Match m in CommandLineTarget().Matches(cmd))
                                {
                                    var v = m.Value.TrimEnd('.', ',', ';', '\'', '"', ')');
                                    var target = v.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? b.Get("url", v, v) : b.Get("ip", v, v);
                                    if (target is null) continue;
                                    target.Alerts.Add(alertId);
                                    b.Edge(proc, target, "connected to", alertId, inferred: true);
                                }
                            break;
                        }
                        case "analyzedMessageEvidence":
                        {
                            var nmid = Str(ev, "networkMessageId");
                            var subject = Str(ev, "subject");
                            var mail = Track(b.Get("email", subject is { Length: > 0 } ? $"\"{Trunc(subject, 80)}\"" : nmid, nmid), ev);
                            var sender = Str(O(ev, "p1Sender"), "emailAddress") ?? Str(O(ev, "p2Sender"), "emailAddress");
                            if (sender is not null) Stated(Track(b.Get("mailbox", sender, sender)), mail, "sent");
                            if (Str(ev, "recipientEmailAddress") is { } rcpt) Stated(mail, Track(MailboxNode(b, rcpt)), "delivered to");
                            if (O(ev, "urls") is { ValueKind: JsonValueKind.Array } urls)
                                foreach (var u in urls.EnumerateArray().Select(x => x.GetString()).OfType<string>())
                                    Stated(mail, Track(b.Get("url", u, u)), "contains link");
                            if (Str(ev, "senderIp") is { } sip) Stated(mail, Track(b.Get("ip", sip, sip)), "sent from");
                            break;
                        }
                        case "mailClusterEvidence":
                            if (O(ev, "networkMessageIds") is { ValueKind: JsonValueKind.Array } nmids)
                                foreach (var id in nmids.EnumerateArray().Select(x => x.GetString()).OfType<string>().Take(20))
                                    Track(b.Get("email", id, id), ev);
                            break;
                        case "mailboxEvidence":
                        {
                            var addr = Str(ev, "primaryAddress");
                            var mbx = Track(MailboxNode(b, addr), ev);
                            Stated(Track(UserNode(b, O(ev, "userAccount"))), mbx, "owns");
                            break;
                        }
                        case "mailboxConfigurationEvidence":
                        {
                            var mbx = Track(MailboxNode(b, Str(ev, "mailboxPrimaryAddress")), ev);
                            if (mbx is not null) mbx.Compromised = true; // a rule/forward in incident evidence means the mailbox was changed by the attacker
                            break;
                        }
                        case "oauthApplicationEvidence":
                            Track(b.Get("cloud_app", Str(ev, "displayName"), Str(ev, "objectId"), Str(ev, "appId"), Str(ev, "displayName")), ev);
                            break;
                        case "servicePrincipalEvidence":
                            Track(b.Get("service_principal", Str(ev, "appDisplayName") ?? Str(ev, "servicePrincipalName"), Str(ev, "servicePrincipalObjectId") ?? Str(ev, "objectId"), Str(ev, "appId"), Str(ev, "appDisplayName")), ev);
                            break;
                        case "cloudApplicationEvidence":
                            Track(b.Get("cloud_app", Str(ev, "displayName"), Str(ev, "instanceId"), Str(ev, "displayName")), ev);
                            break;
                        case "azureResourceEvidence":
                            Track(b.Get("azure_resource", Str(ev, "resourceName"), Str(ev, "resourceId"), Str(ev, "resourceName")), ev);
                            break;
                        case "blobEvidence":
                        case "blobContainerEvidence":
                            Track(b.Get("azure_resource", Str(ev, "name"), Str(ev, "url"), Str(ev, "name")), ev);
                            break;
                        case "cloudLogonSessionEvidence":
                        {
                            var user = Track(UserNode(b, O(O(ev, "account"), "userAccount")));
                            if (Str(ev, "ipAddress") is { } lip) Stated(user, Track(b.Get("ip", lip, lip)), "signed in from");
                            break;
                        }
                    }
                }

                // Same-alert relationships the evidence implies but doesn't state.
                var users = inAlert.Where(n => n.Kind == "user").ToList();
                var devices = inAlert.Where(n => n.Kind == "device").ToList();
                void Infer(Node from, Node to, string rel)
                {
                    if (!stated.Contains((from.Id, to.Id))) b.Edge(from, to, rel, alertId, inferred: true);
                }
                foreach (var app in inAlert.Where(n => n.Kind is "cloud_app" or "service_principal"))
                    foreach (var u in users) Infer(app, u, "granted");
                foreach (var res in inAlert.Where(n => n.Kind == "azure_resource"))
                    foreach (var actor in users.Concat(inAlert.Where(n => n.Kind == "service_principal"))) Infer(actor, res, "accessed");
                if (devices.Count == 1)
                {
                    foreach (var u in users) Infer(u, devices[0], "logged on to");
                    foreach (var ip in inAlert.Where(n => n.Kind == "ip")) Infer(devices[0], ip, "connected to");
                    foreach (var f in inAlert.Where(n => n.Kind == "file" && !b.Edges.Keys.Any(k => k.Item2 == n.Id))) Infer(devices[0], f, "has file");
                    foreach (var u in inAlert.Where(n => n.Kind == "url" && !b.Edges.Keys.Any(k => k.Item2 == n.Id && k.Item3 != "hosted on"))) Infer(devices[0], u, "connected to");
                }
                else if (devices.Count == 0)
                    foreach (var u in users)
                        foreach (var ip in inAlert.Where(n => n.Kind == "ip")) Infer(u, ip, "signed in from");
                foreach (var u in users)
                    foreach (var mbx in inAlert.Where(n => n.Kind == "mailbox" && n.Keys.Overlaps(u.Keys))) Infer(u, mbx, "owns");
                foreach (var mbx in inAlert.Where(n => n.Kind == "mailbox"))
                    foreach (var u in users.Where(u => u.Keys.Overlaps(mbx.Keys))) if (mbx.Compromised) u.Compromised = true;
            }
        }

        // Board IOCs: the strongest verdict reported by anyone; values not in the evidence become flagged nodes.
        foreach (var m in messages.Where(m => m.Type == "ioc").OrderBy(m => long.TryParse(m.Seq, out var s) ? s : 0))
        {
            if (m.Payload is not { ValueKind: JsonValueKind.Object } p || !p.TryGetProperty("indicators", out var list) || list.ValueKind != JsonValueKind.Array) continue;
            foreach (var i in list.EnumerateArray())
            {
                if (Str(i, "value") is not { Length: > 0 } value) continue;
                var verdict = Str(i, "verdict") ?? "unknown";
                var kind = Str(i, "kind") switch
                {
                    "ip" => "ip", "domain" => "domain", "url" => "url", "sha1" or "sha256" or "md5" => "file",
                    "user" => "user", "email" => "mailbox", "device" => "device", _ => null,
                };
                if (kind is null) continue;
                var node = b.Nodes.FirstOrDefault(n => n.Keys.Contains(value.Trim()));
                if (node is null)
                {
                    if (!VerdictRank.ContainsKey(verdict) || verdict == "benign") continue; // don't add noise for unknowns
                    node = b.Get(kind, value, value);
                    if (node is null) continue;
                    node.InEvidence = false;
                }
                Raise(node, verdict);
                if (verdict == "malicious" && node.Kind is "user" or "device" or "mailbox") node.Compromised = true;
            }
        }

        // Verdicts and compromise from executed or pending actions; protected flags from policy.
        foreach (var a in actions)
        {
            if (!Catalog.All.TryGetValue(a.Kind, out var def)) continue;
            Targets targets;
            try { targets = def.TargetsOf(def.Validate(a.Params)); }
            catch (Exception ex) when (ex is Core.BoardException or InvalidOperationException or JsonException) { continue; }
            var keys = targets.All.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var pending = ActionStatus.Open.Contains(a.Status) || (a.Status is "approved" or "running");
            foreach (var n in b.Nodes.Where(n => n.Keys.Overlaps(keys)))
            {
                if (pending) n.Pending.Add(a.Kind);
                else if (a.Status == "succeeded")
                {
                    n.Executed.Add(a.Kind);
                    if (a.Kind == "confirm_user_compromised") n.Compromised = true;
                }
            }
        }

        var pu = Lower(policy.ProtectedUsers);
        var pd = Lower(policy.ProtectedDevices);
        var pa = Lower(policy.ProtectedApps);
        var pi = Lower(policy.ProtectedIndicators);
        string? ProtectedEntry(Node n)
        {
            var keys = n.Keys.Select(k => k.ToLowerInvariant().TrimEnd('.')).ToList();
            HashSet<string>? list = n.Kind switch
            {
                "user" or "mailbox" => pu, "device" => pd, "cloud_app" or "service_principal" => pa, _ => null,
            };
            if (list is not null && keys.FirstOrDefault(list.Contains) is { } hit) return hit;
            if (n.Kind is "ip" or "domain" or "url" or "mailbox")
                foreach (var k in keys)
                    if (PolicyEngine.MatchesProtectedIndicator(k, pi)) return pi.FirstOrDefault(e => PolicyEngine.MatchesProtectedIndicator(k, new HashSet<string> { e })) ?? k;
            return null;
        }

        var nodes = b.Nodes.Select(n =>
        {
            var hit = ProtectedEntry(n);
            var compromised = n.Compromised || (n.Kind is "user" or "device" or "mailbox" && n.Verdict == "malicious");
            return new GraphNode(n.Id, n.Kind, n.Label, n.Keys.Order(StringComparer.OrdinalIgnoreCase).Take(10).ToArray(), [.. n.Alerts.Order(StringComparer.Ordinal)],
                n.InEvidence, n.Verdict, compromised, hit is not null, includeProtectedNames ? hit : null,
                [.. n.Pending.Order(StringComparer.Ordinal)], [.. n.Executed.Order(StringComparer.Ordinal)]);
        }).ToList();
        var edges = b.Edges.Select(e => new GraphEdge(e.Key.Item1, e.Key.Item2, e.Key.Item3, [.. e.Value.Alerts.Order(StringComparer.Ordinal)], e.Value.Inferred))
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Relation, StringComparer.Ordinal).ToList();
        return new IncidentGraphResult(incidentId, graphId, nodes, edges, b.Truncated, Notice);
    }

    /// <summary>One key per process on a device, so a child's parent and that parent's own evidence are one node.</summary>
    private static string ProcessKey(string? device, string? pid, JsonElement? image, string name) =>
        $"proc:{device?.ToLowerInvariant()}:{pid ?? Str(image, "sha256")?.ToLowerInvariant() ?? name.ToLowerInvariant()}";

    private static string? Pid(JsonElement e, string k) =>
        Str(e, k) ?? (e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.ToString() : null);

    private static Node? UserNode(Builder b, JsonElement? ua)
    {
        if (ua is not { ValueKind: JsonValueKind.Object }) return null;
        var upn = Str(ua, "userPrincipalName");
        var oid = Str(ua, "azureAdUserId");
        var name = Str(ua, "displayName");
        var acct = Str(ua, "accountName");
        if (upn is null && oid is null && acct is null) return null;
        return b.Get("user", upn ?? name ?? acct, upn, oid, acct);
    }

    /// <summary>A mailbox joins an existing user node with the same address, so the graph shows one identity.</summary>
    private static Node? MailboxNode(Builder b, string? address)
    {
        if (string.IsNullOrWhiteSpace(address)) return null;
        var user = b.Nodes.FirstOrDefault(n => n.Kind == "user" && n.Keys.Contains(address));
        return user ?? b.Get("mailbox", address, address);
    }

    private static Node? FileNode(Builder b, JsonElement? f, string? algorithm, string? value)
    {
        var alg = algorithm?.ToLowerInvariant();
        var sha256 = Str(f, "sha256") ?? (alg is "sha256" or "filesha256" ? value : null);
        var sha1 = Str(f, "sha1") ?? (alg is "sha1" or "filesha1" ? value : null);
        var md5 = Str(f, "md5") ?? (alg is "md5" or "filemd5" ? value : null);
        var name = Str(f, "fileName");
        if (sha256 is null && sha1 is null && md5 is null) return name is null ? null : b.Get("file", name, $"file:{name}");
        return b.Get("file", name ?? sha256 ?? sha1 ?? md5, sha256, sha1, md5);
    }

    /// <summary>Defender evidence verdict ("malicious", "suspicious", "noThreatsFound") and roles ("compromised", "attacker").</summary>
    private static void ApplyEvidenceVerdict(Node n, JsonElement ev)
    {
        switch (Str(ev, "verdict"))
        {
            case "malicious": Raise(n, "malicious"); break;
            case "suspicious": Raise(n, "suspicious"); break;
            case "noThreatsFound": Raise(n, "benign"); break;
        }
        if (O(ev, "roles") is { ValueKind: JsonValueKind.Array } roles)
            foreach (var r in roles.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : null))
            {
                if (r is "compromised") n.Compromised = true;
                if (r is "attacker") Raise(n, "malicious");
            }
    }

    private static void Raise(Node n, string verdict)
    {
        if (!VerdictRank.TryGetValue(verdict, out var rank)) return;
        if (n.Verdict is null || rank > VerdictRank[n.Verdict]) n.Verdict = verdict;
    }

    private static HashSet<string> Lower(IEnumerable<string> xs) => xs.Select(x => x.ToLowerInvariant().TrimEnd('.')).ToHashSet();

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";

    private static string? Str(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static JsonElement? O(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) ? v : null;
}
