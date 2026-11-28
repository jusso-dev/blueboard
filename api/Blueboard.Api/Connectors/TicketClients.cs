using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Blueboard.Api.Core;

namespace Blueboard.Api.Connectors;

public sealed record TicketRef(string Id, string Key, string? Url);

/// <summary>One ticketing system (ServiceNow or Jira). The board writes structured text only; it never forwards raw board messages.</summary>
public interface ITicketClient
{
    string System { get; }
    Task<TicketRef> CreateAsync(string title, string description, string severity, string boardIncidentId, CancellationToken ct);
    Task CommentAsync(string ticketId, string text, CancellationToken ct);
    /// <summary>Close or transition the ticket when the board incident resolves (if configured); otherwise just a note.</summary>
    Task ResolveAsync(string ticketId, string text, CancellationToken ct);
    Task ProbeAsync(CancellationToken ct);
}

/// <summary>
/// ServiceNow Table API with OAuth 2.0 client credentials (POST /oauth_token.do; needs the instance property
/// glide.oauth.inbound.client.credential.grant_type.enabled and an OAuth application user with only the itil-style role
/// needed for the table). Token cached until a minute before expiry. Ticket = a row in SERVICENOW_TABLE.
/// </summary>
public sealed class ServiceNowClient(ServiceNowSettings s, HttpClient http, bool mocked) : ITicketClient
{
    private readonly ConnectorHttp _http = new(http, s.InstanceUrl!, "ServiceNow");
    private readonly SemaphoreSlim _gate = new(1, 1);
    private (string Token, DateTimeOffset Expires)? _token;

    public string System => "servicenow";

    private async Task<AuthenticationHeaderValue?> AuthAsync(CancellationToken ct)
    {
        if (mocked) return null;
        if (_token is { } t && t.Expires > DateTimeOffset.UtcNow.AddMinutes(1)) return new("Bearer", t.Token);
        await _gate.WaitAsync(ct);
        try
        {
            if (_token is { } t2 && t2.Expires > DateTimeOffset.UtcNow.AddMinutes(1)) return new("Bearer", t2.Token);
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials", ["client_id"] = s.ClientId!, ["client_secret"] = s.ClientSecret!,
            });
            var (_, json, _) = await _http.SendAsync(HttpMethod.Post, "/oauth_token.do", null, form, ct);
            var access = json?.TryGetProperty("access_token", out var a) == true ? a.GetString() : null;
            if (access is null) throw new BoardException("ServiceNow token response had no access_token", 502);
            var secs = json!.Value.TryGetProperty("expires_in", out var e) && e.TryGetInt32(out var n) ? n : 1800;
            _token = (access, DateTimeOffset.UtcNow.AddSeconds(secs));
            return new("Bearer", access);
        }
        finally { _gate.Release(); }
    }

    private string TablePath(string? sysId = null) => $"/api/now/table/{s.Table}{(sysId is null ? "" : "/" + Uri.EscapeDataString(sysId))}";

    public async Task<TicketRef> CreateAsync(string title, string description, string severity, string boardIncidentId, CancellationToken ct)
    {
        var (impact, urgency) = severity.ToLowerInvariant() switch { "high" => ("1", "1"), "medium" => ("2", "2"), _ => ("3", "3") };
        var body = new Dictionary<string, string>
        {
            ["short_description"] = Clip(title, 160),
            ["description"] = Clip(description, 4000),
            ["impact"] = impact,
            ["urgency"] = urgency,
            ["correlation_id"] = boardIncidentId,
            ["correlation_display"] = "blueboard",
        };
        if (s.AssignmentGroup is { } g) body["assignment_group"] = g;
        var (_, json, _) = await _http.SendAsync(HttpMethod.Post, TablePath() + "?sysparm_fields=sys_id,number", await AuthAsync(ct), ConnectorHttp.JsonBody(body), ct);
        var r = json?.TryGetProperty("result", out var res) == true ? res : default;
        var sysId = OktaClient.Str(r, "sys_id") ?? throw new BoardException("ServiceNow create returned no sys_id", 502);
        var number = OktaClient.Str(r, "number") ?? sysId;
        return new TicketRef(sysId, number, $"{s.InstanceUrl}/{s.Table}.do?sys_id={Uri.EscapeDataString(sysId)}");
    }

    public async Task CommentAsync(string ticketId, string text, CancellationToken ct) =>
        await _http.SendAsync(HttpMethod.Patch, TablePath(ticketId) + "?sysparm_fields=sys_id", await AuthAsync(ct),
            ConnectorHttp.JsonBody(new Dictionary<string, string> { ["work_notes"] = Clip(text, 4000) }), ct);

    public async Task ResolveAsync(string ticketId, string text, CancellationToken ct)
    {
        var body = new Dictionary<string, string> { ["work_notes"] = Clip(text, 4000) };
        if (s.ResolveState is { } state)
        {
            body["state"] = state;
            body["close_notes"] = Clip(text, 4000);
            if (s.CloseCode is { } code) body["close_code"] = code;
        }
        await _http.SendAsync(HttpMethod.Patch, TablePath(ticketId) + "?sysparm_fields=sys_id", await AuthAsync(ct), ConnectorHttp.JsonBody(body), ct);
    }

    public async Task ProbeAsync(CancellationToken ct) =>
        await _http.SendAsync(HttpMethod.Get, TablePath() + "?sysparm_limit=1&sysparm_fields=sys_id", await AuthAsync(ct), null, ct);

    internal static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}

/// <summary>
/// Jira Cloud REST API v3 with an Atlassian API token (Basic email:token) for a dedicated integration account limited
/// to one project. Descriptions and comments are Atlassian Document Format (plain paragraphs: nothing is rendered as markup).
/// </summary>
public sealed class JiraClient(JiraSettings s, HttpClient http, bool mocked) : ITicketClient
{
    private readonly ConnectorHttp _http = new(http, s.BaseUrl!, "Jira");

    public string System => "jira";

    private AuthenticationHeaderValue? Auth() =>
        mocked ? null : new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{s.Email}:{s.ApiToken}")));

    /// <summary>Plain text as ADF: one paragraph per line, text nodes only (no marks, links or mentions).</summary>
    internal static object Adf(string text) => new
    {
        type = "doc",
        version = 1,
        content = text.Split('\n').Select(line => line.Length == 0
            ? (object)new { type = "paragraph", content = Array.Empty<object>() }
            : new { type = "paragraph", content = new object[] { new { type = "text", text = line } } }).ToArray(),
    };

    public async Task<TicketRef> CreateAsync(string title, string description, string severity, string boardIncidentId, CancellationToken ct)
    {
        var body = new
        {
            fields = new
            {
                project = new { key = s.ProjectKey },
                issuetype = new { name = s.IssueType },
                summary = ServiceNowClient.Clip(title.Replace('\n', ' '), 250),
                description = Adf(ServiceNowClient.Clip(description, 8000)),
                labels = new[] { "blueboard", $"severity-{severity.ToLowerInvariant()}" },
            },
        };
        var (_, json, _) = await _http.SendAsync(HttpMethod.Post, "/rest/api/3/issue", Auth(), ConnectorHttp.JsonBody(body), ct);
        var id = json is { } j ? OktaClient.Str(j, "id") : null;
        var key = json is { } k ? OktaClient.Str(k, "key") : null;
        if (id is null || key is null) throw new BoardException("Jira create returned no id/key", 502);
        return new TicketRef(id, key, $"{s.BaseUrl}/browse/{Uri.EscapeDataString(key)}");
    }

    public async Task CommentAsync(string ticketId, string text, CancellationToken ct) =>
        await _http.SendAsync(HttpMethod.Post, $"/rest/api/3/issue/{Uri.EscapeDataString(ticketId)}/comment", Auth(),
            ConnectorHttp.JsonBody(new { body = Adf(ServiceNowClient.Clip(text, 8000)) }), ct);

    public async Task ResolveAsync(string ticketId, string text, CancellationToken ct)
    {
        await CommentAsync(ticketId, text, ct);
        if (s.ResolveTransitionId is { } tid)
            await _http.SendAsync(HttpMethod.Post, $"/rest/api/3/issue/{Uri.EscapeDataString(ticketId)}/transitions", Auth(),
                ConnectorHttp.JsonBody(new { transition = new { id = tid } }), ct);
    }

    public async Task ProbeAsync(CancellationToken ct) =>
        await _http.SendAsync(HttpMethod.Get, $"/rest/api/3/project/{Uri.EscapeDataString(s.ProjectKey)}", Auth(), null, ct);

    /// <summary>The text of a Jira comment body: a plain string, or the text nodes of an ADF document.</summary>
    internal static string? TextOf(JsonElement body)
    {
        if (body.ValueKind == JsonValueKind.String) return body.GetString();
        if (body.ValueKind != JsonValueKind.Object) return null;
        var sb = new StringBuilder();
        void Walk(JsonElement n, int depth)
        {
            if (depth > 20 || sb.Length > 8000) return;
            if (n.ValueKind != JsonValueKind.Object) return;
            if (OktaClient.Str(n, "type") == "text" && OktaClient.Str(n, "text") is { } t) sb.Append(t);
            if (n.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.Array)
            {
                foreach (var child in c.EnumerateArray()) Walk(child, depth + 1);
                if (OktaClient.Str(n, "type") == "paragraph") sb.Append('\n');
            }
        }
        Walk(body, 0);
        return sb.ToString().Trim();
    }
}
