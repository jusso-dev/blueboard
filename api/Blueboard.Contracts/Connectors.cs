using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace Blueboard.Contracts;

public sealed record OktaUserInput(
    [Description("Okta user id (00u…) or Okta login / email (usually the same as the Entra UPN)")]
    [StringLength(320, MinimumLength = 3)] string User);

public sealed record OktaLogsInput(
    [Description("Okta user id (00u…) or login / email: events where they are the actor or the target")]
    [StringLength(320)] string? User = null,
    [Description("Client IP address the events came from")]
    [StringLength(45)] string? Ip = null,
    [Description("How far back to look, in hours (1-720, default 24)")]
    [Range(1, 720)] int Hours = 24,
    [Description("Most events to return, newest first (1-100, default 50)")]
    [Range(1, 100)] int Limit = 50);

/// <summary>A ServiceNow or Jira update posted to /api/connectors/{system}/inbound. Signed by the ticketing system (docs/INTEGRATIONS.md § Inbound).</summary>
public sealed record TicketInbound(
    [Description("ServiceNow sys_id or Jira issue id/key of the linked ticket")]
    [StringLength(100, MinimumLength = 1)] string Ticket,
    [Description("comment | attach_playbook")]
    [AllowedValues("comment", "attach_playbook")] string Type,
    [Description("comment: the ticket comment text (posted as untrusted data)")]
    [StringLength(4000)] string? Comment = null,
    [Description("Who wrote it in the ticketing system (display only)")]
    [StringLength(200)] string? Author = null,
    [Description("attach_playbook: playbook id from list_playbooks")]
    [StringLength(41)] string? PlaybookId = null);

public sealed record ConnectorTestInput(
    [Description("okta | servicenow | jira")]
    [AllowedValues("okta", "servicenow", "jira")] string Connector);

public sealed record TicketCreateInput(
    [Description("servicenow | jira")]
    [AllowedValues("servicenow", "jira")] string System);

/// <summary>Inbound ticket webhook signatures: "sha256=" + hex(HMAC-SHA256(secret, "{timestamp}.{nonce}.{body}")).</summary>
public static class TicketSignature
{
    public static readonly TimeSpan Tolerance = TimeSpan.FromMinutes(5);

    public static string Sign(string secret, long timestamp, string nonce, string body)
    {
        var mac = System.Security.Cryptography.HMACSHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret),
            System.Text.Encoding.UTF8.GetBytes($"{timestamp}.{nonce}.{body}"));
        return "sha256=" + Convert.ToHexStringLower(mac);
    }

    /// <summary>
    /// Null when the signature (constant-time compare) and timestamp (±5 minutes) hold and the nonce is well formed;
    /// otherwise why not. Nonce reuse is checked separately against the database.
    /// </summary>
    public static string? Check(string secret, string? timestampHeader, string? nonce, string body, string? signatureHeader, DateTimeOffset now)
    {
        if (signatureHeader is null || nonce is null || timestampHeader is null) return "missing signature, timestamp or nonce header";
        if (!long.TryParse(timestampHeader, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var ts)) return "invalid timestamp";
        if (nonce.Length is < 16 or > 128 || !nonce.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return "invalid nonce";
        DateTimeOffset at;
        try { at = DateTimeOffset.FromUnixTimeSeconds(ts); }
        catch (ArgumentOutOfRangeException) { return "invalid timestamp"; }
        if ((now - at).Duration() > Tolerance) return "timestamp outside the 5 minute window";
        var expected = System.Text.Encoding.ASCII.GetBytes(Sign(secret, ts, nonce, body));
        var actual = System.Text.Encoding.ASCII.GetBytes(signatureHeader.Trim());
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, actual) ? null : "signature mismatch";
    }
}
