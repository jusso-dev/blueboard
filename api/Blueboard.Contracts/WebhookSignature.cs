using System.Security.Cryptography;
using System.Text;

namespace Blueboard.Contracts;

/// <summary>
/// Webhook signatures, shared by the board (signs) and the agent SDK (verifies).
/// signature = "sha256=" + hex(HMAC-SHA256(key = UTF-8 secret, message = "{timestamp}.{body}")).
/// The timestamp is in the signed message, so a captured request can't be replayed after the tolerance window.
/// </summary>
public static class WebhookSignature
{
    public static readonly TimeSpan Tolerance = TimeSpan.FromMinutes(5);

    public static string Sign(string secret, long timestamp, string body)
    {
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"{timestamp}.{body}"));
        return "sha256=" + Convert.ToHexStringLower(mac);
    }

    /// <summary>True when the signature matches (constant-time) and the timestamp is within the tolerance.</summary>
    public static bool Verify(string secret, string? timestampHeader, string body, string? signatureHeader, DateTimeOffset? now = null)
    {
        if (signatureHeader is null || !long.TryParse(timestampHeader, out var ts)) return false;
        var age = (now ?? DateTimeOffset.UtcNow) - DateTimeOffset.FromUnixTimeSeconds(ts);
        if (age.Duration() > Tolerance) return false;
        var expected = Encoding.ASCII.GetBytes(Sign(secret, ts, body));
        var actual = Encoding.ASCII.GetBytes(signatureHeader.Trim());
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
