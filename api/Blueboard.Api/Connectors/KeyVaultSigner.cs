using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Blueboard.Api.Core;

namespace Blueboard.Api.Connectors;

/// <summary>Signs a JWT. Production: Azure Key Vault signs with a non-exportable RSA key. Tests: an in-memory key.</summary>
public interface IJwtSigner
{
    /// <summary>The RS256 signature (raw bytes) of SHA-256(<paramref name="signingInput"/>).</summary>
    Task<byte[]> SignRs256Async(string signingInput, CancellationToken ct);
}

/// <summary>
/// Key Vault sign operation (POST {key-id}/sign, RS256) with the Function App's managed identity, which needs only the
/// "Key Vault Crypto User" role on that key. The private key never leaves Key Vault, so there is no client secret to
/// steal from app settings. Key Vault is reached over its private endpoint in the production profile, so this client
/// does not use OutboundGuard's public-only handler: the host is pinned to *.vault.azure.net at start-up instead
/// (ConnectorSettings.CheckKeyVaultKeyUrl) and redirects are off.
/// </summary>
public sealed class KeyVaultSigner(HttpClient http, string keyUrl, TokenCredential? credential = null) : IJwtSigner
{
    public const string ApiVersion = "7.4";
    private readonly Lazy<TokenCredential> _cred = new(() => credential ?? new DefaultAzureCredential());

    public static HttpClient NewClient() =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, ConnectTimeout = TimeSpan.FromSeconds(5) }) { Timeout = TimeSpan.FromSeconds(15) };

    public async Task<byte[]> SignRs256Async(string signingInput, CancellationToken ct)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(signingInput));
        var token = await _cred.Value.GetTokenAsync(new TokenRequestContext(["https://vault.azure.net/.default"]), ct);
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{keyUrl.TrimEnd('/')}/sign?api-version={ApiVersion}")
        {
            Content = ConnectorHttp.JsonBody(new { alg = "RS256", value = Base64Url(digest) }),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var res = await http.SendAsync(req, ct);
        var text = await res.Content.ReadAsStringAsync(ct);
        if (!res.IsSuccessStatusCode)
            throw new BoardException($"Key Vault sign failed: {(int)res.StatusCode} (does the board's identity have Key Vault Crypto User on the Okta signing key?)", 502);
        using var doc = JsonDocument.Parse(text);
        return FromBase64Url(doc.RootElement.GetProperty("value").GetString()!);
    }

    public static string Base64Url(ReadOnlySpan<byte> b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t.PadRight(t.Length + (4 - t.Length % 4) % 4, '='));
    }
}

/// <summary>Tests only: signs with an in-memory RSA key.</summary>
public sealed class RsaJwtSigner(RSA rsa) : IJwtSigner
{
    public Task<byte[]> SignRs256Async(string signingInput, CancellationToken ct) =>
        Task.FromResult(rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
}

/// <summary>Builds the private_key_jwt client assertion Okta's org authorization server requires for client credentials.</summary>
public static class ClientAssertion
{
    /// <summary>iss = sub = client id, aud = the token endpoint, 5-minute lifetime, a random jti (Okta rejects a reused jti).</summary>
    public static async Task<string> CreateAsync(IJwtSigner signer, string clientId, string tokenEndpoint, string? kid, DateTimeOffset now, CancellationToken ct)
    {
        var header = kid is null ? (object)new { alg = "RS256", typ = "JWT" } : new { alg = "RS256", typ = "JWT", kid };
        var claims = new
        {
            iss = clientId,
            sub = clientId,
            aud = tokenEndpoint,
            iat = now.ToUnixTimeSeconds(),
            exp = now.AddMinutes(5).ToUnixTimeSeconds(),
            jti = Guid.NewGuid().ToString("N"),
        };
        var input = $"{KeyVaultSigner.Base64Url(JsonSerializer.SerializeToUtf8Bytes(header))}.{KeyVaultSigner.Base64Url(JsonSerializer.SerializeToUtf8Bytes(claims))}";
        var sig = await signer.SignRs256Async(input, ct);
        return $"{input}.{KeyVaultSigner.Base64Url(sig)}";
    }
}
