using System.Net;
using System.Net.Sockets;
using Blueboard.Api.Core;

namespace Blueboard.Api.Webhooks;

/// <summary>
/// Outbound webhook safety: https only, the host must be on the admin's exact allowlist, and every address it
/// resolves to must be public. The HTTP handler connects only to an address it has just checked, so a DNS answer
/// that changes between the check and the connection (DNS rebinding) can't reach an internal service.
/// </summary>
public static class OutboundGuard
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    public const int MaxResponseBytes = 64 * 1024;

    /// <summary>Checks the URL shape and allowlist (no DNS). Returns the lower-cased host.</summary>
    public static string CheckUrl(string url, IReadOnlyCollection<string> allowedHosts)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps)
            throw new BoardException("webhook url must be an absolute https URL");
        if (u.UserInfo.Length > 0) throw new BoardException("webhook url must not contain credentials");
        if (u.Fragment.Length > 0) throw new BoardException("webhook url must not contain a fragment");
        if (!u.IsDefaultPort && u.Port != 8443) throw new BoardException("webhook url must use port 443 (or 8443)");
        var host = u.IdnHost.ToLowerInvariant().TrimEnd('.');
        if (IPAddress.TryParse(host.Trim('[', ']'), out _)) throw new BoardException("webhook url must use a host name, not an IP address");
        if (allowedHosts.Count == 0) throw BoardException.Forbidden("webhooks are not enabled on this board (no allowed hosts)");
        if (!allowedHosts.Contains(host)) throw BoardException.Forbidden($"webhook host {host} is not on the board's allowlist; ask a board admin to add it");
        return host;
    }

    /// <summary>Resolves the host and refuses it unless every address is public.</summary>
    public static async Task<IPAddress[]> ResolvePublicAsync(string host, CancellationToken ct)
    {
        IPAddress[] addrs;
        try { addrs = await Dns.GetHostAddressesAsync(host, ct); }
        catch (SocketException) { throw new BoardException($"webhook host {host} does not resolve"); }
        if (addrs.Length == 0) throw new BoardException($"webhook host {host} does not resolve");
        if (addrs.FirstOrDefault(a => !IsPublic(a)) is { } bad)
            throw BoardException.Forbidden($"webhook host {host} resolves to a non-public address ({bad})");
        return addrs;
    }

    /// <summary>False for loopback, private, link-local, CGNAT, multicast, documentation, unspecified and other special ranges.</summary>
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast)) return false;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)       // 100.64.0.0/10 carrier-grade NAT
                || (b[0] == 169 && b[1] == 254)                     // link-local, cloud metadata (169.254.169.254)
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) // 192.0.0.0/24, TEST-NET-1
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19))       // benchmarking
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)       // TEST-NET-2
                || (b[0] == 203 && b[1] == 0 && b[2] == 113)        // TEST-NET-3
                || b[0] >= 224);                                    // multicast and reserved
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal || ip.IsIPv6Teredo) return false;
            var b = ip.GetAddressBytes();
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false; // 2001:db8::/32 documentation
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b) return false; // 64:ff9b::/96 NAT64 (could reach IPv4 internals)
            return true;
        }
        return false;
    }

    /// <summary>
    /// The handler webhook deliveries use: no redirects, no proxy, no cookies, TLS verification on (the default),
    /// and a connect step that resolves, checks and connects to the checked address.
    /// </summary>
    public static SocketsHttpHandler Handler() => new()
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectCallback = async (ctx, ct) =>
        {
            var addrs = await ResolvePublicAsync(ctx.DnsEndPoint.Host, ct);
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(addrs, ctx.DnsEndPoint.Port, ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        },
    };
}
