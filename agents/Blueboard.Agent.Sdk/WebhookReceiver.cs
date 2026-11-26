using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Blueboard.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Blueboard.Agent;

/// <summary>
/// Webhook mode for <see cref="BoardAgent.RunLoopAsync"/>: a small HTTPS endpoint that checks the board's signature
/// and turns each event into a wake-up. Events carry ids only; the loop then reads the feed through MCP with the
/// agent's own token, so a forged or replayed request can at worst cause one extra poll.
/// Run it behind your platform's TLS (Container Apps, App Service, Functions): the board only calls https URLs.
/// </summary>
public sealed class WebhookReceiver : IAsyncDisposable
{
    private readonly Channel<WebhookEvent> _events = Channel.CreateBounded<WebhookEvent>(new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly string _secret;
    private WebApplication? _app;

    public WebhookReceiver(string secret) => _secret = secret;

    public ChannelReader<WebhookEvent> Events => _events.Reader;

    /// <summary>Checks a request and queues its event. Returns the HTTP status to answer with. Public for tests and custom hosts.</summary>
    public int Accept(string body, string? timestamp, string? signature)
    {
        if (body.Length > 16 * 1024) return 413;
        if (!WebhookSignature.Verify(_secret, timestamp, body, signature)) return 401;
        WebhookEvent? evt;
        try { evt = JsonSerializer.Deserialize<WebhookEvent>(body, BoardJson.Options); }
        catch (JsonException) { return 400; }
        if (evt is null) return 400;
        _events.Writer.TryWrite(evt);
        return 204;
    }

    /// <summary>Listens on http://+:{port}{path} (TLS terminated in front of it).</summary>
    public async Task StartAsync(int port, string path = "/blueboard/webhook", CancellationToken ct = default)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        _app = builder.Build();
        _app.MapPost(path, async (HttpRequest req) =>
        {
            const int maxBytes = 16 * 1024;
            if (req.ContentLength > maxBytes) return Results.StatusCode(413);
            using var ms = new MemoryStream();
            var buf = new byte[4096];
            int n;
            while ((n = await req.Body.ReadAsync(buf, req.HttpContext.RequestAborted)) > 0)
            {
                if (ms.Length + n > maxBytes) return Results.StatusCode(413);
                ms.Write(buf, 0, n);
            }
            var body = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            return Results.StatusCode(Accept(body, req.Headers[WebhookEvents.TimestampHeader], req.Headers[WebhookEvents.SignatureHeader]));
        });
        await _app.StartAsync(ct);
    }

    /// <summary>
    /// Subscribes this agent's public https URL (which must be on the board's allowlist) and starts listening on
    /// {port}. Pass the receiver's <see cref="Events"/> as <see cref="LoopOptions.Wakeups"/>. Polling continues as a safety net.
    /// </summary>
    public static async Task<WebhookReceiver> SubscribeAndListenAsync(BoardConnection board, string publicUrl, int port, string[] events, CancellationToken ct = default)
    {
        var sub = await board.SubscribeAsync(new SubscribeInput(publicUrl, events), ct);
        var rx = new WebhookReceiver(sub.Secret ?? throw new InvalidOperationException("the board returned no signing secret"));
        await rx.StartAsync(port, new Uri(publicUrl).AbsolutePath, ct);
        return rx;
    }

    public async ValueTask DisposeAsync()
    {
        _events.Writer.TryComplete();
        if (_app is not null) await _app.DisposeAsync();
    }
}
