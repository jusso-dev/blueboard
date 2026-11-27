using Blueboard.Contracts;
using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Shared helpers for the approval, policy and rate limit tests.</summary>
internal static class A1
{
    public static JsonElement El(object o) => JsonSerializer.SerializeToElement(o);

    public static ActionRequest Isolate(string why = "Encoded PowerShell download on ws-042; isolate to contain the host.") =>
        new("isolate_device", El(new { machine_id = TestBoard.Device }), why, TestBoard.IncidentGraphId);

    public static ActionRequest Disable(string user = "ana@contoso.com") =>
        new("disable_user", El(new { user }), "Credential theft from ana's session on ws-042; disable to stop reuse.", TestBoard.IncidentGraphId);

    /// <summary>A board wired the way Program.cs wires it, on the fixture's database, with its own policy and a fake Microsoft API.</summary>
    public sealed class App
    {
        public required Db Db { get; init; }
        public required Policy Policy { get; init; }
        public required RateLimiter Limiter { get; init; }
        public required BoardService Board { get; init; }
        public required Broker Broker { get; init; }
        public required Blueboard.Api.Webhooks.WebhookService Hooks { get; init; }
        public required PlaybookRunner Playbooks { get; init; }
        public required Blueboard.Api.Intel.IntelService Intel { get; init; }
        public required GifService Gifs { get; init; }
        public required MemoryService Memory { get; init; }
        public required Enrichment Enrich { get; init; }
        public required Authenticator Auth { get; init; }
        public required BoardApi Api { get; init; }
        public required FakeMicrosoft Microsoft { get; init; }
    }

    /// <summary>limited: wire the rate limiter in (the limit tests). Off elsewhere so approval tests can file many requests.</summary>
    public static App Build(TestBoard t, Policy policy, Db? db = null, bool limited = false)
    {
        db ??= t.Db;
        var audit = new Audit(db);
        var limiter = new RateLimiter(db, audit, policy);
        var use = limited ? limiter : null;
        var board = new BoardService(db, audit, t.Settings, use);
        var fake = new FakeMicrosoft();
        var ms = new MsClient(new HttpClient(fake), new FakeCredential());
        var sys = new SystemPrincipal(db);
        var broker = new Broker(db, audit, board, ms, t.Settings, policy, sys, use);
        var enrich = new Enrichment(db, audit, board, ms, use);
        var auth = new Authenticator(t.Settings, new TokenValidator(t.Settings), db, audit);
        var ep = new Blueboard.Api.Http.Endpoint(auth, NullLogger<Blueboard.Api.Http.Endpoint>.Instance);
        var hooks = new Blueboard.Api.Webhooks.WebhookService(db, audit, board, sys, t.Settings);
        var books = PlaybookSet.Empty;
        var runner = new PlaybookRunner(db, board, sys, books);
        var ingest = new Ingest(db, board, ms, sys, t.Settings, runner);
        var search = new Search(db, board);
        var queries = new IncidentQueries(db, board, books);
        var intel = Intel(db, board, ms, enrich, sys, t.Settings);
        var gifs = new GifService(new HttpClient(), t.Settings, use);
        var memory = new MemoryService(db, audit, board, use);
        var api = new BoardApi(ep, board, search, new Reporting(db), broker, enrich, ingest, hooks, db, policy, queries, runner, books, intel, audit, gifs, memory, new AttackViews(db, board, policy));
        return new App { Db = db, Policy = policy, Limiter = limiter, Board = board, Broker = broker, Enrich = enrich, Auth = auth, Api = api, Hooks = hooks, Intel = intel, Gifs = gifs, Memory = memory, Playbooks = runner, Microsoft = fake };
    }

    /// <summary>Threat intel with every source off (the default), so these tests never fetch anything.</summary>
    private static Blueboard.Api.Intel.IntelService Intel(Db db, BoardService board, MsClient ms, Enrichment enrich, SystemPrincipal sys, Blueboard.Api.Core.Settings settings) =>
        new(db, new Blueboard.Api.Intel.IntelStore(db), new Blueboard.Api.Intel.TiFetcher(new Blueboard.Api.Intel.PgFetchCache(db), settings.Ti),
            new Blueboard.Api.Intel.MicrosoftIntel(enrich, ms, settings), board, new Search(db, board), sys, settings,
            NullLogger<Blueboard.Api.Intel.IntelService>.Instance);

    /// <summary>An HTTP request as the Functions host would hand it over, signed in as a dev principal.</summary>
    public static HttpRequest Request(string handle, string method = "GET", object? body = null, string? query = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Headers.Authorization = $"Bearer dev:{handle}";
        if (query is not null) ctx.Request.QueryString = new QueryString(query);
        if (body is not null)
        {
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(body));
            ctx.Request.Body = new MemoryStream(bytes);
            ctx.Request.ContentLength = bytes.Length;
        }
        ctx.Response.Body = new MemoryStream();
        return ctx.Request;
    }

    public static (int Status, JsonElement Body) Read(IActionResult r) => r switch
    {
        ContentResult c => (c.StatusCode ?? 200, c.Content is { Length: > 0 } s ? JsonDocument.Parse(s).RootElement.Clone() : default),
        NoContentResult => (204, default),
        _ => throw new InvalidOperationException($"unexpected result {r.GetType().Name}"),
    };

    /// <summary>Stands in for Graph and Defender: counts calls and answers every one with an empty hunting result.</summary>
    public sealed class FakeMicrosoft : HttpMessageHandler
    {
        private int _calls;
        public int Calls => _calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"schema":[],"results":[]}""", Encoding.UTF8, "application/json") });
        }
    }

    private sealed class FakeCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => new("test-token", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => new(GetToken(requestContext, cancellationToken));
    }
}
