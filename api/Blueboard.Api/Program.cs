using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Mcp;
using Blueboard.Api.Webhooks;
using Blueboard.Api.Ops;
using Blueboard.Api.Intel;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var builder = FunctionsApplication.CreateBuilder(args);
builder.ConfigureFunctionsWebApplication();
// MCP tool input schemas come from the request records in Blueboard.Contracts (one schema source with REST/OpenAPI).
McpSchemas.Register(builder);

var settings = Settings.FromEnvironment();
var origins = MsOrigins.For(settings);
builder.Services.AddSingleton(settings);
builder.Services.AddSingleton(origins);
builder.Services.AddSingleton<Db>();
builder.Services.AddSingleton<Audit>();
builder.Services.AddSingleton<TokenValidator>();
builder.Services.AddSingleton<Authenticator>();
// Strict: an unknown key or kind in policy.json stops the worker here with the reason, rather than running on defaults.
builder.Services.AddSingleton(Policy.Load(settings));
builder.Services.AddSingleton<RateLimiter>();
builder.Services.AddHttpClient<MsClient>();
builder.Services.AddSingleton<PurviewContentGuard>();
builder.Services.AddSingleton<BoardService>();
builder.Services.AddSingleton<SystemPrincipal>();
builder.Services.AddSingleton<Broker>();
builder.Services.AddSingleton<Search>();
builder.Services.AddSingleton<Reporting>();
builder.Services.AddSingleton<Enrichment>();
builder.Services.AddSingleton(Playbooks.Current = Playbooks.Load(settings.PlaybooksDir));
builder.Services.AddHostedService<PlaybooksOnStart>();
builder.Services.AddSingleton<PlaybookRunner>();
builder.Services.AddSingleton<IncidentQueries>();
builder.Services.AddSingleton<Ingest>();
builder.Services.AddSingleton<WebhookService>(sp => new WebhookService(
    sp.GetRequiredService<Db>(), sp.GetRequiredService<Audit>(), sp.GetRequiredService<BoardService>(),
    sp.GetRequiredService<SystemPrincipal>(), settings, sp.GetRequiredService<ILogger<WebhookService>>(),
    sp.GetRequiredService<RateLimiter>()));
builder.Services.AddSingleton(sp => new Migrator(sp.GetRequiredService<Db>(), settings));
// Outbound notifications and audit export: no redirects, short timeouts, no HttpClient request logging, and live
// notification destinations are pinned through OutboundGuard's anti-DNS-rebinding handler. Only the ntfy URL's
// single-label host (a Docker service name in NOTIFY_ALLOWED_HOSTS) may resolve to a private network address.
static HttpMessageHandler NoRedirects() => new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) };
builder.Services.AddHttpClient<Notifier>()
    .ConfigurePrimaryHttpMessageHandler(() => origins.Mocked ? NoRedirects() : OutboundGuard.Handler(host => Notifier.MayBePrivate(settings, host)))
    .RemoveAllLoggers();
builder.Services.AddHttpClient<AuditExporter>().ConfigurePrimaryHttpMessageHandler(NoRedirects).RemoveAllLoggers();
builder.Services.AddSingleton<Retention>();
builder.Services.AddSingleton<Setup>();
builder.Services.AddSingleton<Participants>();
builder.Services.AddSingleton(settings.Ti);
builder.Services.AddSingleton<IntelStore>();
builder.Services.AddSingleton<IFetchCache, PgFetchCache>();
builder.Services.AddSingleton(sp => new TiFetcher(sp.GetRequiredService<IFetchCache>(), settings.Ti));
builder.Services.AddSingleton<MicrosoftIntel>();
builder.Services.AddSingleton<IntelService>();
builder.Services.AddHostedService<MigrateOnStart>();
builder.Services.AddSingleton<Blueboard.Api.Http.Endpoint>();

var app = builder.Build();
if (origins.Mocked)
{
    // Stdout as well as the logger: the worker's logs before the host starts aren't always forwarded.
    var line = $"DEMO MODE: Microsoft APIs are mocked (Graph {origins.Graph}, Defender {origins.Defender}). No Microsoft host is contacted.";
    Console.WriteLine(line);
    app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Blueboard").LogWarning("{DemoMode}", line);
}
app.Run();
