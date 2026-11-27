using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Connectors;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Mcp;
using Blueboard.Api.Webhooks;
using Blueboard.Api.Ops;
using Blueboard.Api.Intel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api;

/// <summary>
/// Every service the Functions host registers, in one place so tests can build the real container (Program.cs calls
/// this; ServiceRegistrationTests resolves every function class from it).
/// </summary>
public static class ServiceRegistration
{
    public static IServiceCollection AddBlueboard(this IServiceCollection services, Settings settings)
    {
        var origins = MsOrigins.For(settings);
        services.AddSingleton(settings);
        services.AddSingleton(origins);
        services.AddSingleton<Db>();
        services.AddSingleton<Audit>();
        services.AddSingleton<TokenValidator>();
        services.AddSingleton<Authenticator>();
        // Strict: an unknown key or kind in policy.json stops the worker here with the reason, rather than running on defaults.
        services.AddSingleton(Policy.Load(settings));
        services.AddSingleton<RateLimiter>();
        services.AddHttpClient<MsClient>();
        services.AddSingleton<PurviewContentGuard>();
        services.AddSingleton<BoardService>();
        services.AddSingleton<MemoryService>();
        services.AddSingleton<SystemPrincipal>();
        // Admin overrides within policy.json (db/migrations/015): the effective policy is read from PostgreSQL with a short cache.
        services.AddSingleton<PolicyStore>();
        // Built explicitly so every optional collaborator is required in production: the policy override store, agent
        // feedback for overturn tracking, the third-party connectors and the agent risk source (max_requester_risk).
        services.AddSingleton<Broker>(sp => new Broker(sp.GetRequiredService<Db>(), sp.GetRequiredService<Audit>(), sp.GetRequiredService<BoardService>(),
            sp.GetRequiredService<MsClient>(), settings, sp.GetRequiredService<Policy>(), sp.GetRequiredService<SystemPrincipal>(), sp.GetRequiredService<RateLimiter>(),
            sp.GetRequiredService<PolicyStore>(), sp.GetRequiredService<Blueboard.Api.Agents.AgentFeedback>(), sp.GetRequiredService<ConnectorHub>(),
            sp.GetRequiredService<Blueboard.Api.Agents.IAgentRiskSource>()));
        // Okta, ServiceNow and Jira (all off unless configured). Each client calls only its configured origin through OutboundGuard.
        services.AddSingleton(sp => ConnectorHub.Create(sp.GetRequiredService<Db>(), sp.GetRequiredService<Audit>(), sp.GetRequiredService<BoardService>(),
            sp.GetRequiredService<SystemPrincipal>(), settings, sp.GetRequiredService<Policy>(), sp.GetRequiredService<PlaybookRunner>(),
            sp.GetRequiredService<RateLimiter>(), sp.GetRequiredService<ILoggerFactory>().CreateLogger("Blueboard.Connectors")));
        services.AddSingleton<Search>();
        services.AddSingleton<Reporting>();
        services.AddSingleton<Enrichment>();
        services.AddSingleton(Playbooks.Current = Playbooks.Load(settings.PlaybooksDir));
        services.AddHostedService<PlaybooksOnStart>();
        services.AddSingleton<PlaybookRunner>();
        services.AddSingleton<IncidentQueries>();
        services.AddSingleton<AttackViews>();
        services.AddSingleton<Ingest>();
        services.AddSingleton<WebhookService>(sp => new WebhookService(
            sp.GetRequiredService<Db>(), sp.GetRequiredService<Audit>(), sp.GetRequiredService<BoardService>(),
            sp.GetRequiredService<SystemPrincipal>(), settings, sp.GetRequiredService<ILogger<WebhookService>>(),
            sp.GetRequiredService<RateLimiter>()));
        services.AddSingleton(sp => new Migrator(sp.GetRequiredService<Db>(), settings));
        // Outbound notifications and audit export: no redirects, short timeouts, no HttpClient request logging, and live
        // notification destinations are pinned through OutboundGuard's anti-DNS-rebinding handler. Only the ntfy URL's
        // single-label host (a Docker service name in NOTIFY_ALLOWED_HOSTS) may resolve to a private network address.
        static HttpMessageHandler NoRedirects() => new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) };
        services.AddHttpClient<Notifier>()
            .ConfigurePrimaryHttpMessageHandler(() => origins.Mocked ? NoRedirects() : OutboundGuard.Handler(host => Notifier.MayBePrivate(settings, host)))
            .RemoveAllLoggers();
        services.AddHttpClient<AuditExporter>().ConfigurePrimaryHttpMessageHandler(NoRedirects).RemoveAllLoggers();
        services.AddHttpClient<GifService>().ConfigurePrimaryHttpMessageHandler(NoRedirects).RemoveAllLoggers();
        services.AddSingleton<Retention>();
        services.AddSingleton<AuditLog>();
        services.AddSingleton<Posture>();
        services.AddSingleton<Setup>();
        services.AddSingleton<Participants>();
        services.AddSingleton(settings.Ti);
        services.AddSingleton<IntelStore>();
        services.AddSingleton<IFetchCache, PgFetchCache>();
        services.AddSingleton(sp => new TiFetcher(sp.GetRequiredService<IFetchCache>(), settings.Ti));
        services.AddSingleton<MicrosoftIntel>();
        services.AddSingleton<IntelService>();
        services.AddSingleton<DetectionService>();
        services.AddSingleton<ExposureService>();
        services.AddHostedService<MigrateOnStart>();
        services.AddSingleton<Blueboard.Api.Http.Endpoint>();
        // Agent observability (WS3): usage and budgets, tool-call traces, feedback and overturns, risk. McpObserver is the one
        // hook around every MCP tool call (BoardTools.Call); IAgentRiskSource is the read-only risk API for other services.
        services.AddSingleton(new Blueboard.Api.Agents.PriceTable(settings));
        services.AddSingleton<Blueboard.Api.Agents.ObservabilitySettingsStore>();
        services.AddSingleton<Blueboard.Api.Agents.AgentBudgets>();
        services.AddSingleton<Blueboard.Api.Agents.AgentTrace>();
        services.AddSingleton<Blueboard.Api.Agents.AgentFeedback>();
        services.AddSingleton<Blueboard.Api.Agents.AgentRisk>();
        services.AddSingleton<Blueboard.Api.Agents.IAgentRiskSource>(sp => sp.GetRequiredService<Blueboard.Api.Agents.AgentRisk>());
        services.AddSingleton<Blueboard.Api.Agents.AgentReports>();
        services.AddSingleton<McpObserver>();
        return services;
    }
}
