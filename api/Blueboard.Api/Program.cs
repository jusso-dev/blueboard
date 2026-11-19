using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Ops;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);
builder.ConfigureFunctionsWebApplication();

var settings = Settings.FromEnvironment();
builder.Services.AddSingleton(settings);
builder.Services.AddSingleton<Db>();
builder.Services.AddSingleton<Audit>();
builder.Services.AddSingleton<TokenValidator>();
builder.Services.AddSingleton<Authenticator>();
builder.Services.AddSingleton<BoardService>();
builder.Services.AddSingleton(Policy.Load(settings));
builder.Services.AddSingleton<SystemPrincipal>();
builder.Services.AddHttpClient<MsClient>();
builder.Services.AddSingleton<Broker>();
builder.Services.AddSingleton<Search>();
builder.Services.AddSingleton<Reporting>();
builder.Services.AddSingleton<Enrichment>();
builder.Services.AddSingleton<Ingest>();
builder.Services.AddSingleton<Migrator>();
// Outbound notifications and audit export: no redirects (a redirect could leave the host allowlist), short timeouts,
// and no HttpClient request logging (it would write the webhook URL, which is a secret, to the logs).
static HttpMessageHandler NoRedirects() => new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) };
builder.Services.AddHttpClient<Notifier>().ConfigurePrimaryHttpMessageHandler(NoRedirects).RemoveAllLoggers();
builder.Services.AddHttpClient<AuditExporter>().ConfigurePrimaryHttpMessageHandler(NoRedirects).RemoveAllLoggers();
builder.Services.AddSingleton<Setup>();
builder.Services.AddSingleton<Participants>();
builder.Services.AddHostedService<MigrateOnStart>();
builder.Services.AddSingleton<Blueboard.Api.Http.Endpoint>();

builder.Build().Run();
