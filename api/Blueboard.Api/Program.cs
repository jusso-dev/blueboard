using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
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
// Strict: an unknown key or kind in policy.json stops the worker here with the reason, rather than running on defaults.
builder.Services.AddSingleton(Policy.Load(settings));
builder.Services.AddSingleton<RateLimiter>();
builder.Services.AddSingleton<BoardService>();
builder.Services.AddSingleton<SystemPrincipal>();
builder.Services.AddHttpClient<MsClient>();
builder.Services.AddSingleton<Broker>();
builder.Services.AddSingleton<Search>();
builder.Services.AddSingleton<Reporting>();
builder.Services.AddSingleton<Enrichment>();
builder.Services.AddSingleton<Ingest>();
builder.Services.AddSingleton<Migrator>();
builder.Services.AddHostedService<MigrateOnStart>();
builder.Services.AddSingleton<Blueboard.Api.Http.Endpoint>();

builder.Build().Run();
