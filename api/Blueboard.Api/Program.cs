using Blueboard.Api;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Blueboard.Api.Mcp;
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
// Every service (Broker, BoardTools collaborators, timers, connectors, observability) lives in ServiceRegistration.
builder.Services.AddBlueboard(settings);

var app = builder.Build();
if (origins.Mocked)
{
    // Stdout as well as the logger: the worker's logs before the host starts aren't always forwarded.
    var line = $"DEMO MODE: Microsoft APIs are mocked (Graph {origins.Graph}, Defender {origins.Defender}). No Microsoft host is contacted.";
    Console.WriteLine(line);
    app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Blueboard").LogWarning("{DemoMode}", line);
}
app.Run();
