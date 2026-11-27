using System.Reflection;
using System.Text.RegularExpressions;
using Blueboard.Api.Http;
using Blueboard.Api.Mcp;
using Blueboard.Contracts;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Extensions.Mcp;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>
/// The whole public surface stays consistent as features are added: tool names are unique, every MCP tool goes
/// through BoardTools.Call (so the McpObserver hook meters, budgets and traces it), and every HTTP route is in the
/// OpenAPI document.
/// </summary>
public class ApiSurfaceTests
{
    [Fact]
    public void Tool_names_and_functions_are_unique()
    {
        Assert.Equal(Tools.All.Count, Tools.All.Select(t => t.Name).Distinct().Count());
        var functions = typeof(BoardTools).GetMethods().Select(m => m.GetCustomAttribute<FunctionAttribute>()?.Name).OfType<string>().ToList();
        Assert.Equal(functions.Count, functions.Distinct().Count());
    }

    [Fact]
    public void Every_mcp_tool_is_dispatched_through_call()
    {
        // The observer hook lives in Call<TIn>; a tool body that skips it would be unmetered, unbudgeted and untraced.
        var src = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "../../../../Blueboard.Api/Mcp/BoardTools.cs"));
        var bodies = Regex.Matches(src, @"\[McpToolTrigger\((?<tool>[^,]+),[^\]]*\]\s*ToolInvocationContext ctx\)\s*=>\s*(?<body>\S+)");
        Assert.Equal(Tools.All.Count, bodies.Count);
        foreach (Match m in bodies)
            Assert.True(m.Groups["body"].Value.StartsWith("Call<", StringComparison.Ordinal) || m.Groups["body"].Value.StartsWith("Call(", StringComparison.Ordinal),
                $"{m.Groups["tool"].Value} does not dispatch through Call");
    }

    [Fact]
    public void Every_http_route_is_documented_in_openapi()
    {
        var paths = OpenApi.Document()["paths"]!.AsObject();
        var routes = typeof(BoardApi).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Select(m => (Method: m, Trigger: m.GetParameters().Select(p => p.GetCustomAttribute<HttpTriggerAttribute>()).OfType<HttpTriggerAttribute>().FirstOrDefault()))
            .Where(x => x.Trigger?.Route is not null)
            .ToList();
        Assert.NotEmpty(routes);
        foreach (var (method, trigger) in routes)
        {
            var path = "/api/" + Regex.Replace(trigger!.Route!, @"\{(\w+):[^}]+\}", "{$1}");
            Assert.True(paths.ContainsKey(path), $"{method.DeclaringType!.Name}.{method.Name} ({path}) is missing from OpenAPI");
        }
        // One route from each feature area.
        foreach (var p in new[] { "/api/policy/automation", "/api/manage/agents/report", "/api/incidents/{id}/timeline", "/api/manage/connectors", "/api/detections/backtests" })
            Assert.True(paths.ContainsKey(p), p);
    }

    [Fact]
    public void Mcp_trigger_tool_names_match_the_contract()
    {
        var triggers = typeof(BoardTools).GetMethods()
            .SelectMany(m => m.GetParameters())
            .Select(p => p.GetCustomAttribute<McpToolTriggerAttribute>()?.ToolName).OfType<string>().ToList();
        Assert.Equal(triggers.Count, triggers.Distinct().Count());
        Assert.Equal(Tools.All.Select(t => t.Name).Order(), triggers.Order());
    }
}
