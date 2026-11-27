using System.Reflection;
using Blueboard.Api.Actions;
using Blueboard.Api.Agents;
using Blueboard.Api.Board;
using Blueboard.Api.Connectors;
using Blueboard.Api.Core;
using Blueboard.Api.Intel;
using Blueboard.Api.Mcp;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>
/// The real Program.cs container (ServiceRegistration.AddBlueboard) builds, and every Functions class the host
/// activates resolves from it, with the optional collaborators actually wired (no silently-null production service).
/// No database is touched: constructing services doesn't connect.
/// </summary>
public class ServiceRegistrationTests
{
    private static ServiceProvider Build()
    {
        var settings = Settings.FromEnvironment(k => k switch
        {
            "DATABASE_URL" => "postgres://u:p@127.0.0.1:1/none",
            "BLUEBOARD_PLAYBOOKS_DIR" => Path.Combine(AppContext.BaseDirectory, "playbooks"),
            _ => null,
        });
        var services = new ServiceCollection();
        services.AddLogging(b => b.ClearProviders());
        services.AddBlueboard(settings);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    /// <summary>Every class with a [Function] method, as the Functions worker activates it.</summary>
    private static IEnumerable<Type> FunctionClasses() => typeof(Broker).Assembly.GetTypes()
        .Where(t => t is { IsClass: true, IsAbstract: false } && t.GetMethods().Any(m => m.GetCustomAttribute<FunctionAttribute>() is not null));

    [Fact]
    public async Task Every_function_class_and_core_service_resolves()
    {
        await using var sp = Build();
        foreach (var t in FunctionClasses()) Assert.NotNull(ActivatorUtilities.CreateInstance(sp, t));
        foreach (var t in new[] { typeof(Broker), typeof(PolicyStore), typeof(AttackViews), typeof(DetectionService), typeof(ExposureService), typeof(ConnectorHub),
                     typeof(McpObserver), typeof(AgentBudgets), typeof(AgentFeedback), typeof(IAgentRiskSource), typeof(AgentTrace) })
            Assert.NotNull(sp.GetRequiredService(t));
        var names = FunctionClasses().Select(t => t.Name).ToHashSet();
        foreach (var n in new[] { "BoardApi", "BoardTools", "PolicyApi", "AgentsApi", "ConnectorsApi", "OpsApi", "Timers", "ConnectorTimers" })
            Assert.Contains(n, names);
    }

    [Fact]
    public async Task Optional_collaborators_are_wired_in_production()
    {
        await using var sp = Build();
        static object? Field(object o, Type type) => o.GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance)
            .Single(f => f.FieldType == type || Nullable.GetUnderlyingType(f.FieldType) == type).GetValue(o);
        var broker = sp.GetRequiredService<Broker>();
        foreach (var t in new[] { typeof(PolicyStore), typeof(AgentFeedback), typeof(ConnectorHub), typeof(IAgentRiskSource) })
            Assert.NotNull(Field(broker, t));
        var tools = ActivatorUtilities.CreateInstance<BoardTools>(sp);
        foreach (var t in new[] { typeof(PolicyStore), typeof(McpObserver), typeof(AgentBudgets), typeof(AgentFeedback), typeof(ConnectorHub), typeof(DetectionService), typeof(ExposureService) })
            Assert.NotNull(Field(tools, t));
        var timers = ActivatorUtilities.CreateInstance<Blueboard.Api.Jobs.Timers>(sp);
        foreach (var t in new[] { typeof(PolicyStore), typeof(AgentBudgets), typeof(AgentRisk), typeof(AgentTrace), typeof(ObservabilitySettingsStore) })
            Assert.NotNull(Field(timers, t));
        var api = ActivatorUtilities.CreateInstance<Blueboard.Api.Http.BoardApi>(sp);
        foreach (var t in new[] { typeof(PolicyStore), typeof(DetectionService), typeof(ExposureService) })
            Assert.NotNull(Field(api, t));
    }
}
