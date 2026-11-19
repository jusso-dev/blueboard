using System.Reflection;
using Blueboard.Api.Http;
using Microsoft.Azure.Functions.Worker;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>
/// Routes with a literal segment (actions/preview) must not be swallowed by a parameter route on the same path
/// (actions/{id}). Found in a live run: POST /api/actions/preview reached the decide handler and failed "invalid id".
/// </summary>
public class RouteTests
{
    private static IEnumerable<(string Method, string Route)> Routes() =>
        typeof(BoardApi).GetMethods()
            .SelectMany(m => m.GetParameters())
            .Select(p => p.GetCustomAttribute<HttpTriggerAttribute>())
            .OfType<HttpTriggerAttribute>()
            .SelectMany(a => (a.Methods ?? []).Select(m => (m, a.Route ?? "")));

    [Fact]
    public void Action_id_routes_only_match_guids()
    {
        var routes = Routes().ToList();
        Assert.Contains(("post", "actions/preview"), routes);
        Assert.Contains(("post", "actions/{id:guid}"), routes);
        Assert.Contains(("get", "actions/{id:guid}"), routes);
        Assert.DoesNotContain(routes, r => r.Route == "actions/{id}");
    }
}
