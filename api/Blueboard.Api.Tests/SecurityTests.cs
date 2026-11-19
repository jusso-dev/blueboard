using System.Security.Claims;
using System.Text;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Xunit;

namespace Blueboard.Api.Tests;

public class SecurityTests
{
    [Fact]
    public void Token_guard_refuses_look_alike_origin() =>
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(MsApi.Graph, "https://graph.microsoft.com.evil.example/v1.0/me"));

    [Theory]
    [InlineData("/v1.0/security/incidents/../../me")]
    [InlineData("/v1.0/users/%2E%2E/x")]
    [InlineData("/v1.0/users/./x")]
    public void Token_guard_refuses_dot_segments(string path) =>
        Assert.Throws<InvalidOperationException>(() => MsClient.BuildUri(MsApi.Graph, path));

    [Fact]
    public void Token_guard_allows_graph_next_links() =>
        Assert.Equal("graph.microsoft.com", MsClient.BuildUri(MsApi.Graph, "https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=x").Host);

    [Fact]
    public void Agents_never_hold_approve_or_admin() =>
        Assert.Equal(["poster", "requester"], TokenValidator.MapRoles(["Board.Post", "Board.Approve", "Board.Admin", "Board.RequestActions"], "agent"));

    [Fact]
    public void Humans_keep_approve() =>
        Assert.Contains("approver", TokenValidator.MapRoles(["Board.Post", "Board.Approve"], "human"));

    [Fact]
    public void App_only_tokens_are_agents()
    {
        var id = TokenValidator.FromClaims(new ClaimsIdentity([new("oid", "o1"), new("idtyp", "app"), new("azp", "app-1"), new("roles", "Board.Approve"), new("roles", "Board.Post")]));
        Assert.Equal("agent", id.Kind);
        Assert.DoesNotContain("approver", id.Roles);
    }

    [Fact]
    public void Delegated_tokens_are_humans()
    {
        var id = TokenValidator.FromClaims(new ClaimsIdentity([new("oid", "o2"), new("scp", "user_impersonation"), new("preferred_username", "a@b.com"), new("roles", "Board.Approve")]));
        Assert.Equal("human", id.Kind);
        Assert.Contains("approver", id.Roles);
    }

    [Fact]
    public void Swa_principal_is_parsed_and_roles_mapped()
    {
        var json = """
            {"identityProvider":"aad","userId":"x","userDetails":"ana@contoso.com","userRoles":["anonymous","authenticated"],
             "claims":[{"typ":"http://schemas.microsoft.com/identity/claims/objectidentifier","val":"oid-9"},{"typ":"name","val":"Ana"},{"typ":"roles","val":"Board.Post"},{"typ":"roles","val":"Board.Approve"}]}
            """;
        var id = Authenticator.FromSwaPrincipal(Convert.ToBase64String(Encoding.UTF8.GetBytes(json)));
        Assert.Equal("oid-9", id.Oid);
        Assert.Equal("human", id.Kind);
        Assert.Equal(["approver", "poster"], id.Roles);
    }

    [Fact]
    public void Swa_principal_from_other_providers_is_refused()
    {
        var json = """{"identityProvider":"github","userId":"x","userDetails":"x","claims":[]}""";
        Assert.Throws<BoardException>(() => Authenticator.FromSwaPrincipal(Convert.ToBase64String(Encoding.UTF8.GetBytes(json))));
    }

    [Fact]
    public void App_service_principal_format_is_parsed()
    {
        var json = """
            {"auth_typ":"aad","name_typ":"name","role_typ":"roles",
             "claims":[{"typ":"http://schemas.microsoft.com/identity/claims/objectidentifier","val":"oid-7"},{"typ":"name","val":"Bo"},{"typ":"roles","val":"Board.Post"}]}
            """;
        var id = Authenticator.FromSwaPrincipal(Convert.ToBase64String(Encoding.UTF8.GetBytes(json)));
        Assert.Equal("oid-7", id.Oid);
        Assert.Equal(["poster"], id.Roles);
    }

    [Fact]
    public void Swa_user_roles_from_roles_source_are_honoured()
    {
        var json = """
            {"identityProvider":"aad","userDetails":"c@contoso.com","userRoles":["anonymous","authenticated","Board.Post","Board.Admin"],
             "claims":[{"typ":"http://schemas.microsoft.com/identity/claims/objectidentifier","val":"oid-8"}]}
            """;
        Assert.Equal(["admin", "poster"], Authenticator.FromSwaPrincipal(Convert.ToBase64String(Encoding.UTF8.GetBytes(json))).Roles);
    }

    [Fact]
    public void Principal_without_oid_is_refused() =>
        Assert.Throws<BoardException>(() => Authenticator.FromSwaPrincipal(Convert.ToBase64String(Encoding.UTF8.GetBytes("""{"identityProvider":"aad","claims":[]}"""))));

    [Fact]
    public void Mentions_ignore_email_addresses() =>
        Assert.Equal(["enrichment-agent", "analyst"], BoardService.ParseMentions("hey @enrichment-agent and @analyst, mail j.doe@contoso.com @analyst"));

    [Fact]
    public void Percentile_matches_postgres_percentile_cont()
    {
        Assert.Null(Reporting.Percentile([], 0.5));
        Assert.Equal(2.5, Reporting.Percentile([1, 2, 3, 4], 0.5));
        Assert.Equal(91, Reporting.Percentile([10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 0.9)!.Value, 6);
    }

    [Fact]
    public void Csv_neutralises_formula_injection()
    {
        var report = new Report(new { }, new Coverage(1, 1, 0, 0), new Stat(60, 60, 1), new Stat(null, null, 0), new Stat(null, null, 0), new Stat(null, null, 0), [],
            [new IncidentTiming(Guid.Empty, "42", "=HYPERLINK(\"http://evil\",\"x\")", "high", "active", DateTimeOffset.UnixEpoch, 61.4, null, null, 3, 0)]);
        var row = Reporting.Csv(report).Split('\n')[1];
        Assert.Contains("\"'=HYPERLINK(\"\"http://evil\"\",\"\"x\"\")\"", row);
        Assert.EndsWith(",61,,,3,0", row);
    }
}
