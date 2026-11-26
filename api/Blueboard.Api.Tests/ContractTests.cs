using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Http;
using Blueboard.Api.Mcp;
using Blueboard.Contracts;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>TD-01: one schema source. The MCP inputSchema, the OpenAPI schema and validation all come from the request record.</summary>
public class ContractTests
{
    [Fact]
    public void Every_tool_has_a_schema_and_a_function()
    {
        var schemas = McpSchemas.All();
        var functions = typeof(BoardTools).GetMethods()
            .SelectMany(m => m.GetParameters())
            .Select(p => p.GetCustomAttributes(typeof(Microsoft.Azure.Functions.Worker.Extensions.Mcp.McpToolTriggerAttribute), false).FirstOrDefault())
            .OfType<Microsoft.Azure.Functions.Worker.Extensions.Mcp.McpToolTriggerAttribute>()
            .Select(a => a.ToolName).Order().ToArray();
        Assert.Equal(Tools.All.Select(t => t.Name).Order().ToArray(), functions);
        Assert.Equal(functions, schemas.Keys.Order().ToArray());
        Assert.Contains("renew_claim", functions);
        Assert.Contains("set_profile", functions);
    }

    [Fact]
    public void Mcp_and_openapi_share_the_post_message_schema()
    {
        var doc = OpenApi.Document();
        var mcp = McpSchemas.All()["post_message"];
        Assert.True(JsonNode.DeepEquals(mcp, OpenApi.ToolSchema(doc, "post_message")));
        Assert.True(JsonNode.DeepEquals(mcp, OpenApi.BodySchema(doc, "/api/messages", "post")));
        Assert.Equal(["channel", "body"], mcp["required"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Equal(1, mcp["properties"]!["body"]!["minLength"]!.GetValue<int>());
    }

    // A copy of PostInput with one field removed and one changed: the generated schema follows with no other edit.
    private sealed record PostInputWithoutIncident(
        [Description("Channel name, e.g. incidents, triage, intel")]
        [System.ComponentModel.DataAnnotations.StringLength(41, MinimumLength = 1)] string Channel,
        [Description("Markdown")][System.ComponentModel.DataAnnotations.StringLength(500, MinimumLength = 1)] string Body,
        string? Type = null,
        JsonElement? Payload = null,
        Guid? ParentId = null);

    [Fact]
    public void Changing_a_record_changes_the_schema_with_no_other_edit()
    {
        var full = Contract.SchemaFor<PostInput>();
        var changed = Contract.SchemaFor<PostInputWithoutIncident>();
        Assert.NotNull(full["properties"]!["incident"]);
        Assert.Null(changed["properties"]!["incident"]);
        Assert.Equal(500, changed["properties"]!["body"]!["maxLength"]!.GetValue<int>());
        // The record also drives validation: an over-long body is refused by the same constraint.
        var ex = Assert.Throws<ContractException>(() => Contract.Read<PostInputWithoutIncident>(
            JsonSerializer.SerializeToElement(new { channel = "general", body = new string('x', 501) })));
        Assert.Contains("body", ex.Message);
    }

    [Fact]
    public void Feed_query_reads_mcp_and_rest_shapes_the_same_way()
    {
        var fromMcp = Contract.Read<FeedQuery>(McpSchemas.Arguments(new Dictionary<string, object>
        {
            ["after_seq"] = "12", ["types"] = new List<object> { "question", "incident" }, ["limit"] = 5,
        }));
        var fromRest = Contract.Read<FeedQuery>(Endpoint.QueryJson<FeedQuery>(new Dictionary<string, string[]>
        {
            ["after_seq"] = ["12"], ["type"] = ["question", "incident"], ["limit"] = ["5"],
        }, new Dictionary<string, string> { ["type"] = "types" }));
        Assert.Equal(12, fromMcp.AfterSeq);
        Assert.Equal(fromMcp.AfterSeq, fromRest.AfterSeq);
        Assert.Equal(fromMcp.Types, fromRest.Types);
        Assert.Equal(5, fromRest.Limit);
        // Older agents send types as one comma-separated string.
        Assert.Equal(["a", "b"], Contract.Read<FeedQuery>(JsonSerializer.SerializeToElement(new { types = "a, b" })).Types!);
    }

    [Theory]
    [InlineData("""{"body":"x"}""", "channel")]
    [InlineData("""{"channel":"general","body":"x","type":"action_result"}""", "type must be one of")]
    [InlineData("""{"channel":"general","body":""}""", "body")]
    public void Post_input_is_validated_by_its_record(string json, string message)
    {
        var ex = Assert.Throws<ContractException>(() => Contract.Read<PostInput>(JsonDocument.Parse(json).RootElement));
        Assert.Contains(message, ex.Message);
    }

    [Fact]
    public void Legacy_payload_json_string_still_works()
    {
        var p = Contract.Read<PostInput>(McpSchemas.Arguments(new Dictionary<string, object>
        {
            ["channel"] = "intel", ["body"] = "hi", ["type"] = "status", ["payload_json"] = """{"state":"ok"}""",
        }));
        Assert.Equal("ok", p.Payload!.Value.GetProperty("state").GetString());
        Assert.Throws<ContractException>(() => McpSchemas.Arguments(new Dictionary<string, object> { ["payload_json"] = "{not json" }));
    }

    [Fact]
    public void Openapi_document_is_3_1_and_lists_every_route_and_tool()
    {
        var doc = OpenApi.Document();
        Assert.Equal("3.1.0", doc["openapi"]!.GetValue<string>());
        var paths = doc["paths"]!.AsObject();
        foreach (var p in new[] { "/api/messages", "/api/threads/{id}", "/api/claims/{id}", "/api/actions/{id}", "/api/search", "/api/openapi.json", "/api/manage/participants/{handle}/profile" })
            Assert.True(paths.ContainsKey(p), p);
        Assert.Equal(Tools.All.Count, doc["x-mcp-tools"]!.AsObject().Count);
        // Every $ref resolves.
        var schemas = doc["components"]!["schemas"]!.AsObject();
        foreach (var r in Refs(doc)) Assert.True(r.StartsWith("#/components/responses/") || schemas.ContainsKey(r.Split('/')[^1]), r);
        // Query parameters for /api/messages come from FeedQuery.
        var names = paths["/api/messages"]!["get"]!["parameters"]!.AsArray().Select(x => x!["name"]!.GetValue<string>()).ToArray();
        Assert.Contains("after_seq", names);
        Assert.Contains("open_requests", names);
    }

    [Fact]
    public void Messages_carry_thread_activity_for_the_replies_row()
    {
        var message = OpenApi.Document()["components"]!["schemas"]!["Message"]!["properties"]!.AsObject();
        Assert.True(message.ContainsKey("last_reply_at"));
        var author = message["reply_authors"]!["items"]!["properties"]!.AsObject();
        Assert.Equal(["handle", "display_name", "kind"], author.Select(kv => kv.Key));
    }

    private static IEnumerable<string> Refs(JsonNode? n) => n switch
    {
        JsonObject o => o.SelectMany(kv => kv.Key == "$ref" ? [kv.Value!.GetValue<string>()] : Refs(kv.Value)),
        JsonArray a => a.SelectMany(Refs),
        _ => [],
    };
}
