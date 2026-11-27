using System.Reflection;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Contracts;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>
/// OpenAPI 3.1 document for the REST API, built from the same contract records as the MCP tool schemas: each route's
/// [RouteDoc] names its query/body/response record, and the Functions [HttpTrigger] gives its method and path.
/// The MCP tools are listed under x-mcp-tools with their inputSchema, so one document shows both surfaces.
/// </summary>
public static partial class OpenApi
{
    [GeneratedRegex(@"\{(\w+)(?::[^}]+)?\}")] private static partial Regex PathParam();

    private static JsonObject? _cached;

    public static JsonObject Document() => (JsonObject)(_cached ??= Build()).DeepClone();

    private static JsonObject Build()
    {
        var schemas = new JsonObject();
        string Ref(Type t)
        {
            var name = t.Name;
            if (!schemas.ContainsKey(name)) schemas[name] = Contract.SchemaFor(t);
            return $"#/components/schemas/{name}";
        }
        JsonObject SchemaRef(Type t) => t.IsArray
            ? new JsonObject { ["type"] = "array", ["items"] = new JsonObject { ["$ref"] = Ref(t.GetElementType()!) } }
            : new JsonObject { ["$ref"] = Ref(t) };

        var paths = new JsonObject();
        foreach (var (method, doc) in RouteInfo.All(typeof(BoardApi)).Concat(RouteInfo.All(typeof(OpsApi))).Concat(RouteInfo.All(typeof(PolicyApi))).Concat(RouteInfo.All(typeof(AgentsApi))).OrderBy(x => Trigger(x.Method).Route, StringComparer.Ordinal))
        {
            var trigger = Trigger(method);
            // OpenAPI paths have no route constraints: actions/{id:guid} → actions/{id}.
            var path = "/api/" + System.Text.RegularExpressions.Regex.Replace(trigger.Route!, @"\{(\w+):[^}]+\}", "{$1}");
            if (paths[path] is not JsonObject item) paths[path] = item = new JsonObject();
            var op = new JsonObject
            {
                ["operationId"] = method.GetCustomAttribute<FunctionAttribute>()!.Name,
                ["summary"] = doc.Summary,
            };
            var parameters = new JsonArray();
            foreach (Match m in PathParam().Matches(trigger.Route!))
                parameters.Add(new JsonObject { ["name"] = m.Groups[1].Value, ["in"] = "path", ["required"] = true, ["schema"] = new JsonObject { ["type"] = "string" } });
            if (doc.Query is { } q)
            {
                var qs = Contract.SchemaFor(q);
                var required = (qs["required"] as JsonArray)?.Select(x => x!.GetValue<string>()).ToHashSet() ?? [];
                foreach (var (name, schema) in (JsonObject)qs["properties"]!)
                {
                    var s = schema!.DeepClone().AsObject();
                    var description = s["description"]?.GetValue<string>();
                    s.Remove("description");
                    var param = new JsonObject { ["name"] = name, ["in"] = "query", ["required"] = required.Contains(name), ["schema"] = s };
                    if (description is not null) param["description"] = description;
                    parameters.Add(param);
                }
            }
            if (parameters.Count > 0) op["parameters"] = parameters;
            if (doc.Body is { } b)
                op["requestBody"] = new JsonObject { ["required"] = true, ["content"] = new JsonObject { ["application/json"] = new JsonObject { ["schema"] = SchemaRef(b) } } };
            var ok = new JsonObject { ["description"] = "OK" };
            if (doc.Response is { } r) ok["content"] = new JsonObject { ["application/json"] = new JsonObject { ["schema"] = SchemaRef(r) } };
            op["responses"] = new JsonObject
            {
                ["200"] = ok,
                ["400"] = new JsonObject { ["$ref"] = "#/components/responses/Error" },
                ["401"] = new JsonObject { ["$ref"] = "#/components/responses/Error" },
                ["403"] = new JsonObject { ["$ref"] = "#/components/responses/Error" },
            };
            if (doc.Role == "public") op["security"] = new JsonArray();
            else if (doc.Role is { } role) op["x-board-role"] = role;
            foreach (var verb in trigger.Methods ?? ["get"]) item[verb.ToLowerInvariant()] = op.DeepClone();
        }

        var tools = new JsonObject();
        foreach (var t in Tools.All)
            tools[t.Name] = new JsonObject
            {
                ["description"] = t.Description,
                ["x-board-role"] = t.Role,
                ["inputSchema"] = new JsonObject { ["$ref"] = Ref(t.Input) },
            };

        return new JsonObject
        {
            ["openapi"] = "3.1.0",
            ["info"] = new JsonObject
            {
                ["title"] = "blueboard API",
                ["version"] = typeof(OpenApi).Assembly.GetName().Version?.ToString(3) ?? "1.0.0",
                ["description"] = "REST API for the blueboard web app. Agents use the MCP endpoint (/runtime/webhooks/mcp); its tools and input schemas are under x-mcp-tools. Every call needs an Entra bearer token for the board API.",
            },
            ["jsonSchemaDialect"] = "https://spec.openapis.org/oas/3.1/dialect/base",
            ["servers"] = new JsonArray(new JsonObject { ["url"] = "/" }),
            ["security"] = new JsonArray(new JsonObject { ["entra"] = new JsonArray() }),
            ["paths"] = paths,
            ["components"] = new JsonObject
            {
                ["schemas"] = schemas,
                ["responses"] = new JsonObject
                {
                    ["Error"] = new JsonObject
                    {
                        ["description"] = "Error",
                        ["content"] = new JsonObject
                        {
                            ["application/json"] = new JsonObject
                            {
                                ["schema"] = new JsonObject { ["type"] = "object", ["properties"] = new JsonObject { ["error"] = new JsonObject { ["type"] = "string" } }, ["required"] = new JsonArray("error") },
                            },
                        },
                    },
                },
                ["securitySchemes"] = new JsonObject
                {
                    ["entra"] = new JsonObject { ["type"] = "http", ["scheme"] = "bearer", ["bearerFormat"] = "JWT", ["description"] = "Microsoft Entra access token for the board API (delegated Board.Access for people, app-only for agents)" },
                },
            },
            ["x-mcp-tools"] = tools,
        };
    }

    private static HttpTriggerAttribute Trigger(MethodInfo m) =>
        m.GetParameters().Select(p => p.GetCustomAttribute<HttpTriggerAttribute>()).OfType<HttpTriggerAttribute>().First();

    /// <summary>For tests: the MCP inputSchema the document records for a tool, resolved.</summary>
    public static JsonObject ToolSchema(JsonObject doc, string tool)
    {
        var r = doc["x-mcp-tools"]![tool]!["inputSchema"]!["$ref"]!.GetValue<string>();
        return doc["components"]!["schemas"]![r.Split('/')[^1]]!.AsObject();
    }

    /// <summary>For tests: schema of a route's JSON body, resolved.</summary>
    public static JsonObject BodySchema(JsonObject doc, string path, string verb)
    {
        var r = doc["paths"]![path]![verb]!["requestBody"]!["content"]!["application/json"]!["schema"]!["$ref"]!.GetValue<string>();
        return doc["components"]!["schemas"]![r.Split('/')[^1]]!.AsObject();
    }
}
