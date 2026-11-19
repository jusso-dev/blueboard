using System.Text.Json;

namespace Blueboard.Api.Core;

public static class Roles
{
    public const string Poster = "poster";
    public const string Hunter = "hunter";
    public const string Requester = "requester";
    public const string Approver = "approver";
    public const string Admin = "admin";

    /// <summary>Entra app role value → board role.</summary>
    public static readonly IReadOnlyDictionary<string, string> FromAppRole = new Dictionary<string, string>
    {
        ["Board.Post"] = Poster,
        ["Board.Hunt"] = Hunter,
        ["Board.RequestActions"] = Requester,
        ["Board.Approve"] = Approver,
        ["Board.Admin"] = Admin,
    };
}

public static class MessageTypes
{
    public static readonly string[] All = ["chat", "finding", "question", "ioc", "action_request", "action_result", "verdict", "status", "incident"];
    /// <summary>Types an outside principal may post. The others are board-generated.</summary>
    public static readonly string[] Postable = ["chat", "finding", "question", "ioc", "verdict", "status"];
    public static readonly string[] Claimable = ["question", "finding", "ioc"];
}

public sealed record Principal(Guid Id, string Handle, string DisplayName, string Kind, string[] Roles)
{
    public bool Has(string role) => Roles.Contains(role);
    public bool IsHuman => Kind == "human";
    public void Require(string role)
    {
        if (!Has(role)) throw BoardException.Forbidden($"missing role {role}");
    }
}
