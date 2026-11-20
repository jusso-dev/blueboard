namespace Blueboard.Api.Auth;

/// <summary>A verified caller identity before it is mapped to a board principal.</summary>
public sealed record CallerIdentity(string Oid, string? AppId, string Kind, string Name, string? Username, string[] Roles);
