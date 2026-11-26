using Blueboard.Api.Core;

namespace Blueboard.Api.Actions;

/// <summary>
/// The board message an agent cites as a person's instruction (request_action on_behalf_of), as the database sees it
/// at request time. Age is measured by the database clock.
/// </summary>
public sealed record Instruction(
    Guid MessageId, Guid AuthorId, string AuthorHandle, string AuthorKind, bool AuthorEnabled, string[] AuthorRoles,
    Guid? IncidentId, TimeSpan Age, bool MentionsRequester, bool RequesterInThread, bool AlreadyUsed);

/// <summary>
/// When a person's chat message may count as their approval (policy act_on_instruction). Every rule must hold; the
/// first that fails is the 400 the requester sees. An agent can never approve its own request this way: the message
/// must be a person's, that person an enabled approver who isn't the requester, on the same incident, recent, and
/// addressed to the requester (an @mention, or a thread the requester is in).
/// </summary>
public static class InstructionRules
{
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(60);
    private const string Refile = "file it without on_behalf_of and it waits in Approvals";

    /// <summary>Policy rules that don't depend on the message: checked before it is read.</summary>
    public static string? CheckPolicy(string kind, Policy policy, bool paused, int approvalsRequired)
    {
        if (!policy.ActOnInstruction.Contains(kind))
            return $"on_behalf_of refused: policy act_on_instruction does not list {kind}, so this kind needs a person to approve it on the board ({Refile})";
        if (policy.ConfirmsTarget(kind))
            return $"on_behalf_of refused: {kind} is in confirm_target, so this kind needs a person to approve it on the board ({Refile})";
        if (approvalsRequired > 1 || policy.RequireTwoApprovers.Contains(kind))
            return $"on_behalf_of refused: {kind} needs two approvers, so this kind needs people to approve it on the board ({Refile})";
        if (paused)
            return $"on_behalf_of refused: the broker is paused, so an instruction can't approve actions until an admin resumes it ({Refile})";
        return null;
    }

    /// <summary>Rules about the cited message. Null when it counts as the approval.</summary>
    public static string? CheckMessage(Instruction? m, Guid messageId, Principal requester, Guid? actionIncidentId)
    {
        if (m is null) return $"on_behalf_of refused: message {messageId} not found";
        if (m.AuthorKind != "human")
            return $"on_behalf_of refused: message {messageId} was written by @{m.AuthorHandle}, who is not a person; only a human approver's instruction counts";
        if (!m.AuthorEnabled) return $"on_behalf_of refused: @{m.AuthorHandle} is disabled on the board";
        if (!m.AuthorRoles.Contains(Roles.Approver))
            return $"on_behalf_of refused: @{m.AuthorHandle} is not an approver (Board.Approve), so their message can't approve an action";
        if (m.AuthorId == requester.Id) return "on_behalf_of refused: you can't act on your own message; another approver has to approve it";
        if (actionIncidentId is null) return "on_behalf_of refused: the action must be linked to the incident the instruction is on";
        if (m.IncidentId != actionIncidentId)
            return $"on_behalf_of refused: message {messageId} is not on the same incident as this action";
        if (m.Age > MaxAge)
            return $"on_behalf_of refused: message {messageId} is more than {MaxAge.TotalMinutes:0} minutes old; ask @{m.AuthorHandle} to confirm again";
        if (!m.MentionsRequester && !m.RequesterInThread)
            return $"on_behalf_of refused: message {messageId} neither @mentions @{requester.Handle} nor is in a thread @{requester.Handle} posted in";
        if (m.AlreadyUsed) return $"on_behalf_of refused: message {messageId} was already used for a request of this kind";
        return null;
    }
}
