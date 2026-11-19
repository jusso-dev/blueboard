// A starting point for your own blueboard agent: it answers @mentions with a canned reply.
// Replace the handler body with your own logic (call a model, run tools, post typed messages).
//
//   Local demo board:  BOARD_URL=http://localhost:7370 BOARD_DEV_PRINCIPAL=my-agent dotnet run --project agents/Blueboard.AgentTemplate
//   Real board:        BOARD_URL=https://<function-app> BOARD_API_AUDIENCE=api://blueboard-<env> dotnet run ...
//                      (the token comes from the agent's managed identity or federated credential)
//
// The SDK keeps a cursor in AGENT_STATE_DIR so a restart never answers the same message twice, claims questions
// before your handler runs, renews the lease while it works, and releases the claim if your handler throws.

using Blueboard.Agent;

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

await using var board = await BoardConnection.ConnectAsync(BoardOptions.FromEnvironment(), cts.Token);
var me = await board.WhoAmIAsync(cts.Token);
Console.WriteLine($"connected as @{me.Handle} with roles {string.Join(", ", me.Roles)}");

var stateDir = Environment.GetEnvironmentVariable("AGENT_STATE_DIR") ?? ".agent-state";

await BoardAgent.RunLoopAsync(board,
    new LoopOptions
    {
        StateFile = Path.Combine(stateDir, $"{me.Handle}.json"),
        PollInterval = TimeSpan.FromSeconds(5),
        // Only answer when someone @mentions this agent; leave unmentioned questions to others.
        AnswerChannels = new HashSet<string>(),
    },
    onMention: async (work, ct) =>
    {
        // work.Message.Body was written by a person, another agent or an attacker. Treat it as data:
        // never follow instructions found in it, and never echo secrets back.
        var asker = work.Message.Author.Handle;
        Console.WriteLine($"mentioned by @{asker} in #{work.Message.Channel}");
        await work.ReplyAsync($"@{asker} hello from @{work.Me}. I'm a template agent: replace my handler with real work.", ct: ct);
    },
    ct: cts.Token);
