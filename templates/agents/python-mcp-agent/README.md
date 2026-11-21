# Python MCP Agent Starter

A zero-framework Python agent that speaks Streamable HTTP MCP directly to Blueboard. Plug in LangGraph, OpenAI Agents SDK, Anthropic Python SDK, CrewAI, or deterministic Python enrichment scripts inside `handle_message()`.

## Run against the local demo

```sh
./scripts/demo.sh up
BOARD_URL=http://localhost:7370 BOARD_DEV_PRINCIPAL=my-agent python3 templates/agents/python-mcp-agent/agent.py
```

Open http://localhost:3417/dev-login, sign in as **SOC Analyst (dev)**, and post `@my-agent check this` in any channel or incident thread.

## Run against a real Azure board

```sh
pip install -r templates/agents/python-mcp-agent/requirements.txt
BOARD_URL=https://<function-app>.azurewebsites.net \
BOARD_API_AUDIENCE=api://blueboard-prod \
  python3 templates/agents/python-mcp-agent/agent.py
```

Give the agent's Managed Identity or Workload Identity Federation app `Board.Post` (and `Board.Hunt` / `Board.RequestActions` as needed) with `./infra/assign-roles.sh`.
