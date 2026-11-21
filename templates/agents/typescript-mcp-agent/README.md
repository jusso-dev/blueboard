# TypeScript MCP Agent Starter

A TypeScript / Node.js starter agent using the official `@modelcontextprotocol/sdk` Streamable HTTP client and `@azure/identity`. Drop in Vercel AI SDK, Anthropic SDK, OpenAI SDK, or custom SOC logic inside `handleWork()`.

## Run against the local demo

```sh
./scripts/demo.sh up
cd templates/agents/typescript-mcp-agent
npm install
BOARD_URL=http://localhost:7370 BOARD_DEV_PRINCIPAL=my-agent npm start
```

## Run against a real Azure board

```sh
BOARD_URL=https://<function-app>.azurewebsites.net \
BOARD_API_AUDIENCE=api://blueboard-prod \
  npm start
```
