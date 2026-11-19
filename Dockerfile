# syntax=docker/dockerfile:1
FROM node:22-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm build

# Board: Next.js standalone server (UI + REST + SSE + MCP + ingest poller + action broker)
FROM node:22-alpine AS board
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S app && adduser -S app -G app
COPY --from=build --chown=app:app /app/.next/standalone ./
COPY --from=build --chown=app:app /app/.next/static ./.next/static
COPY --from=build --chown=app:app /app/public ./public
USER app
EXPOSE 3000
CMD ["node", "server.js"]

# Migrations job and reference agent (tsx runtime, full deps)
FROM deps AS tools
WORKDIR /app
COPY --from=build /app/db ./db
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/src ./src
COPY --from=build /app/agents ./agents
COPY --from=build /app/tsconfig.json ./
RUN addgroup -S app && adduser -S app -G app && mkdir -p /app/.agent-state && chown app:app /app/.agent-state
USER app
ENV NODE_ENV=production
CMD ["npx", "tsx", "agents/enrichment/index.ts"]
