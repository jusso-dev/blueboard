# The board's Function App for the local demo, built from the repo.
# Built from the repo root: docker compose -f docker-compose.demo.yml build api
#
# Runtime: the Azure Functions .NET isolated (.NET 10) base image with Azure Functions Core Tools, which runs the
# published app with `func start`. Why Core Tools and not the image's own host: on the published host images we
# tested (4.1039 to 4.1055, 19-11-2026) the MCP extension's webhook either needs a host key (401) or fails during
# initialize with no error (500) when run outside App Service. Core Tools' host serves MCP correctly, matches
# local development (`func start`), and is what the demo needs; Azure runs the normal Flex Consumption host.
# The base image is linux/amd64 only (emulated on Apple silicon).
ARG FUNCTIONS_IMAGE=mcr.microsoft.com/azure-functions/dotnet-isolated:4-dotnet-isolated10.0
ARG CORE_TOOLS_VERSION=4.0.7030
ARG CORE_TOOLS_SHA256=22931181a4c2891d0040077b7e27f145a1010bac74193ddec269acbea8a3a782

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:11.0 AS build
WORKDIR /src
COPY global.json ./
COPY api/Directory.Build.props api/
COPY api/Blueboard.Contracts/ api/Blueboard.Contracts/
COPY api/Blueboard.Api/ api/Blueboard.Api/
COPY api/Blueboard.Tools/ api/Blueboard.Tools/
COPY db/ db/
RUN rm -f api/Blueboard.Api/local.settings.json \
 && dotnet publish api/Blueboard.Api -c Release -o /out/api \
 && dotnet publish api/Blueboard.Tools -c Release -o /out/tools

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:11.0 AS coretools
ARG CORE_TOOLS_VERSION
ARG CORE_TOOLS_SHA256
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /tmp/ct.zip "https://github.com/Azure/azure-functions-core-tools/releases/download/${CORE_TOOLS_VERSION}/Azure.Functions.Cli.linux-x64.${CORE_TOOLS_VERSION}.zip" \
 && echo "${CORE_TOOLS_SHA256}  /tmp/ct.zip" | sha256sum -c - \
 && mkdir /opt/func && unzip -q /tmp/ct.zip -d /opt/func && chmod +x /opt/func/func /opt/func/gozip 2>/dev/null; rm /tmp/ct.zip

FROM --platform=linux/amd64 ${FUNCTIONS_IMAGE}
ENV FUNCTIONS_WORKER_RUNTIME=dotnet-isolated \
    FUNCTIONS_CORE_TOOLS_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1
COPY --from=coretools /opt/func /opt/func
COPY --from=build /out/api /home/site/wwwroot
# The operator CLI (migrate, seed-dev): docker compose -f docker-compose.demo.yml exec api blueboard migrate
COPY --from=build /out/tools /opt/blueboard-tools
RUN printf '#!/bin/sh\nexec dotnet /opt/blueboard-tools/blueboard.dll "$@"\n' > /usr/local/bin/blueboard && chmod +x /usr/local/bin/blueboard
COPY policy.example.json /home/site/policy.json
WORKDIR /home/site/wwwroot
EXPOSE 80
# Settings come from the environment (docker-compose.demo.yml); Core Tools reads them like app settings.
# CORS: the web origin allowed to call the API (Core Tools takes it as a flag, not an app setting).
ENV CORS_ORIGIN=http://localhost:3417
ENTRYPOINT ["sh", "-c", "exec /opt/func/func start --port 80 --no-build --dotnet-isolated --cors \"$CORS_ORIGIN\""]
