# Small .NET apps for the local demo: the mock Microsoft API and the scripted reference agent.
#   --build-arg PROJECT=dev/mock-msapi  DLL=blueboard-mock-msapi.dll
#   --build-arg PROJECT=agents/Blueboard.EnrichmentAgent  DLL=blueboard-enrichment-agent.dll
FROM mcr.microsoft.com/dotnet/sdk:11.0 AS build
ARG PROJECT
WORKDIR /src
COPY global.json ./
COPY api/Directory.Build.props api/
COPY api/Blueboard.Contracts/ api/Blueboard.Contracts/
COPY agents/ agents/
COPY dev/mock-msapi/ dev/mock-msapi/
RUN dotnet publish "$PROJECT" -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0
ARG DLL
WORKDIR /app
COPY --from=build /out ./
COPY dev/fixtures/ /app/fixtures/
USER $APP_UID
ENV DLL=${DLL}
ENTRYPOINT ["sh", "-c", "exec dotnet /app/$DLL"]
