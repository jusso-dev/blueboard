# The React app served by its ASP.NET Core host (web/host), for the local demo.
FROM node:26-alpine AS spa
WORKDIR /web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS host
WORKDIR /src
COPY global.json ./
COPY web/host/ web/host/
COPY --from=spa /web/dist web/dist
RUN dotnet publish web/host -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=host /out ./
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "blueboard-web.dll"]
