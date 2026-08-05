FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/Gateway/Gateway.Api/Gateway.Api.csproj --locked-mode && dotnet publish src/Gateway/Gateway.Api/Gateway.Api.csproj -c Release --no-restore -o /app /p:UseAppHost=false

FROM node:22.22.1-alpine AS admin-web
WORKDIR /src/src/Admin/Admin.Web
COPY src/Admin/Admin.Web/package.json src/Admin/Admin.Web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY src/Admin/Admin.Web/ ./
COPY docs/api/gateway-openapi.yaml /src/docs/api/gateway-openapi.yaml
COPY docs/connectors/connector-definition.schema.json /src/docs/connectors/connector-definition.schema.json
COPY docs/connectors/examples/sample-secure-service.connector.json /src/docs/connectors/examples/sample-secure-service.connector.json
RUN npm run build

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .
COPY --from=admin-web /src/src/Admin/Admin.Web/dist ./wwwroot/admin
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["dotnet", "SecureIntegration.Gateway.Api.dll", "--health-probe"]
ENTRYPOINT ["dotnet", "SecureIntegration.Gateway.Api.dll"]
