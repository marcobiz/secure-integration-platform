FROM mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/Gateway/Gateway.Api/Gateway.Api.csproj --locked-mode \
    && dotnet restore packs/deployment/local-pkcs12/src/Providers.LocalPkcs12/Providers.LocalPkcs12.csproj --locked-mode \
    && dotnet restore src/ConnectorPacks/Healthcare/Healthcare.FSE2/Healthcare.FSE2.csproj --locked-mode \
    && dotnet publish src/Gateway/Gateway.Api/Gateway.Api.csproj -c Release --no-restore -o /app /p:UseAppHost=false \
    && dotnet publish packs/deployment/local-pkcs12/src/Providers.LocalPkcs12/Providers.LocalPkcs12.csproj -c Release --no-restore -o /provider-pack /p:UseAppHost=false \
    && dotnet publish src/ConnectorPacks/Healthcare/Healthcare.FSE2/Healthcare.FSE2.csproj -c Release --no-restore -o /connector-pack /p:UseAppHost=false

FROM node:22.22.1-alpine AS admin-web
WORKDIR /src/src/Admin/Admin.Web
COPY src/Admin/Admin.Web/package.json src/Admin/Admin.Web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY src/Admin/Admin.Web/ ./
COPY docs/api/gateway-openapi.yaml /src/docs/api/gateway-openapi.yaml
COPY docs/connectors/connector-definition.schema.json /src/docs/connectors/connector-definition.schema.json
COPY docs/connectors/examples/sample-secure-service.connector.json /src/docs/connectors/examples/sample-secure-service.connector.json
RUN npm run build

FROM mcr.microsoft.com/dotnet/aspnet:10.0.11@sha256:207cc51496778557731c81ff670333d8ade4a4fec22768fd1be8e78474a84ecf AS runtime
WORKDIR /app
COPY --from=build /app .
COPY --from=build /provider-pack ./packs/local-pkcs12/
COPY --from=build /connector-pack ./packs/healthcare-fse2/
COPY --from=admin-web /src/src/Admin/Admin.Web/dist ./wwwroot/admin
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["dotnet", "SecureIntegration.Gateway.Api.dll", "--health-probe"]
ENTRYPOINT ["dotnet", "SecureIntegration.Gateway.Api.dll"]
