FROM mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS build
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

FROM mcr.microsoft.com/dotnet/aspnet:10.0.11@sha256:207cc51496778557731c81ff670333d8ade4a4fec22768fd1be8e78474a84ecf AS runtime
ARG PRODUCT_VERSION
ARG SOURCE_REVISION
WORKDIR /app
COPY --from=build /app .
COPY --from=admin-web /src/src/Admin/Admin.Web/dist ./wwwroot/admin
COPY LICENSE NOTICE /licenses/
LABEL org.opencontainers.image.version=$PRODUCT_VERSION \
      org.opencontainers.image.revision=$SOURCE_REVISION \
      org.opencontainers.image.source="https://github.com/marcobiz/secure-integration-platform" \
      org.opencontainers.image.vendor="ApoCert S.r.l." \
      org.opencontainers.image.title="Secure Integration Platform Gateway" \
      org.opencontainers.image.licenses="MPL-2.0"
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["dotnet", "SecureIntegration.Gateway.Api.dll", "--health-probe"]
ENTRYPOINT ["dotnet", "SecureIntegration.Gateway.Api.dll"]
