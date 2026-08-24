FROM mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/Gateway/Gateway.Migrations/Gateway.Migrations.csproj --locked-mode && dotnet publish src/Gateway/Gateway.Migrations/Gateway.Migrations.csproj -c Release --no-restore -o /app /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0.11@sha256:acad02eb5c4fbf57d15296f9c08d56cd4036e915bdae5b4dd48a06523d452617 AS runtime
ARG PRODUCT_VERSION
ARG SOURCE_REVISION
WORKDIR /app
COPY --from=build /app .
COPY LICENSE NOTICE /licenses/
LABEL org.opencontainers.image.version=$PRODUCT_VERSION \
      org.opencontainers.image.revision=$SOURCE_REVISION \
      org.opencontainers.image.source="https://github.com/marcobiz/secure-integration-platform" \
      org.opencontainers.image.vendor="ApoCert S.r.l." \
      org.opencontainers.image.title="Secure Integration Platform Migrations" \
      org.opencontainers.image.licenses="MPL-2.0"
USER $APP_UID
ENTRYPOINT ["dotnet", "SecureIntegration.Gateway.Migrations.dll", "apply"]
