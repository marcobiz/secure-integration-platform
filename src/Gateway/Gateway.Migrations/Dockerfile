FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/Gateway/Gateway.Migrations/Gateway.Migrations.csproj --locked-mode && dotnet publish src/Gateway/Gateway.Migrations/Gateway.Migrations.csproj -c Release --no-restore -o /app /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
ENTRYPOINT ["dotnet", "SecureIntegration.Gateway.Migrations.dll", "apply"]
