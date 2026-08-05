FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/Gateway/Gateway.Api/Gateway.Api.csproj --locked-mode \
    && dotnet restore packs/deployment/azure/src/Providers.Azure/Providers.Azure.csproj --locked-mode \
    && dotnet publish src/Gateway/Gateway.Api/Gateway.Api.csproj -c Release --no-restore -o /app /p:UseAppHost=false \
    && dotnet publish packs/deployment/azure/src/Providers.Azure/Providers.Azure.csproj -c Release --no-restore -o /pack /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .
COPY --from=build /pack ./packs/azure/
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["dotnet", "SecureIntegration.Gateway.Api.dll", "--health-probe"]
ENTRYPOINT ["dotnet", "SecureIntegration.Gateway.Api.dll"]
