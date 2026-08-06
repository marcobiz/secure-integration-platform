FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY ["global.json", "Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props", "NuGet.config", "./"]
COPY ["src/Gateway/Gateway.Domain/Gateway.Domain.csproj", "src/Gateway/Gateway.Domain/"]
COPY ["src/Gateway/Gateway.Domain/packages.lock.json", "src/Gateway/Gateway.Domain/"]
COPY ["src/Providers/Abstractions/Providers.Abstractions.csproj", "src/Providers/Abstractions/"]
COPY ["src/Providers/Abstractions/packages.lock.json", "src/Providers/Abstractions/"]
COPY ["src/Gateway/Gateway.Application/Gateway.Application.csproj", "src/Gateway/Gateway.Application/"]
COPY ["src/Gateway/Gateway.Application/packages.lock.json", "src/Gateway/Gateway.Application/"]
COPY ["src/Gateway/Gateway.Infrastructure/Gateway.Infrastructure.csproj", "src/Gateway/Gateway.Infrastructure/"]
COPY ["src/Gateway/Gateway.Infrastructure/packages.lock.json", "src/Gateway/Gateway.Infrastructure/"]
COPY ["tools/m3/Provisioner/Provisioner.csproj", "tools/m3/Provisioner/"]
COPY ["tools/m3/Provisioner/packages.lock.json", "tools/m3/Provisioner/"]
RUN dotnet restore tools/m3/Provisioner/Provisioner.csproj --locked-mode
COPY src/Gateway/ src/Gateway/
COPY src/Providers/Abstractions/ src/Providers/Abstractions/
COPY docs/api/runtime-wire-codes.json docs/api/runtime-wire-codes.json
COPY docs/connectors/connector-definition.schema.json docs/connectors/connector-definition.schema.json
COPY docs/connectors/examples/sample-secure-service.connector.json docs/connectors/examples/sample-secure-service.connector.json
COPY tools/m3/Provisioner/ tools/m3/Provisioner/
RUN dotnet publish tools/m3/Provisioner/Provisioner.csproj -c Release --no-restore -o /app /p:UseAppHost=false
FROM mcr.microsoft.com/dotnet/runtime:10.0-alpine
RUN addgroup -S m3fixture && adduser -S -G m3fixture -u 1657 m3fixture
WORKDIR /app
COPY --from=build /app .
USER 1657:1657
ENTRYPOINT ["dotnet", "SecureIntegration.M3.Provisioner.dll"]
