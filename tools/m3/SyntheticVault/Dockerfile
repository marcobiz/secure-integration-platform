FROM mcr.microsoft.com/dotnet/sdk:10.0.302-alpine3.24@sha256:979da27fc87dc255f4675b7642556cdcba9307459f8891f85f3cc26edcd7e766 AS build
WORKDIR /src
COPY ["global.json", "Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props", "NuGet.config", "./"]
COPY ["tools/m3/SyntheticVault/SyntheticVault.csproj", "tools/m3/SyntheticVault/"]
COPY ["tools/m3/SyntheticVault/packages.lock.json", "tools/m3/SyntheticVault/"]
RUN dotnet restore tools/m3/SyntheticVault/SyntheticVault.csproj --locked-mode
COPY tools/m3/SyntheticVault/ tools/m3/SyntheticVault/
RUN dotnet publish tools/m3/SyntheticVault/SyntheticVault.csproj -c Release --no-restore -o /app /p:UseAppHost=false
FROM mcr.microsoft.com/dotnet/aspnet:10.0.11-alpine3.24@sha256:c4b29bf368004ad9076c1ab9bc91fb373561e3905b4345637e14e8b8c57e3be8
RUN addgroup -S m3fixture && adduser -S -G m3fixture -u 1655 m3fixture
WORKDIR /app
COPY --from=build /app .
USER 1655:1655
EXPOSE 8443
ENTRYPOINT ["dotnet", "SecureIntegration.M3.SyntheticVault.dll"]
