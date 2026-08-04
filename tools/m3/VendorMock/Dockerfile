FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY ["global.json", "Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props", "NuGet.config", "./"]
COPY ["tools/m3/VendorMock/VendorMock.csproj", "tools/m3/VendorMock/"]
RUN dotnet restore tools/m3/VendorMock/VendorMock.csproj --locked-mode=false
COPY tools/m3/VendorMock/ tools/m3/VendorMock/
RUN dotnet publish tools/m3/VendorMock/VendorMock.csproj -c Release --no-restore -o /app /p:UseAppHost=false
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
RUN addgroup -S m3fixture && adduser -S -G m3fixture -u 1656 m3fixture
WORKDIR /app
COPY --from=build /app .
USER 1656:1656
EXPOSE 8443
ENTRYPOINT ["dotnet", "SecureIntegration.M3.VendorMock.dll"]
