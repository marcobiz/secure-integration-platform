# Azure deployment pack

Optional deployment pack for the provider-neutral Core. It owns Azure SDK dependencies, Managed Identity composition, Key Vault reference validation and Azure-specific packaging.

Build and test independently:

```powershell
dotnet restore BrokerGateway.Azure.slnx
dotnet build BrokerGateway.Azure.slnx -c Release --no-restore
dotnet test BrokerGateway.Azure.slnx -c Release --no-build --no-restore
```

The Core solution and default Gateway image do not reference or contain this pack. The Azure image is built explicitly with `packs/deployment/azure/Dockerfile`. M3B remains a separate, deferred deployment qualification gate.
