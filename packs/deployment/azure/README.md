# Azure deployment pack

Optional deployment pack for the provider-neutral Core. It owns Azure SDK dependencies, Managed Identity composition, Key Vault reference validation and Azure-specific packaging.

Build and test independently:

```powershell
dotnet restore BrokerGateway.Azure.slnx
dotnet build BrokerGateway.Azure.slnx -c Release --no-restore
dotnet test BrokerGateway.Azure.slnx -c Release --no-build --no-restore
```

The Core solution and default Gateway image do not reference or contain this pack. The Azure image is built explicitly with `packs/deployment/azure/Dockerfile`. M3B remains a separate, deferred deployment qualification gate.

Readiness is resource-scoped. Configure `Gateway__Provider__Settings__ReadinessSecretReference`
to one Gateway-owned Key Vault reference, such as the activation HMAC reference. `/health/ready`
inspects version metadata for that secret name and, when a version is configured, only accepts
that exact version. It does not enumerate vault-wide secrets or download secret values. With
the Azure Key Vault SDK used by this pack, the probe uses the secret-version listing API; scope
that metadata permission to the configured secret instead of granting broad vault enumeration.
Existing runtime secret and certificate references keep their normal lookup behavior and cache
semantics; deployments without this setting remain lazy for invocation but do not report
provider-ready.
