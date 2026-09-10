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
to the existing Gateway-owned activation HMAC reference, as the dev Bicep does; do not use
a PFX, certificate or signing resource as the probe. `/health/ready` performs a secret GET
for only that reference: the SDK receives the exact configured version or resolves the
current version when it is omitted. Success proves read access to that resource, not
cryptographic suitability, expiry validation or readiness of every configured resource.
Neither secret versions nor vault-wide secrets are enumerated. The probe requires GET
access, not LIST; it adds no application retry and preserves caller cancellation.
The SDK response includes the secret value temporarily in process memory. The probe
does not access, retain, cache, log or use that value; this is not metadata-only retrieval
and does not guarantee erasure of managed strings.
Existing runtime secret and certificate references keep their normal lookup behavior and cache
semantics; deployments without this setting remain lazy for invocation but do not report
provider-ready.
